# Phone Touchpad - โปรแกรมช่วยฝั่งโน้ตบุ๊กสำหรับโหมด Wi-Fi
# รับการขยับ/การกดจากแอปบนมือถือผ่าน Wi-Fi (UDP เข้ารหัส) แล้วสั่งเมาส์และคีย์บอร์ดของ Windows
# เปิดด้วย Start-Touchpad-WiFi.bat — ไม่ต้องติดตั้งอะไรเพิ่ม ไม่ต้องใช้สิทธิ์ผู้ดูแลระบบ
#
# โน้ตบุ๊กเป็นฝ่ายส่งออกไปหามือถือก่อนเสมอ (ประกาศตัวทุก 1 วินาที) จึงไม่ต้องเปิดพอร์ตขาเข้าใน Windows Firewall
#
# สำหรับทดสอบ:  -TestCode ABCDEFGH  ใช้รหัสจับคู่ตายตัว (ไม่บันทึก)
#               -LogReports <ไฟล์>  จดรายงานที่ได้รับลงไฟล์แทนการสั่งเมาส์/คีย์บอร์ดจริง
#               -NoUi -Seconds N    ไม่เปิดหน้าต่าง ทำงาน N วินาทีแล้วจบ
param(
    [string]$TestCode = '',
    [string]$LogReports = '',
    [switch]$NoUi,
    [int]$Seconds = 0
)

$src = @'
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;

public static class PtwHelper
{
    const int PORT = 34870;
    const int T_BEACON = 1, T_HELLO = 2, T_WELCOME = 3, T_DATA = 4, T_ACK = 5, T_REJECT = 6;
    static readonly byte[] MAGIC = { (byte)'P', (byte)'T', (byte)'W', (byte)'1' };
    const string ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    class Session
    {
        public byte[] sid, enc, mac;
        public long txCtr, rxCtr;
        public IPEndPoint peer;
        public uint expected;
        public long lastRx;
    }

    static readonly object gate = new object();
    static byte[] helperId, K;
    static string code;
    static bool persist = true;
    static Socket sock;
    static Session cur, pending;
    static long lastReject;
    static volatile int leds;
    static volatile bool stop;
    static string logPath;
    static IPAddress manual;
    static long reportsApplied;

    // ------------------------------------------------------------ สถานะสำหรับหน้าต่าง
    public static string Code { get { return code.Substring(0, 4) + "-" + code.Substring(4); } }
    public static bool Connected { get { lock (gate) return cur != null; } }
    public static string PeerText { get { lock (gate) return cur == null ? "" : cur.peer.Address.ToString(); } }
    public static long Reports { get { return Interlocked.Read(ref reportsApplied); } }

    // ------------------------------------------------------------ รหัสจับคู่
    static string ConfigPath()
    {
        string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PhoneTouchpad");
        Directory.CreateDirectory(dir);
        return Path.Combine(dir, "helper.dat");
    }

    static byte[] Rand(int n)
    {
        byte[] b = new byte[n];
        using (RandomNumberGenerator r = RandomNumberGenerator.Create()) r.GetBytes(b);
        return b;
    }

    static string Hex(byte[] b)
    {
        StringBuilder s = new StringBuilder();
        foreach (byte x in b) s.Append(x.ToString("x2"));
        return s.ToString();
    }

    static byte[] Unhex(string s)
    {
        byte[] b = new byte[s.Length / 2];
        for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(s.Substring(i * 2, 2), 16);
        return b;
    }

    public static void NewCode()
    {
        lock (gate)
        {
            byte[] r = Rand(8);
            StringBuilder s = new StringBuilder();
            foreach (byte x in r) s.Append(ALPHABET[x & 31]);
            code = s.ToString();
            helperId = Rand(16);
            if (persist)
            {
                // เก็บแบบเข้ารหัสผูกกับบัญชี Windows ของผู้ใช้ (DPAPI)
                byte[] plain = Encoding.UTF8.GetBytes(Hex(helperId) + "|" + code);
                File.WriteAllBytes(ConfigPath(), ProtectedData.Protect(plain, null, DataProtectionScope.CurrentUser));
            }
            DeriveKey();
            if (cur != null) EndSession();
            pending = null;
        }
    }

    static void LoadOrCreate(string testCode)
    {
        if (!string.IsNullOrEmpty(testCode))
        {
            persist = false;
            code = testCode.ToUpperInvariant().Replace("-", "");
            helperId = new byte[16];
            for (int i = 0; i < 16; i++) helperId[i] = (byte)(0xA0 + i);
            DeriveKey();
            return;
        }
        try
        {
            string[] parts = Encoding.UTF8.GetString(
                ProtectedData.Unprotect(File.ReadAllBytes(ConfigPath()), null, DataProtectionScope.CurrentUser)).Split('|');
            if (parts.Length == 2 && parts[0].Length == 32 && parts[1].Length == 8)
            {
                helperId = Unhex(parts[0]);
                code = parts[1];
                DeriveKey();
                return;
            }
        }
        catch (Exception) { }
        NewCode();
    }

    static void DeriveKey()
    {
        using (Rfc2898DeriveBytes d = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(code), helperId, 100000, HashAlgorithmName.SHA256))
            K = d.GetBytes(32);
    }

    // ------------------------------------------------------------ เข้ารหัส
    static byte[] Hmac(byte[] key, params byte[][] parts)
    {
        using (HMACSHA256 h = new HMACSHA256(key))
        {
            using (MemoryStream m = new MemoryStream())
            {
                foreach (byte[] p in parts) m.Write(p, 0, p.Length);
                return h.ComputeHash(m.ToArray());
            }
        }
    }

    static byte[] A(string s) { return Encoding.ASCII.GetBytes(s); }

    static byte[] Sub(byte[] b, int off, int n)
    {
        byte[] r = new byte[n];
        Buffer.BlockCopy(b, off, r, 0, n);
        return r;
    }

    static bool Same(byte[] a, int aoff, byte[] b, int boff, int n)
    {
        int diff = 0;
        for (int i = 0; i < n; i++) diff |= a[aoff + i] ^ b[boff + i];
        return diff == 0;
    }

    static void PutLong(byte[] b, int off, long v)
    {
        for (int i = 7; i >= 0; i--) { b[off + i] = (byte)v; v >>= 8; }
    }

    static long GetLong(byte[] b, int off)
    {
        long v = 0;
        for (int i = 0; i < 8; i++) v = (v << 8) | b[off + i];
        return v;
    }

    // AES-256-CTR: IV = ทิศ(1) sid(4) ตัวนับ(8) เลขบล็อก(3)
    static byte[] Crypt(byte[] key, int dir, byte[] sid, long ctr, byte[] data, int off, int n)
    {
        byte[] iv = new byte[16], ks = new byte[16], o = new byte[n];
        iv[0] = (byte)dir;
        Buffer.BlockCopy(sid, 0, iv, 1, 4);
        PutLong(iv, 5, ctr);
        using (Aes aes = Aes.Create())
        {
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.Key = key;
            using (ICryptoTransform t = aes.CreateEncryptor())
            {
                for (int i = 0, blk = 0; i < n; i += 16, blk++)
                {
                    iv[13] = (byte)(blk >> 16); iv[14] = (byte)(blk >> 8); iv[15] = (byte)blk;
                    t.TransformBlock(iv, 0, 16, ks, 0);
                    for (int j = 0; j < 16 && i + j < n; j++) o[i + j] = (byte)(data[off + i + j] ^ ks[j]);
                }
            }
        }
        return o;
    }

    static byte[] Seal(Session s, int type, byte[] plain)
    {
        long ctr = ++s.txCtr;
        byte[] head = new byte[17];
        Buffer.BlockCopy(MAGIC, 0, head, 0, 4);
        head[4] = (byte)type;
        Buffer.BlockCopy(s.sid, 0, head, 5, 4);
        PutLong(head, 9, ctr);
        byte[] ct = Crypt(s.enc, 2, s.sid, ctr, plain, 0, plain.Length);
        byte[] mac = Hmac(s.mac, head, ct);
        byte[] p = new byte[17 + ct.Length + 16];
        Buffer.BlockCopy(head, 0, p, 0, 17);
        Buffer.BlockCopy(ct, 0, p, 17, ct.Length);
        Buffer.BlockCopy(mac, 0, p, 17 + ct.Length, 16);
        return p;
    }

    static byte[] Open(Session s, byte[] p, int len)
    {
        if (len < 33 || !Same(p, 5, s.sid, 0, 4)) return null;
        long ctr = GetLong(p, 9);
        if (ctr <= s.rxCtr) return null;
        byte[] head = Sub(p, 0, 17), ct = Sub(p, 17, len - 33);
        byte[] mac = Hmac(s.mac, head, ct);
        if (!Same(mac, 0, p, len - 16, 16)) return null;
        s.rxCtr = ctr;
        return Crypt(s.enc, 1, s.sid, ctr, ct, 0, ct.Length);
    }

    // ------------------------------------------------------------ เครือข่าย
    static void Send(byte[] p, IPEndPoint to)
    {
        try { sock.SendTo(p, to); }
        catch (Exception) { }
    }

    public static void SetManual(string ip)
    {
        IPAddress a;
        lock (gate) manual = IPAddress.TryParse((ip ?? "").Trim(), out a) && a.AddressFamily == AddressFamily.InterNetwork ? a : null;
    }

    public static string LocalAddresses()
    {
        List<string> l = new List<string>();
        try
        {
            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                foreach (UnicastIPAddressInformation u in ni.GetIPProperties().UnicastAddresses)
                    if (u.Address.AddressFamily == AddressFamily.InterNetwork && !l.Contains(u.Address.ToString())) l.Add(u.Address.ToString());
            }
        }
        catch (Exception) { }
        return string.Join(", ", l.ToArray());
    }

    // ประกาศตัว: broadcast ทุกวงเครือข่าย + เกตเวย์ (ถ้าโน้ตบุ๊กต่อ Hotspot ของมือถือ เกตเวย์ก็คือมือถือ) + IP ที่ผู้ใช้ใส่เอง
    static void Beacon()
    {
        byte[] name = Encoding.UTF8.GetBytes(Environment.MachineName);
        if (name.Length > 60) name = Sub(name, 0, 60);
        byte[] p = new byte[22 + name.Length];
        Buffer.BlockCopy(MAGIC, 0, p, 0, 4);
        p[4] = T_BEACON;
        Buffer.BlockCopy(helperId, 0, p, 5, 16);
        p[21] = (byte)name.Length;
        Buffer.BlockCopy(name, 0, p, 22, name.Length);
        HashSet<string> seen = new HashSet<string>();
        List<IPAddress> to = new List<IPAddress>();
        to.Add(IPAddress.Broadcast);
        if (manual != null) to.Add(manual);
        try
        {
            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                IPInterfaceProperties ip = ni.GetIPProperties();
                foreach (UnicastIPAddressInformation u in ip.UnicastAddresses)
                {
                    if (u.Address.AddressFamily != AddressFamily.InterNetwork || u.IPv4Mask == null) continue;
                    byte[] a = u.Address.GetAddressBytes(), m = u.IPv4Mask.GetAddressBytes();
                    if (m[0] == 0) continue;
                    for (int i = 0; i < 4; i++) a[i] = (byte)(a[i] | ~m[i]);
                    to.Add(new IPAddress(a));
                }
                foreach (GatewayIPAddressInformation g in ip.GatewayAddresses)
                    if (g.Address.AddressFamily == AddressFamily.InterNetwork) to.Add(g.Address);
            }
        }
        catch (Exception) { }
        foreach (IPAddress a in to)
            if (seen.Add(a.ToString())) Send(p, new IPEndPoint(a, PORT));
    }

    static void RxLoop()
    {
        byte[] buf = new byte[2048];
        while (!stop)
        {
            int n;
            EndPoint ep = new IPEndPoint(IPAddress.Any, 0);
            try { n = sock.ReceiveFrom(buf, ref ep); }
            catch (Exception) { if (stop) return; Thread.Sleep(20); continue; }
            if (n < 5 || !Same(buf, 0, MAGIC, 0, 4)) continue;
            try { lock (gate) Handle(buf, n, (IPEndPoint)ep); }
            catch (Exception) { }
        }
    }

    static void Handle(byte[] p, int n, IPEndPoint from)
    {
        long now = Environment.TickCount;
        if (p[4] == T_HELLO)
        {
            if (n != 53 || !Same(p, 5, helperId, 0, 16)) return;
            byte[] pn = Sub(p, 21, 16);
            if (!Same(Hmac(K, A("hello"), helperId, pn), 0, p, 37, 16))
            {
                if (now - lastReject < 1000 && now >= lastReject) return;   // กันเดารหัสรัวๆ
                lastReject = now;
                byte[] r = new byte[37];
                Buffer.BlockCopy(MAGIC, 0, r, 0, 4);
                r[4] = T_REJECT;
                Buffer.BlockCopy(helperId, 0, r, 5, 16);
                Buffer.BlockCopy(pn, 0, r, 21, 16);
                Send(r, from);
                return;
            }
            byte[] pcn = Rand(16);
            byte[] s = Hmac(K, A("session"), pn, pcn);
            Session ses = new Session();
            ses.sid = Sub(pcn, 0, 4);
            ses.enc = Hmac(s, A("enc"));
            ses.mac = Hmac(s, A("mac"));
            ses.peer = from;
            ses.lastRx = now;
            pending = ses;   // ยังไม่แทนที่รอบปัจจุบันจนกว่าจะได้ข้อมูลที่ถูกต้องของรอบใหม่ (กันการส่ง HELLO เก่าซ้ำมาก่อกวน)
            byte[] w = new byte[53];
            Buffer.BlockCopy(MAGIC, 0, w, 0, 4);
            w[4] = T_WELCOME;
            Buffer.BlockCopy(pn, 0, w, 5, 16);
            Buffer.BlockCopy(pcn, 0, w, 21, 16);
            Buffer.BlockCopy(Hmac(K, A("welcome"), pn, pcn), 0, w, 37, 16);
            Send(w, from);
            return;
        }
        if (p[4] != T_DATA) return;
        Session t = null;
        byte[] plain = null;
        if (cur != null) { plain = Open(cur, p, n); if (plain != null) t = cur; }
        if (t == null && pending != null)
        {
            plain = Open(pending, p, n);
            if (plain != null)
            {
                if (cur != null) ReleaseAll();
                cur = t = pending;
                pending = null;
            }
        }
        if (t == null || plain.Length < 6) return;
        t.peer = from;
        t.lastRx = now;
        int flags = plain[0];
        uint first = ((uint)plain[1] << 24) | ((uint)plain[2] << 16) | ((uint)plain[3] << 8) | plain[4];
        int count = plain[5], pos = 6;
        if (count > 0 && first > t.expected)
        {
            ReleaseAll();           // มีรายงานหายไประหว่างทาง — ปล่อยปุ่มทั้งหมดก่อน กันปุ่มค้าง
            t.expected = first;
        }
        for (int i = 0; i < count && pos + 2 <= plain.Length; i++)
        {
            int id = plain[pos], len = plain[pos + 1];
            if (pos + 2 + len > plain.Length) break;
            if (first + (uint)i == t.expected)
            {
                Apply(id, plain, pos + 2, len, (flags & 2) != 0);
                t.expected++;
            }
            pos += 2 + len;
        }
        byte[] ack = new byte[5];
        ack[0] = (byte)(t.expected >> 24); ack[1] = (byte)(t.expected >> 16); ack[2] = (byte)(t.expected >> 8); ack[3] = (byte)t.expected;
        ack[4] = (byte)leds;
        Send(Seal(t, T_ACK, ack), from);
        if ((flags & 1) != 0) EndSession();
    }

    static void EndSession()
    {
        ReleaseAll();
        cur = null;
    }

    static void TimerLoop()
    {
        int tick = 0;
        while (!stop)
        {
            Thread.Sleep(100);
            tick++;
            lock (gate)
            {
                long now = Environment.TickCount;
                if (cur != null && (now - cur.lastRx > 3000 || now < cur.lastRx)) EndSession();
                if (cur == null && tick % 10 == 0) Beacon();
            }
        }
    }

    // ------------------------------------------------------------ สั่งเมาส์/คีย์บอร์ดของ Windows
    [StructLayout(LayoutKind.Sequential)]
    struct MOUSEINPUT { public int dx, dy, mouseData, dwFlags, time; public IntPtr dwExtraInfo; }
    [StructLayout(LayoutKind.Sequential)]
    struct KEYBDINPUT { public ushort wVk, wScan; public int dwFlags, time; public IntPtr dwExtraInfo; }
    [StructLayout(LayoutKind.Explicit)]
    struct InputUnion { [FieldOffset(0)] public MOUSEINPUT mi; [FieldOffset(0)] public KEYBDINPUT ki; }
    [StructLayout(LayoutKind.Sequential)]
    struct INPUT { public int type; public InputUnion u; }

    [DllImport("user32.dll", SetLastError = true)]
    static extern uint SendInput(uint n, INPUT[] inputs, int size);
    [DllImport("user32.dll")]
    static extern short GetKeyState(int vk);

    static int buttons, mods;
    static readonly bool[] down = new bool[256];
    static readonly ushort[] SCAN = BuildScan();

    // รหัสปุ่ม HID -> scan code ของ Windows (0xE0xx = ปุ่มกลุ่มขยาย) — ส่งเป็น scan code เหมือนคีย์บอร์ดจริง
    // ตัวอักษรที่ออกจึงขึ้นกับภาษาของ Windows ตอนนั้น เหมือนตอนใช้ผ่าน Bluetooth ทุกประการ
    static ushort[] BuildScan()
    {
        ushort[] t = new ushort[256];
        byte[] letters = { 0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32, 0x31, 0x18, 0x19, 0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C };
        for (int i = 0; i < 26; i++) t[0x04 + i] = letters[i];
        for (int i = 0; i < 10; i++) t[0x1E + i] = (ushort)(0x02 + i);
        ushort[] a = { 0x1C, 0x01, 0x0E, 0x0F, 0x39, 0x0C, 0x0D, 0x1A, 0x1B, 0x2B, 0x2B, 0x27, 0x28, 0x29, 0x33, 0x34, 0x35, 0x3A };
        for (int i = 0; i < a.Length; i++) t[0x28 + i] = a[i];
        for (int i = 0; i < 10; i++) t[0x3A + i] = (ushort)(0x3B + i);   // F1-F10
        t[0x44] = 0x57; t[0x45] = 0x58;                                    // F11 F12
        t[0x46] = 0xE037; t[0x47] = 0x46;                                  // PrtSc ScrollLock
        ushort[] nav = { 0xE052, 0xE047, 0xE049, 0xE053, 0xE04F, 0xE051, 0xE04D, 0xE04B, 0xE050, 0xE048 };
        for (int i = 0; i < nav.Length; i++) t[0x49 + i] = nav[i];         // Ins Home PgUp Del End PgDn Right Left Down Up
        t[0x53] = 0xE045; t[0x54] = 0xE035; t[0x55] = 0x37; t[0x56] = 0x4A; t[0x57] = 0x4E; t[0x58] = 0xE01C;
        ushort[] kp = { 0x4F, 0x50, 0x51, 0x4B, 0x4C, 0x4D, 0x47, 0x48, 0x49, 0x52, 0x53 };
        for (int i = 0; i < kp.Length; i++) t[0x59 + i] = kp[i];           // แป้นตัวเลข 1-9 0 .
        t[0x64] = 0x56; t[0x65] = 0xE05D;
        return t;
    }

    static readonly ushort[] MODSCAN = { 0x1D, 0x2A, 0x38, 0xE05B, 0xE01D, 0x36, 0xE038, 0xE05C };

    static INPUT Key(ushort sc, bool up)
    {
        INPUT i = new INPUT();
        i.type = 1;
        i.u.ki.wScan = (ushort)(sc & 0xFF);
        i.u.ki.dwFlags = 0x0008 | ((sc & 0xE000) != 0 ? 0x0001 : 0) | (up ? 0x0002 : 0);
        return i;
    }

    static INPUT Mouse(int flags, int dx, int dy, int data)
    {
        INPUT i = new INPUT();
        i.type = 0;
        i.u.mi.dwFlags = flags;
        i.u.mi.dx = dx;
        i.u.mi.dy = dy;
        i.u.mi.mouseData = data;
        return i;
    }

    static void Inject(List<INPUT> l)
    {
        if (l.Count == 0 || logPath != null) return;
        SendInput((uint)l.Count, l.ToArray(), Marshal.SizeOf(typeof(INPUT)));
    }

    static void Log(string s)
    {
        if (logPath == null) return;
        try { File.AppendAllText(logPath, s + "\r\n"); }
        catch (Exception) { }
    }

    static void Apply(int id, byte[] d, int off, int len, bool hiRes)
    {
        Interlocked.Increment(ref reportsApplied);
        List<INPUT> l = new List<INPUT>();
        if (id == 2 && len >= 5)
        {
            int b = d[off] & 7, dx = (sbyte)d[off + 1], dy = (sbyte)d[off + 2], w = (sbyte)d[off + 3], pan = (sbyte)d[off + 4];
            Log("M " + b + " " + dx + " " + dy + " " + w + " " + pan);
            SetButtons(b, l);
            if (dx != 0 || dy != 0) l.Add(Mouse(0x0001, dx, dy, 0));
            if (w != 0) l.Add(Mouse(0x0800, 0, 0, hiRes ? w : w * 120));
            if (pan != 0) l.Add(Mouse(0x1000, 0, 0, hiRes ? pan : pan * 120));
        }
        else if (id == 1 && len >= 8)
        {
            Log("K " + BitConverter.ToString(d, off, 8));
            bool[] want = new bool[256];
            for (int i = 2; i < 8; i++) want[d[off + i]] = true;
            want[0] = false;
            int m = d[off];
            for (int k = 1; k < 256; k++) if (down[k] && !want[k]) { down[k] = false; if (SCAN[k] != 0) l.Add(Key(SCAN[k], true)); }
            for (int i = 0; i < 8; i++) if ((mods & (1 << i)) != 0 && (m & (1 << i)) == 0) l.Add(Key(MODSCAN[i], true));
            for (int i = 0; i < 8; i++) if ((mods & (1 << i)) == 0 && (m & (1 << i)) != 0) l.Add(Key(MODSCAN[i], false));
            for (int k = 1; k < 256; k++) if (!down[k] && want[k]) { down[k] = true; if (SCAN[k] != 0) l.Add(Key(SCAN[k], false)); }
            mods = m;
        }
        Inject(l);
    }

    static void SetButtons(int b, List<INPUT> l)
    {
        int[] dn = { 0x0002, 0x0008, 0x0020 }, up = { 0x0004, 0x0010, 0x0040 };
        for (int i = 0; i < 3; i++)
        {
            bool was = (buttons & (1 << i)) != 0, now = (b & (1 << i)) != 0;
            if (was != now) l.Add(Mouse(now ? dn[i] : up[i], 0, 0, 0));
        }
        buttons = b;
    }

    static void ReleaseAll()
    {
        List<INPUT> l = new List<INPUT>();
        for (int k = 1; k < 256; k++) if (down[k]) { down[k] = false; if (SCAN[k] != 0) l.Add(Key(SCAN[k], true)); }
        for (int i = 0; i < 8; i++) if ((mods & (1 << i)) != 0) l.Add(Key(MODSCAN[i], true));
        mods = 0;
        SetButtons(0, l);
        if (l.Count > 0) Log("RELEASE-ALL");
        Inject(l);
    }

    public static void PollLeds()
    {
        leds = ((GetKeyState(0x90) & 1) != 0 ? 1 : 0) | ((GetKeyState(0x14) & 1) != 0 ? 2 : 0) | ((GetKeyState(0x91) & 1) != 0 ? 4 : 0);
    }

    // ------------------------------------------------------------ เริ่ม/หยุด
    public static void Start(string testCode, string log)
    {
        logPath = string.IsNullOrEmpty(log) ? null : log;
        LoadOrCreate(testCode);
        sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        sock.EnableBroadcast = true;
        sock.Bind(new IPEndPoint(IPAddress.Any, 0));
        // ไม่ให้ ICMP "ปลายทางไม่รับ" (เช่นเกตเวย์ที่ไม่ใช่มือถือ) ทำให้การรับล้ม
        try { sock.IOControl(unchecked((int)0x9800000C), new byte[] { 0, 0, 0, 0 }, null); }
        catch (Exception) { }
        Thread rx = new Thread(RxLoop); rx.IsBackground = true; rx.Start();
        Thread tm = new Thread(TimerLoop); tm.IsBackground = true; tm.Start();
    }

    public static void Stop()
    {
        lock (gate) { if (cur != null) EndSession(); }
        stop = true;
        try { sock.Close(); }
        catch (Exception) { }
    }

    // ------------------------------------------------------------ หน้าต่าง (ธีมสว่าง)
    public static void RunUi()
    {
        Application.EnableVisualStyles();
        Form f = new Form();
        f.Text = "Phone Touchpad - Wi-Fi";
        f.BackColor = Color.White;
        f.ForeColor = Color.FromArgb(32, 33, 36);
        f.Font = new Font("Leelawadee UI", 10f);
        f.FormBorderStyle = FormBorderStyle.FixedSingle;
        f.MaximizeBox = false;
        f.StartPosition = FormStartPosition.CenterScreen;
        f.ClientSize = new Size(460, 430);

        Label title = new Label();
        title.Text = "Phone Touchpad  ·  โหมด Wi-Fi";
        title.Font = new Font("Leelawadee UI", 14f, FontStyle.Bold);
        title.ForeColor = Color.FromArgb(57, 73, 171);
        title.SetBounds(20, 16, 420, 30);

        Label status = new Label();
        status.Font = new Font("Leelawadee UI", 11f, FontStyle.Bold);
        status.SetBounds(20, 52, 420, 26);

        Label l1 = new Label();
        l1.Text = "รหัสจับคู่ (ใส่ในแอปบนมือถือครั้งแรกครั้งเดียว)";
        l1.SetBounds(20, 92, 420, 22);

        Label codeLabel = new Label();
        codeLabel.Text = Code;
        codeLabel.Font = new Font("Consolas", 30f, FontStyle.Bold);
        codeLabel.TextAlign = ContentAlignment.MiddleCenter;
        codeLabel.BackColor = Color.FromArgb(240, 242, 250);
        codeLabel.SetBounds(20, 118, 420, 64);

        Label how = new Label();
        how.Text = "วิธีใช้: มือถือกับโน้ตบุ๊กต้องอยู่ Wi-Fi เดียวกัน (หรือโน้ตบุ๊กต่อ Hotspot ของมือถือ) "
            + "แล้วในแอป แตะ เมนู → เชื่อมผ่าน Wi-Fi\r\nเปิดหน้าต่างนี้ทิ้งไว้ขณะใช้งาน (ย่อเก็บได้) ปิดหน้าต่าง = หยุดทำงาน";
        how.ForeColor = Color.FromArgb(95, 99, 104);
        how.SetBounds(20, 192, 420, 70);

        Label info = new Label();
        info.ForeColor = Color.FromArgb(95, 99, 104);
        info.SetBounds(20, 266, 420, 40);

        Label l2 = new Label();
        l2.Text = "IP ของมือถือ (ใส่เฉพาะเมื่อแอปหาโน้ตบุ๊กไม่เจอ)";
        l2.SetBounds(20, 312, 420, 22);
        TextBox ipBox = new TextBox();
        ipBox.SetBounds(20, 336, 200, 26);
        ipBox.TextChanged += delegate { SetManual(ipBox.Text); };

        Button renew = new Button();
        renew.Text = "สร้างรหัสใหม่";
        renew.FlatStyle = FlatStyle.System;
        renew.SetBounds(20, 380, 150, 32);
        renew.Click += delegate
        {
            if (MessageBox.Show(f, "สร้างรหัสจับคู่ใหม่? มือถือที่เคยจับคู่ไว้ต้องใส่รหัสใหม่อีกครั้ง", "Phone Touchpad",
                    MessageBoxButtons.OKCancel, MessageBoxIcon.Question) == DialogResult.OK)
            {
                NewCode();
                codeLabel.Text = Code;
            }
        };

        f.Controls.AddRange(new Control[] { title, status, l1, codeLabel, how, info, l2, ipBox, renew });

        System.Windows.Forms.Timer t = new System.Windows.Forms.Timer();
        t.Interval = 200;
        int n = 0;
        t.Tick += delegate
        {
            PollLeds();
            if (Connected)
            {
                status.Text = "● เชื่อมต่อกับมือถือแล้ว (" + PeerText + ")";
                status.ForeColor = Color.FromArgb(46, 125, 50);
            }
            else
            {
                status.Text = "○ กำลังรอมือถือ…";
                status.ForeColor = Color.FromArgb(176, 120, 0);
            }
            if (n++ % 10 == 0) info.Text = "คอมพิวเตอร์: " + Environment.MachineName + "\r\nIP ของเครื่องนี้: " + LocalAddresses();
        };
        t.Start();
        f.FormClosed += delegate { t.Stop(); Stop(); };
        Application.Run(f);
    }
}
'@

Add-Type -TypeDefinition $src -ReferencedAssemblies System.Windows.Forms, System.Drawing, System.Security

[PtwHelper]::Start($TestCode, $LogReports)
if ($NoUi) {
    $end = (Get-Date).AddSeconds($(if ($Seconds -gt 0) { $Seconds } else { 3600 }))
    $was = $false
    while ((Get-Date) -lt $end) {
        Start-Sleep -Milliseconds 200
        $c = [PtwHelper]::Connected
        if ($c -ne $was) { Write-Output ("connected=" + $c + " reports=" + [PtwHelper]::Reports); $was = $c }
    }
    Write-Output ("done reports=" + [PtwHelper]::Reports)
    [PtwHelper]::Stop()
} else {
    [PtwHelper]::RunUi()
}
