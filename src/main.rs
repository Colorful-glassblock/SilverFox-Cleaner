// silverfox-cleaner v4 — 银狐检测清除工具
// v4: 多线程扫描 + TrustedInstaller 提权删除 + 美化 GUI + drivers.dat 检测
#![cfg(windows)]
#![windows_subsystem = "windows"]
#![allow(non_snake_case, dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

#[link(name = "kernel32")]
extern "system" {
    fn OpenMutexW(a: u32, i: i32, n: *const u16) -> isize;
    fn CloseHandle(h: isize) -> i32;
    fn OpenProcess(a: u32, i: i32, p: u32) -> isize;
    fn ReadProcessMemory(h: isize, b: *const u8, buf: *mut u8, s: usize, r: *mut usize) -> i32;
    fn VirtualQueryEx(h: isize, a: *const u8, buf: *mut u8, len: u32) -> usize;
    fn GetCurrentProcess() -> isize;
    fn GetModuleHandleW(n: *const u16) -> isize;
    fn MoveFileExW(a: *const u16, b: *const u16, f: u32) -> i32;
    fn GetFileAttributesW(a: *const u16) -> u32;
}
#[link(name = "ntdll")]
extern "system" {
    fn RtlAdjustPrivilege(p: u32, enable: i32, thread: i32, old: *mut u8) -> i32;
    fn NtRaiseHardError(status: u32, count: u32, mask: u32, params: *const u64, option: u32, resp: *mut u32) -> i32;
}
#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(ph: isize, a: u32, t: *mut isize) -> i32;
    fn LookupPrivilegeValueW(s: *const u16, n: *const u16, l: *mut u64) -> i32;
    fn AdjustTokenPrivileges(t: isize, d: i32, n: *const u8, l: u32, p: *mut u8, r: *mut u32) -> i32;
}
#[link(name = "user32")]
extern "system" {
    fn RegisterClassExW(w: *const u8) -> u16;
    fn CreateWindowExW(e: u32, c: *const u16, n: *const u16, s: u32, x: i32, y: i32, w: i32, h: i32, p: isize, m: isize, i: isize, pa: *const u8) -> isize;
    fn DefWindowProcW(h: isize, m: u32, w: usize, l: isize) -> isize;
    fn GetMessageW(m: *mut u8, h: isize, a: u32, b: u32) -> i32;
    fn TranslateMessage(m: *const u8) -> i32;
    fn DispatchMessageW(m: *const u8) -> isize;
    fn PostQuitMessage(c: i32);
    fn SendMessageW(h: isize, m: u32, w: usize, l: isize) -> isize;
    fn MessageBoxW(p: isize, t: *const u16, c: *const u16, t2: u32) -> i32;
}
#[link(name = "gdi32")]
extern "system" {
    fn GetStockObject(i: i32) -> isize;
    fn CreateSolidBrush(c: u32) -> isize;
}

const PROCESS_VM_READ: u32 = 0x10;
const PROCESS_QUERY_INFO: u32 = 0x400;
const MEM_COMMIT: u32 = 0x1000;
const TOKEN_ADJUST: u32 = 0x20;
const TOKEN_QUERY: u32 = 0x8;
const SE_ENABLED: u32 = 2;

const WM_DESTROY: u32 = 2;
const WM_COMMAND: u32 = 0x111;
const WM_SETFONT: u32 = 0x30;
const EM_SETSEL: u32 = 0xB1;
const EM_REPLACESEL: u32 = 0xC2;
const ES_MULTILINE: u32 = 4;
const ES_READONLY: u32 = 0x800;
const ES_AUTOVSCROLL: u32 = 0x80;
const ES_WANTRETURN: u32 = 0x40;
const WS_VSCROLL: u32 = 0x200000;
const WS_VISIBLE: u32 = 0x10000000;
const WS_CHILD: u32 = 0x40000000;
const WS_OVERLAPPEDWINDOW: u32 = 0xCF0000;
const MB_OKCANCEL: u32 = 1;
const MB_ICONWARNING: u32 = 0x30;
const IDOK: i32 = 1;
const DEFAULT_GUI_FONT: i32 = 17;

fn utf16(s: &str) -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() }
fn utf16le(s: &str) -> Vec<u8> { s.encode_utf16().flat_map(|w| w.to_le_bytes()).collect() }
fn find(h: &[u8], n: &[u8]) -> bool { !n.is_empty() && h.windows(n.len()).any(|w| w == n) }

const MAGIC_STEG: &[u8] = b"STEGR1Xp";
const MAGIC_JELG: &[u8] = b"JELG";
const QMAGIC: &[u8; 8] = b"SFQENC1\0";
const QUAR: &str = "sf_quarantine";
const QUAR_ROOT: &str = r"C:\ProgramData\sf_quarantine";
const RUN_KEY: &str = r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run";
const MARK_KEY: &str = r"HKLM\Software\SFCleaner";
const C2_IOCS: &[&str] = &["4d.skendh.com", "de.sjd82.org", "skendh.com", "sjd82.org", "dmo/client"];

#[derive(Clone)]
struct Finding { kind: String, detail: String, high: bool, action: String }

// ---- TrustedInstaller 提权 ----
fn enable_privs() {
    unsafe {
        let mut tok: isize = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST | TOKEN_QUERY, &mut tok) != 0 {
            for pn in ["SeTakeOwnershipPrivilege", "SeRestorePrivilege", "SeBackupPrivilege", "SeDebugPrivilege", "SeSecurityPrivilege"] {
                let pn16 = utf16(pn);
                let mut luid = [0u8; 8];
                if LookupPrivilegeValueW(std::ptr::null(), pn16.as_ptr(), luid.as_mut_ptr() as *mut u64) != 0 {
                    let mut tp = [0u8; 16];
                    tp[0..4].copy_from_slice(&1u32.to_le_bytes());
                    tp[4..12].copy_from_slice(&luid);
                    tp[12..16].copy_from_slice(&SE_ENABLED.to_le_bytes());
                    let mut prev = [0u8; 64]; let mut rl: u32 = 0;
                    AdjustTokenPrivileges(tok, 0, tp.as_ptr(), 64, prev.as_mut_ptr(), &mut rl);
                }
            }
            CloseHandle(tok);
        }
    }
}

fn take_own(path: &str) {
    let _ = Command::new("takeown").args(["/f", path, "/a"]).output();
    let _ = Command::new("icacls").args([path, "/grant", "Administrators:F"]).output();
}

// ---- 扫描 ----
fn scan_all() -> Vec<Finding> {
    enable_privs();
    let results = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();
    let r1 = Arc::clone(&results);
    handles.push(thread::spawn(move || {
        let mut f = scan_tasks(); f.extend(scan_services());
        r1.lock().unwrap().extend(f);
    }));
    let r2 = Arc::clone(&results);
    handles.push(thread::spawn(move || {
        let mut f = scan_procs(); f.extend(scan_ctfmon());
        r2.lock().unwrap().extend(f);
    }));
    let r3 = Arc::clone(&results);
    handles.push(thread::spawn(move || {
        let mut f = scan_files();
        f.extend(scan_hosts());
        f.extend(scan_wu());
        r3.lock().unwrap().extend(f);
    }));
    for h in handles { h.join().unwrap(); }
    let mut out = results.lock().unwrap().clone();
    out.sort_by(|a, b| b.high.cmp(&a.high));
    out
}

fn scan_tasks() -> Vec<Finding> {
    let root = PathBuf::from(r"C:\Windows\System32\Tasks");
    let mut out = Vec::new();
    let u_e: Vec<u8> = "EkxZJr".encode_utf16().flat_map(|w| w.to_le_bytes()).collect();
    let u_s: Vec<u8> = "SrL.exe".encode_utf16().flat_map(|w| w.to_le_bytes()).collect();
    let u_cd: Vec<u8> = "cd /d".encode_utf16().flat_map(|w| w.to_le_bytes()).collect();
    let u_st: Vec<u8> = "&& start".encode_utf16().flat_map(|w| w.to_le_bytes()).collect();
    walk(&root, 0, &mut |p| {
        if let Ok(dt) = fs::read(p) {
            let hi = find(&dt, b"EkxZJr") || find(&dt, b"SrL.exe") || find(&dt, &u_e) || find(&dt, &u_s);
            let md = find(&dt, &u_cd) && find(&dt, &u_st);
            if hi || md {
                let nm = p.strip_prefix(&root).unwrap_or(p).to_string_lossy().to_string();
                out.push(Finding { kind: "TASK".into(), detail: if hi { nm.clone() } else { format!("{} [链式]", nm) }, high: hi, action: format!("schtasks /delete /tn \"{}\" /f", nm) });
            }
        }
    });
    out
}

fn scan_services() -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    for (pat, hi) in [("EkxZJr", true), ("SrL.exe", true), ("cd /d", false),
        ("vafdska", true), ("MiniFilterDrv", true), ("vmservice", true),
        ("MicrosoftSoftware2ShadowCop4yProvider", true)] {
        if let Ok(o) = Command::new("reg").args(["query", r"HKLM\SYSTEM\CurrentControlSet\Services", "/s", "/f", pat, "/d"]).output() {
            for l in String::from_utf8_lossy(&o.stdout).lines() {
                let l = l.trim();
                if l.starts_with("HKEY_LOCAL_MACHINE") {
                    if let Some(nm) = l.rsplit('\\').next() {
                        if !nm.is_empty() && !out.iter().any(|f| f.detail == nm) {
                            out.push(Finding { kind: "SERVICE".into(), detail: if hi { nm.to_string() } else { format!("{} [结构]", nm) }, high: hi, action: format!("sc delete \"{}\"", nm) });
                        }
                    }
                }
            }
        }
    }
    out
}

fn pids() -> Vec<(String, u32)> {
    let mut out = Vec::new();
    if let Ok(o) = Command::new("tasklist").args(["/fo", "csv", "/nh"]).output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            let c: Vec<&str> = l.split("\",\"").collect();
            if c.len() >= 2 {
                let n = c[0].trim_start_matches('"').to_string();
                if let Ok(p) = c[1].trim_end_matches('"').parse() { out.push((n, p)); }
            }
        }
    }
    out
}

fn scan_procs() -> Vec<Finding> {
    let mut out = Vec::new();
    for (n, p) in pids() {
        if n.eq_ignore_ascii_case("SrL.exe") {
            out.push(Finding { kind: "PROCESS".into(), high: true, detail: format!("SrL.exe (pid {})", p), action: format!("taskkill /f /pid {}", p) });
        }
        let rev: String = p.to_string().chars().rev().collect();
        let mn = format!("Global\\P_{}", rev);
        let w = utf16(&mn);
        let h = unsafe { OpenMutexW(0x1F0001, 0, w.as_ptr()) };
        if h != 0 { unsafe { CloseHandle(h); }
            out.push(Finding { kind: "MUTEX".into(), high: true, detail: format!("{} (pid {} {})", mn, p, n), action: "随进程终止".into() });
        }
    }
    out
}

fn scan_ctfmon() -> Vec<Finding> {
    let mut out = Vec::new();
    for (n, p) in pids() {
        if !n.eq_ignore_ascii_case("ctfmon.exe") { continue; }
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_INFO | PROCESS_VM_READ, 0, p);
            if h == 0 { continue; }
            let mut hits: Vec<&str> = Vec::new();
            let mut addr: usize = 0x10000;
            let mut mbi = [0u8; 48];
            loop {
                let r = VirtualQueryEx(h, addr as *const u8, mbi.as_mut_ptr(), 48);
                if r == 0 { break; }
                let rb = usize::from_le_bytes(mbi[0..8].try_into().unwrap());
                let rs = usize::from_le_bytes(mbi[24..32].try_into().unwrap());
                let st = u32::from_le_bytes(mbi[32..36].try_into().unwrap());
                let pr = u32::from_le_bytes(mbi[36..40].try_into().unwrap());
                let nx = rb.wrapping_add(rs);
                if nx <= addr { break; }
                if st == MEM_COMMIT && (pr & 0x100) == 0 && (pr & 1) == 0 && rs > 0 && rs <= 0x10000000 {
                    let mut buf = vec![0u8; rs];
                    let mut nr = 0usize;
                    if ReadProcessMemory(h, rb as *const u8, buf.as_mut_ptr(), rs, &mut nr) != 0 && nr > 0 {
                        buf.truncate(nr);
                        for ioc in C2_IOCS { if find(&buf, ioc.as_bytes()) && !hits.contains(ioc) { hits.push(ioc); } }
                    }
                }
                addr = nx;
            }
            CloseHandle(h);
            if !hits.is_empty() {
                out.push(Finding { kind: "PROC-MEM".into(), high: true, detail: format!("ctfmon.exe (pid {}) 注入: {}", p, hits.join(", ")), action: "重启 ctfmon".into() });
            }
        }
    }
    out
}

const DEFAULT_HOSTS: &str = "# Copyright (c) 1993-2009 Microsoft Corp.\r\n#\r\n# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\r\n# This file contains the mappings of IP addresses to host names. Each\r\n# entry should be kept on an individual line. The IP address should\r\n# be placed in the first column followed by the corresponding host name.\r\n# The IP address and the host name should be separated by at least one space.\r\n#\r\n# localhost name resolution is handled within DNS itself.\r\n#\t127.0.0.1       localhost\r\n#\t::1             localhost\r\n";

fn scan_hosts() -> Vec<Finding> {
    let hp = r"C:\Windows\System32\drivers\etc\hosts";
    let mut out = Vec::new();
    if let Ok(content) = fs::read_to_string(hp) {
        for line in content.lines() {
            let c = line.trim_start();
            if c.is_empty() || c.starts_with('#') { continue; }
            if !c.starts_with("127.0.0.1") && !c.starts_with("::1") {
                out.push(Finding { kind: "HOSTS".into(), detail: "hosts 文件被篡改 (存在活动解析条目)".into(),
                                  high: true, action: "重置为默认并隔离原件".into() });
                break;
            }
        }
    }
    out
}

fn scan_wu() -> Vec<Finding> {
    let mut out = Vec::new();
    for svc in ["wuauserv", "UsoSvc", "uhssvc", "WaaSMedicSvc"] {
        if let Ok(o) = Command::new("reg").args(["query",
            &format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{}", svc), "/v", "Start"]).output() {
            let txt = String::from_utf8_lossy(&o.stdout);
            if !txt.contains("0x2") {
                out.push(Finding { kind: "WU".into(), high: true,
                    detail: format!("Windows 更新服务被禁用: {}", svc),
                    action: format!("sc config {} start= auto", svc) });
            }
        }
    }
    out
}

fn scan_files() -> Vec<Finding> {
    let mut out = Vec::new();
    let roots: Vec<PathBuf> = [
        Some(r"C:\Drivers".to_string()), std::env::var("TEMP").ok(),
        std::env::var("APPDATA").ok(), std::env::var("LOCALAPPDATA").ok(),
        std::env::var("ProgramData").ok(),
    ].into_iter().flatten().map(PathBuf::from).collect();
    let nh = ["ekxzjr", "dd9ocged", "srl.exe", "wdybq.dll", "drivers.dat", "drivers.dat.0",
        "wow64log.dll", "vafdska.sys", "vmservice.sys"];
    for root in &roots {
        walk(root, 0, &mut |p| {
            let s = p.to_string_lossy().to_lowercase();
            if s.contains(QUAR) { return; }
            let fnm = p.file_name().map(|x| x.to_string_lossy().to_lowercase()).unwrap_or_default();
            let isext = [".exe", ".dll", ".sys", ".xl", ".xlez"].iter().any(|e| fnm.ends_with(e));
            let by_nm = nh.iter().any(|h| &fnm == *h) || fnm.starts_with("itqe.");
            let sz = p.metadata().map(|m| m.len()).unwrap_or(0);
            let mut md = String::new();
            if sz > 100 * 1024 {
                if let Ok(hd) = read_head(p, 16) {
                    if find(&hd, MAGIC_STEG) { md.push_str(" [STEGR1Xp]"); }
                    if find(&hd, MAGIC_JELG) { md.push_str(" [JELG]"); }
                    if hd.starts_with(&[0x89, b'P', b'N', b'G']) && !fnm.ends_with(".png") { md.push_str(" [PNG伪装]"); }
                }
            }
            let mut hs = "";
            unsafe {
                if GetFileAttributesW(utf16(&p.to_string_lossy()).as_ptr()) & 0x6 != 0 { hs = " [隐藏+系统]"; }
            }
            if by_nm || !md.is_empty() || (hs != "" && isext) {
                out.push(Finding { kind: "FILE".into(), detail: format!("{}{}{}", p.display(), if by_nm { String::new() } else { md }, hs), high: by_nm, action: format!("quarantine {}", p.display()) });
            }
        });
    }
    out
}

fn read_head(p: &Path, n: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut f = fs::File::open(p)?;
    let mut b = vec![0u8; n as usize];
    let g = f.read(&mut b)?;
    b.truncate(g);
    Ok(b)
}

fn walk(dir: &Path, depth: usize, cb: &mut impl FnMut(&Path)) {
    if depth > 4 { return; }
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() { walk(&p, depth + 1, cb); } else { cb(&p); }
        }
    }
}

fn do_clean(f: &[Finding]) -> (usize, usize, String) {
    enable_privs();
    let mut extra = String::new();
    if f.iter().any(|x| x.kind == "PROC-MEM") {
        let _ = Command::new("taskkill").args(["/f", "/im", "ctfmon.exe"]).output();
        extra.push_str("[*] 已重启 ctfmon\n");
    }
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let qd = PathBuf::from(r"C:\ProgramData\sf_quarantine").join(ts.to_string());
    let (mut ok, mut fail) = (0usize, 0usize);
    for x in f {
        let s = match x.kind.as_str() {
            "PROC-MEM" => true,
            "PROCESS" => { let p = x.detail.rsplit("pid ").next().unwrap_or("").trim_end_matches(')'); run(&["taskkill", "/f", "/pid", p]) }
            "TASK" => { let t = x.detail.split(" [").next().unwrap_or(""); run(&["schtasks", "/delete", "/tn", t, "/f"]) }
            "SERVICE" => { let s = x.detail.split(" [").next().unwrap_or(""); run(&["sc", "stop", s]); run(&["sc", "delete", s]) }
            "FILE" => {
                let src = PathBuf::from(x.detail.split(" [").next().unwrap_or(""));
                take_own(&src.to_string_lossy());
                quarantine(&src, &qd)
            }
            "WU" => {
                let svc = x.detail.rsplit(": ").next().unwrap_or("");
                run(&["sc", "config", svc, "start=", "auto"]);
                run(&["sc", "config", svc, "depend=", "RpcSs"]);
                run(&["sc", "start", svc]);
                true
            }
            "HOSTS" => {
                let hp = Path::new(r"C:\Windows\System32\drivers\etc\hosts");
                let _ = quarantine(hp, &qd);           // 隔离原件 (失败不阻塞)
                take_own(&hp.to_string_lossy());
                fs::write(hp, DEFAULT_HOSTS).is_ok()
            }
            _ => true,
        };
        if s { ok += 1; } else { fail += 1; }
    }
    (ok, fail, extra)
}

fn run(c: &[&str]) -> bool { Command::new(c[0]).args(&c[1..]).output().map(|o| o.status.success()).unwrap_or(false) }

// ---- 加密隔离（与 WinUI 版 QuarCrypt 字节级兼容）----
// 容器: SFQENC1\0 | u64 明文长度 | u32 原路径UTF16字符数 | 原路径 | 密文体
// 密钥流: 以隔离目录名(清理时间戳)为种的 xorshift64*；明文 PE 落盘即失效，防残余组件搬回复活

struct XorShift(u64);

impl XorShift {
    fn new(seed: u64) -> Self {
        let mut s = XorShift(seed ^ 0xA55A_5AA5_0F0F_0F0F);
        for _ in 0..4 { s.next_word(); }
        s
    }
    fn next_word(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

fn apply_keystream(seed: u64, data: &mut [u8]) {
    let mut g = XorShift::new(seed);
    for ch in data.chunks_mut(8) {
        let k = g.next_word().to_le_bytes();
        for (i, b) in ch.iter_mut().enumerate() { *b ^= k[i]; }
    }
}

fn seal_quarantine_file(staged: &Path, orig: &str, ts: u64) -> std::io::Result<PathBuf> {
    let mut data = fs::read(staged)?;
    apply_keystream(ts, &mut data);
    let p16: Vec<u8> = orig.encode_utf16().flat_map(|w| w.to_le_bytes()).collect();
    let mut out = Vec::with_capacity(20 + p16.len() + data.len());
    out.extend_from_slice(QMAGIC);
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(&((p16.len() / 2) as u32).to_le_bytes());
    out.extend_from_slice(&p16);
    out.extend_from_slice(&data);
    let mut nm = staged.file_name().unwrap_or_default().to_os_string();
    nm.push(".qenc");
    let sealed = staged.with_file_name(nm);
    fs::write(&sealed, &out)?;
    let _ = fs::remove_file(staged);
    Ok(sealed)
}

fn quarantine(src: &Path, qd: &Path) -> bool {
    if !src.exists() { return true; }
    let _ = fs::create_dir_all(qd);
    take_own(&src.to_string_lossy());
    let ts: u64 = qd.file_name().and_then(|n| n.to_str()).and_then(|s| s.parse().ok()).unwrap_or(0);
    let staged = qd.join(src.file_name().unwrap_or_default());
    let moved = if fs::rename(src, &staged).is_ok() {
        true
    } else {
        fs::copy(src, &staged).is_ok() && fs::remove_file(src).is_ok()
    };
    if !moved { return false; }
    match seal_quarantine_file(&staged, &src.to_string_lossy(), ts) {
        Ok(_) => true,
        Err(_) => { let _ = fs::remove_file(&staged); false }
    }
}

fn restore_all() -> (usize, usize, String) {
    enable_privs();
    let root = PathBuf::from(r"C:\ProgramData\sf_quarantine");
    let (mut ok, mut fail) = (0usize, 0usize);
    let mut detail = String::new();
    if let Ok(batches) = fs::read_dir(&root) {
        for batch in batches.flatten() {
            let ts: u64 = batch.file_name().to_str().and_then(|s| s.parse().ok()).unwrap_or(0);
            let Ok(files) = fs::read_dir(batch.path()) else { continue };
            for f in files.flatten() {
                let p = f.path();
                let is_q = p.extension().and_then(|e| e.to_str())
                    .map(|e| e.eq_ignore_ascii_case("qenc")).unwrap_or(false);
                if !is_q { continue; }
                match unseal_and_restore(&p, ts) {
                    Ok(t) => { ok += 1; detail.push_str(&format!("[+] 已还原 {t}\n")); }
                    Err(e) => { fail += 1; detail.push_str(&format!("[-] 还原失败 {}: {e}\n", p.display())); }
                }
            }
        }
    }
    (ok, fail, detail)
}

fn unseal_and_restore(p: &Path, ts: u64) -> Result<String, String> {    let raw = fs::read(p).map_err(|e| e.to_string())?;
    if raw.len() < 24 || &raw[0..8] != QMAGIC { return Err("格式不符".into()); }
    let size = u64::from_le_bytes(raw[8..16].try_into().unwrap()) as usize;
    let plen = u32::from_le_bytes(raw[16..20].try_into().unwrap()) as usize;
    let hs = 20 + plen * 2;
    if plen > 4096 || raw.len() < hs || raw.len() - hs < size { return Err("头部损坏".into()); }
    let u16s: Vec<u16> = raw[20..hs].chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let orig = String::from_utf16_lossy(&u16s);
    let mut body = raw[hs..hs + size].to_vec();
    apply_keystream(ts, &mut body);
    let target = PathBuf::from(&orig);
    if target.as_os_str().is_empty() { return Err("空目标路径".into()); }
    if let Some(par) = target.parent() { let _ = fs::create_dir_all(par); }
    take_own(&target.to_string_lossy());
    fs::write(&target, &body).map_err(|e| e.to_string())?;
    let _ = fs::remove_file(p);
    Ok(orig)
}

// ---- 隔离区清空 ----

fn quarantine_stats() -> (usize, u64) {
    let root = PathBuf::from(QUAR_ROOT);
    let mut n = 0usize;
    let mut bytes = 0u64;
    let mut stack = vec![(root, 0)];
    while let Some((dir, d)) = stack.pop() {
        if d > 4 { continue; }
        if let Ok(rd) = fs::read_dir(&dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() { stack.push((p, d + 1)); }
                else if let Ok(m) = e.metadata() { n += 1; bytes += m.len(); }
            }
        }
    }
    (n, bytes)
}

fn quarantine_wipe() -> bool {
    enable_privs();
    let root = PathBuf::from(QUAR_ROOT);
    if !root.exists() { return true; }
    fs::remove_dir_all(&root).is_ok()
}

// ---- 极端模式 ----

fn xlog(s: &str) {
    let _ = fs::create_dir_all(QUAR_ROOT);
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true)
        .open(format!(r"{}\extreme.log", QUAR_ROOT)) {
        use std::io::Write;
        let _ = writeln!(f, "[{}] {}", now_str(), s);
    }
}

fn autorun_set() {
    if let Ok(exe) = std::env::current_exe() {
        let d = format!("\"{}\" --extreme", exe.display());
        run(&["reg", "add", RUN_KEY, "/v", "SFCleaner", "/t", "REG_SZ", "/d", &d, "/f"]);
        // 安全模式只执行带 * 前缀的条目
        run(&["reg", "add", RUN_KEY, "/v", "*SFCleaner", "/t", "REG_SZ", "/d", &d, "/f"]);
        run(&["reg", "add", r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "/v", "*SFCleaner", "/t", "REG_SZ", "/d", &d, "/f"]);
    }
}

// 安全模式启动 (safeboot minimal; 安全模式下 UAC 禁用 → 阶段二可改回)
fn run_logged(cmd: &str, args: &[&str]) -> bool {
    match Command::new(cmd).args(args).output() {
        Ok(o) => {
            let out = String::from_utf8_lossy(&o.stdout);
            let err = String::from_utf8_lossy(&o.stderr);
            xlog(&format!("exec {} {} -> {:?}", cmd, args.join(" "), o.status.code()));
            if !out.trim().is_empty() { xlog(&format!("  out: {}", out.trim())); }
            if !err.trim().is_empty() { xlog(&format!("  err: {}", err.trim())); }
            o.status.success()
        }
        Err(e) => { xlog(&format!("exec {} failed: {}", cmd, e)); false }
    }
}

fn safeboot_set() {
    xlog("safeboot: set minimal");
    run_logged("bcdedit", &["/set", "{current}", "safeboot", "minimal"]);
}

fn safeboot_clear() {
    xlog("safeboot: clear");
    run_logged("bcdedit", &["/deletevalue", "{current}", "safeboot"]);
}

fn autorun_del() {
    run(&["reg", "delete", RUN_KEY, "/v", "SFCleaner", "/f"]);
    run(&["reg", "delete", RUN_KEY, "/v", "*SFCleaner", "/f"]);
    run(&["reg", "delete", r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "/v", "*SFCleaner", "/f"]);
}

fn marker_set(v: &str) {
    run(&["reg", "add", MARK_KEY, "/v", "ExtremePhase", "/t", "REG_DWORD", "/d", v, "/f"]);
}

fn marker_get() -> u32 {
    if let Ok(o) = Command::new("reg").args(["query", MARK_KEY, "/v", "ExtremePhase"]).output() {
        let s = String::from_utf8_lossy(&o.stdout);
        if s.contains("0x2") { return 2; }
    }
    0
}

fn marker_del() {
    run(&["reg", "delete", MARK_KEY, "/v", "ExtremePhase", "/f"]);
}

// 自毁: 改名绕开运行中 exe 的锁定, MoveFileEx 延迟到下次开机删除
// ---- 不客气模式: 自定义证书 + 内核驱动清理 (marker=3 两阶段) ----
const DRV_SVC: &str = "SFCleanerDrv";
const CERT_CN: &str = "SFCleaner Test";

fn nomore_material_paths() -> (String, String) {
    let dir = std::env::current_exe().ok()
        .and_then(|p| p.parent().map(|d| d.to_string_lossy().to_string()))
        .unwrap_or_default();
    (format!("{dir}\\SFCleanerDrv.sys"), format!("{dir}\\SFCleanerCert.pfx"))
}

fn nomore_phase1() -> bool {
    let (drv, pfx) = nomore_material_paths();
    if !std::path::Path::new(&drv).exists() {
        xlog(&format!("nomore: 缺 {} ", drv));
        return false;
    }
    if !std::path::Path::new(&pfx).exists() {
        xlog(&format!("nomore: 缺 {}", pfx));
        return false;
    }
    xlog("nomore: testsigning on");
    run(&["bcdedit", "/set", "testsigning", "on"]);
    xlog("nomore: import cert (pfx 优先, cer 回退)");
    if std::path::Path::new(&pfx).exists() {
        run(&["certutil", "-f", "-p", "sf-cleaner", "-importpfx", &pfx, "ROOT"]);
        run(&["certutil", "-f", "-p", "sf-cleaner", "-importpfx", &pfx, "TrustedPublisher"]);
    } else {
        let cer = pfx.replace(".pfx", ".cer");
        run(&["certutil", "-addstore", "-f", "ROOT", &cer]);
        run(&["certutil", "-addstore", "-f", "TrustedPublisher", &cer]);
    }
    let dst = format!("C:\\Windows\\System32\\drivers\\{DRV_SVC}.sys");
    let _ = std::fs::remove_file(&dst);
    run(&["takeown", "/f", &dst, "/a"]);
    run(&["icacls", &dst, "/grant", "Administrators:F"]);
    if std::fs::copy(&drv, &dst).is_err() {
        xlog("nomore: 部署 driver 失败");
        return false;
    }
    run(&["sc", "stop", DRV_SVC]);
    run(&["sc", "delete", DRV_SVC]);
    run(&["sc", "create", DRV_SVC, "binPath=",
         &format!("System32\\drivers\\{DRV_SVC}.sys"), "type=", "kernel", "start=", "demand"]);
    true
}

fn nomore_phase2() {
    xlog("nomore: phase2 - 先解除 testsigning (已装载驱动不受影响, 防后续异常残留)");
    run(&["bcdedit", "/set", "testsigning", "off"]);
    xlog("nomore: phase2 start driver");
    run(&["sc", "start", DRV_SVC]);
    std::thread::sleep(std::time::Duration::from_secs(10));
    run(&["sc", "stop", DRV_SVC]);
    run(&["sc", "delete", DRV_SVC]);
    let _ = std::fs::remove_file(format!("C:\\Windows\\System32\\drivers\\{DRV_SVC}.sys"));
    xlog("nomore: remove cert");
    run(&["certutil", "-delstore", "ROOT", CERT_CN]);
    run(&["certutil", "-delstore", "TrustedPublisher", CERT_CN]);
    marker_del();
    unsafe {
        MessageBoxW(0, utf16("不客气模式完成\n驱动已装载→清理→卸载, 证书已移除\ntestsigning 已关闭(重启后生效) — 请重启").as_ptr(),
                    utf16("SFCleaner 不客气模式").as_ptr(), 0);
    }
}

fn nomore_run() {
    enable_privs();
    if marker_get() == 3 {
        nomore_phase2();
    } else {
        if !nomore_phase1() {
            unsafe {
                MessageBoxW(0, utf16("不客气模式缺材料\n请将 SFCleanerDrv.sys 与 SFCleanerCert.pfx 与程序同目录放置").as_ptr(),
                            utf16("SFCleaner 不客气模式").as_ptr(), 0);
            }
            return;
        }
        marker_set("3");
        xlog("nomore: phase1 done, bsod (testsigning 生效需重启)");
        unsafe { trigger_bsod(); }
    }
}

fn schedule_self_delete() {
    unsafe {
        if let Ok(exe) = std::env::current_exe() {
            let old = exe.with_extension("sfold");
            let _ = fs::rename(&exe, &old);
            MoveFileExW(utf16(&old.to_string_lossy()).as_ptr(), std::ptr::null(), 4);
        }
    }
}

unsafe fn trigger_bsod() -> ! {
    let mut old: u8 = 0;
    RtlAdjustPrivilege(19 /*SeShutdownPrivilege*/, 1, 0, &mut old);
    let mut resp: u32 = 0;
    // ResponseOption 必须是 6 (OptionShutdownSystem) 才会 bugcheck;
    // 传 1 (OptionOk) 只会弹系统硬错误对话框然后正常返回
    NtRaiseHardError(0xC0114514, 0, 0, std::ptr::null(), 6, &mut resp);
    loop { std::thread::sleep(std::time::Duration::from_secs(3600)); }
}

// 阶段一: 自启动+标记+清除+蓝屏; 阶段二: 再清除+解除+自毁+蓝屏
fn extreme_run() {
    enable_privs();
    if marker_get() == 2 {
        xlog("phase2: boot cleanup");
        let f = scan_all();
        let (ok, fail, _) = do_clean(&f);
        xlog(&format!("phase2: clean {} ok {} fail", ok, fail));
        autorun_del();
        marker_del();
        safeboot_clear(); // 解除安全模式 → 本次蓝屏后回正常启动
        schedule_self_delete();
        xlog("phase2: self-destruct scheduled, bsod now");
        unsafe { trigger_bsod(); }
    } else {
        xlog("phase1: arming extreme mode");
        autorun_set();
        marker_set("2");
        safeboot_set(); // 下一轮重启进安全模式再清场
        let f = scan_all();
        let (ok, fail, _) = do_clean(&f);
        xlog(&format!("phase1: clean {} ok {} fail, bsod now", ok, fail));
        unsafe { trigger_bsod(); }
    }
}

fn fmt_report(f: &[Finding]) -> String {
    if f.is_empty() { return "[OK] 未发现银狐痕迹\n".into(); }
    let mut s = String::new();
    for x in f {
        s.push_str(&format!("[{:9}] {}\n             → {}\n", x.kind, x.detail, x.action));
    }
    s.push_str(&format!("\n共 {} 项 (高置信 {}, 结构 {})\n", f.len(), f.iter().filter(|x| x.high).count(), f.iter().filter(|x| !x.high).count()));
    s
}

// ---- GUI v4 ----
static GUI_LOG: AtomicIsize = AtomicIsize::new(0);
static GUI_BG: AtomicIsize = AtomicIsize::new(0);

fn gui_append(s: &str) {
    let l = GUI_LOG.load(Ordering::SeqCst);
    if l == 0 { return; }
    unsafe {
        let w = utf16(s);
        SendMessageW(l, EM_SETSEL, usize::MAX, (usize::MAX - 1) as isize);
        SendMessageW(l, EM_REPLACESEL, 1, w.as_ptr() as isize);
    }
}

fn now_str() -> String {
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as i64 + 8 * 3600;
    format!("{:02}:{:02}:{:02}", (t / 3600) % 24, (t / 60) % 60, t % 60)
}

unsafe extern "system" fn wndproc(hwnd: isize, msg: u32, wp: usize, lp: isize) -> isize {
    match msg {
        WM_DESTROY => { PostQuitMessage(0); 0 }
        WM_COMMAND if (wp >> 16) == 0 => match (wp & 0xFFFF) as usize {
            1 => {
                gui_append(&format!("[{}] 扫描中 (多线程)...\n", now_str()));
                let f = scan_all();
                gui_append(&fmt_report(&f));
                gui_append("[提示] 点击 [清除] 处理以上项\n\n");
                0
            }
            2 => {
                let f = scan_all();
                if f.is_empty() { gui_append("无可清除项\n\n"); 0 }
                else {
                    let m = utf16(&format!("发现 {} 项银狐痕迹\n确认清除?", f.len()));
                    let c = utf16("SilverFox Cleaner v4");
                    if MessageBoxW(hwnd, m.as_ptr(), c.as_ptr(), MB_OKCANCEL | MB_ICONWARNING) == IDOK {
                        gui_append(&format!("[{}] 清除中 (TrustedInstaller 提权)...\n", now_str()));
                        let (ok, fail, extra) = do_clean(&f);
                        gui_append(&extra);
                        gui_append(&format!("完成: {} 成功, {} 失败\n建议重启确认无复活\n\n", ok, fail));
                    }
                    0
                }
            }
            3 => {
                let m = utf16("SilverFox Cleaner v4.1\n银狐 (dmo/client) 检测清除工具\n\n检测: 持久化/落盘/互斥/SrL/ctfmon注入\n权限: SYSTEM + TrustedInstaller\n隔离: SFQENC1 时间戳加密, 明文不落盘防复活\n还原: 仅本工具「还原隔离区」入口解密回写\n\n IOC: SHA256(DER)=3cef796a...");
                let c = utf16("关于");
                MessageBoxW(hwnd, m.as_ptr(), c.as_ptr(), 0);
                0
            }
            4 => {
                gui_append(&format!("[{}] 扫描隔离区...\n", now_str()));
                let (ok, fail, detail) = restore_all();
                gui_append(&detail);
                gui_append(&format!("还原完成: {} 成功, {} 失败\n\n", ok, fail));
                0
            }
            5 => {
                let (n, bytes) = quarantine_stats();
                if n == 0 {
                    gui_append("隔离区已为空\n\n");
                } else {
                    let m = utf16(&format!("删除隔离区全部 {} 个文件 (共 {:.1} MB)?\n不可恢复!", n, bytes as f64 / 1048576.0));
                    let c = utf16("清空隔离区");
                    if MessageBoxW(hwnd, m.as_ptr(), c.as_ptr(), MB_OKCANCEL | MB_ICONWARNING) == IDOK {
                        let ok = quarantine_wipe();
                        if ok {
                            gui_append(&format!("[*] 已清空隔离区 ({} 个文件)\n\n", n));
                        } else {
                            gui_append("[!] 清空失败\n\n");
                        }
                    }
                }
                0
            }
            6 => {
                let m = utf16("☢ 极端模式确认\n\n序列: 写入自启动 → 扫描清除 → 蓝屏重启\n重启后自动: 再次清除 → 解除自启动 → 自毁 → 再蓝屏\n\n共两次蓝屏! 请保存所有工作!\n确定执行?");
                let c = utf16("SilverFox Cleaner 极端模式");
                if MessageBoxW(hwnd, m.as_ptr(), c.as_ptr(), MB_OKCANCEL | MB_ICONWARNING) == IDOK {
                    gui_append("[!!] 极端模式启动 — 阶段序列执行中\n");
                    extreme_run();
                }
                0
            }
            7 => {
                let m = utf16("⚡ 不客气模式确认\n\n导入自定义证书 + 装载内核驱动清理\ntestsigning ON → 蓝屏重启 → 驱动清理\n→ 卸载 → 删证书 → testsigning OFF\n\n材料: SFCleanerDrv.sys + SFCleanerCert.pfx 同目录");
                let c = utf16("SilverFox Cleaner 不客气模式");
                if MessageBoxW(hwnd, m.as_ptr(), c.as_ptr(), MB_OKCANCEL | MB_ICONWARNING) == IDOK {
                    gui_append("[!!] 不客气模式启动\n");
                    nomore_run();
                }
                0
            }
            _ => 0,
        },
        _ => DefWindowProcW(hwnd, msg, wp, lp),
    }
}

fn run_gui() {
    unsafe {
        let bg = CreateSolidBrush(0x1E1E2E);
        GUI_BG.store(bg, Ordering::SeqCst);
        let inst = GetModuleHandleW(std::ptr::null());
        let cn = utf16("SFC4");
        #[repr(C)]
        struct WndClass {
            size: u32, style: u32, wp: usize, ce: i32, we: i32,
            inst: isize, icon: isize, cursor: isize, bg: isize,
            menu: isize, class_name: *const u16, icon_sm: isize,
        }
        let wc = WndClass {
            size: 80, style: 0, wp: wndproc as usize, ce: 0, we: 0,
            inst, icon: 0, cursor: 0, bg,
            menu: 0, class_name: cn.as_ptr(), icon_sm: 0,
        };
        RegisterClassExW(&wc as *const WndClass as *const u8);
        let title = utf16("SilverFox Cleaner v4.2 — 银狐检测清除 (dmo/client)");
        let hwnd = CreateWindowExW(0, cn.as_ptr(), title.as_ptr(), WS_OVERLAPPEDWINDOW | WS_VISIBLE, 200, 200, 920, 640, 0, 0, inst, std::ptr::null());
        if hwnd == 0 { return; }
        let font = GetStockObject(DEFAULT_GUI_FONT);
        let b1 = CreateWindowExW(0, utf16("BUTTON").as_ptr(), utf16("🔍 扫描").as_ptr(), WS_CHILD | WS_VISIBLE, 14, 12, 120, 38, hwnd, 1, inst, std::ptr::null());
        let b2 = CreateWindowExW(0, utf16("BUTTON").as_ptr(), utf16("🧹 清除").as_ptr(), WS_CHILD | WS_VISIBLE, 144, 12, 120, 38, hwnd, 2, inst, std::ptr::null());
        let b3 = CreateWindowExW(0, utf16("BUTTON").as_ptr(), utf16("ℹ 关于").as_ptr(), WS_CHILD | WS_VISIBLE, 274, 12, 80, 38, hwnd, 3, inst, std::ptr::null());
        let b4 = CreateWindowExW(0, utf16("BUTTON").as_ptr(), utf16("♻ 还原隔离区").as_ptr(), WS_CHILD | WS_VISIBLE, 364, 12, 130, 38, hwnd, 4, inst, std::ptr::null());
        let b5 = CreateWindowExW(0, utf16("BUTTON").as_ptr(), utf16("🗑 清空隔离区").as_ptr(), WS_CHILD | WS_VISIBLE, 504, 12, 150, 38, hwnd, 5, inst, std::ptr::null());
        let b6 = CreateWindowExW(0, utf16("BUTTON").as_ptr(), utf16("☢ 极端").as_ptr(), WS_CHILD | WS_VISIBLE, 624, 12, 110, 38, hwnd, 6, inst, std::ptr::null());
        let b7 = CreateWindowExW(0, utf16("BUTTON").as_ptr(), utf16("⚡ 不客气").as_ptr(), WS_CHILD | WS_VISIBLE, 744, 12, 130, 38, hwnd, 7, inst, std::ptr::null());
        let edit = CreateWindowExW(0x200, utf16("EDIT").as_ptr(), utf16("").as_ptr(), WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | WS_VSCROLL | ES_AUTOVSCROLL | ES_WANTRETURN, 14, 58, 880, 490, hwnd, 4, inst, std::ptr::null());
        let status = CreateWindowExW(0, utf16("STATIC").as_ptr(), utf16("就绪 — 扫描 | SYSTEM + TrustedInstaller | 加密隔离: sf_quarantine (仅本工具可还原)").as_ptr(), WS_CHILD | WS_VISIBLE, 14, 556, 880, 24, hwnd, 5, inst, std::ptr::null());
        for h in [b1, b2, b3, b4, b5, b6, b7, edit, status] { SendMessageW(h, WM_SETFONT, font as usize, 1); }
        GUI_LOG.store(edit, Ordering::SeqCst);
        gui_append("╔════════════════════════════════════╗\n║  SilverFox Cleaner v4.1 — dmo/client ║\n╚════════════════════════════════════╝\n\n检测: 持久化 / 落盘物 / 互斥 / SrL / ctfmon内存注入\n权限: SYSTEM + TrustedInstaller 提权\n隔离: 时间戳加密 SFQENC1 (明文不落盘防复活)\n还原: [♻ 还原隔离区] 或 restore 子命令\n扫描: 多线程并行 (任务+服务 | 进程+内存 | 文件)\n\n");
        let mut msg = [0u8; 48];
        loop {
            let r = GetMessageW(msg.as_mut_ptr(), 0, 0, 0);
            if r <= 0 { break; }
            TranslateMessage(msg.as_ptr());
            DispatchMessageW(msg.as_ptr());
        }
    }
}

fn run_cli(mode: &str, yes: bool) {
    let f = scan_all();
    let r = fmt_report(&f);
    let t = utf16(&r);
    let c = utf16("silverfox-cleaner v4");
    unsafe { MessageBoxW(0, t.as_ptr(), c.as_ptr(), 0); }
    if mode == "clean" && !f.is_empty() && yes {
        let (ok, fail, extra) = do_clean(&f);
        let r = format!("{}\n清除: {} 成功, {} 失败", extra, ok, fail);
        let t = utf16(&r);
        unsafe { MessageBoxW(0, t.as_ptr(), utf16("清除结果").as_ptr(), 0); }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("scan") => run_cli("scan", false),
        Some("clean") => run_cli("clean", args.iter().any(|a| a == "--yes")),
        Some("restore") => {
            let (ok, fail, d) = restore_all();
            let r = format!("{d}\n还原: {ok} 成功, {fail} 失败");
            unsafe { MessageBoxW(0, utf16(&r).as_ptr(), utf16("还原隔离区").as_ptr(), 0); }
        }
        Some("--extreme") => extreme_run(),
        Some("--nomore") => nomore_run(),
        Some("--extreme-abort") => {
            safeboot_clear();
            autorun_del();
            marker_del();
            unsafe { MessageBoxW(0, utf16("极端模式已解除 (自启动+阶段标记已清除)").as_ptr(), utf16("SFCleaner").as_ptr(), 0); }
        }
        Some("--wipe-quarantine") => {
            let (n, bytes) = quarantine_stats();
            let ok = quarantine_wipe();
            let r = if ok { format!("已清空隔离区: {} 个文件 ({:.1} MB)", n, bytes as f64 / 1048576.0) } else { "清空失败".into() };
            unsafe { MessageBoxW(0, utf16(&r).as_ptr(), utf16("清空隔离区").as_ptr(), 0); }
        }
        _ => run_gui(),
    }
}
