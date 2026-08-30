// silverfox-cleaner v4 — 银狐检测清除工具
// v4: 多线程扫描 + TrustedInstaller 提权删除 + 美化 GUI + drivers.dat 检测
#![cfg(windows)]
#![windows_subsystem = "windows"]
#![allow(non_snake_case, dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicIsize, Ordering};
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
    fn GetShortPathNameW(l: *const u16, s: *mut u16, n: u32) -> u32;
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
#[link(name = "version")]
extern "system" {
    fn GetFileVersionInfoSizeW(l: *const u16, h: *mut u32) -> u32;
    fn GetFileVersionInfoW(l: *const u16, h: u32, cb: u32, d: *mut u8) -> i32;
    fn VerQueryValueW(d: *const u8, sub: *const u16, buf: *mut *mut u8, len: *mut u32) -> i32;
}
#[link(name = "wintrust")]
extern "system" {
    fn WinVerifyTrust(hwnd: isize, action: *const Guid, data: *mut WTData) -> i32;
    fn CryptCATAdminAcquireContext(h: *mut isize, g: *const Guid, f: u32) -> i32;
    fn CryptCATAdminCalcHashFromFileHandle(fh: isize, cb: *mut u32, buf: *mut u8, f: u32) -> i32;
    fn CryptCATAdminEnumCatalogFromHash(hca: isize, hash: *const u8, cb: u32, f: u32, prev: *mut isize) -> isize;
    fn CryptCATCatalogInfoFromContext(hc: isize, ci: *mut CatalogInfo, f: u32) -> i32;
    fn CryptCATAdminReleaseCatalogContext(hca: isize, hc: isize, f: u32) -> i32;
    fn CryptCATAdminReleaseContext(hca: isize, f: u32) -> i32;
}

#[repr(C)]
struct Guid { a: u32, b: u16, c: u16, d: [u8; 8] }
const WTV_ACTION: Guid = Guid {
    a: 0x00AAC56B, b: 0xCD44, c: 0x11D0, d: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
};
const WTD_UI_NONE: u32 = 2; /* 1=WTD_UI_ALL 会弹运行警告, 必须 2 静默验签 */
const WTD_CHOICE_FILE: u32 = 1;
const WTD_CHOICE_CATALOG: u32 = 2;
/* catalog 物理库 catroot\{F750E6C3-...} 对应 DRIVER_ACTION_VERIFY subsystem;
   GENERIC_VERIFY_V2 acquire 在 Win11 枚举不到系统 catalog */
const DRIVER_ACTION: Guid = Guid {
    a: 0xF750E6C3, b: 0x38EE, c: 0x11D1, d: [0x85, 0xE5, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
};
const WTD_STATE_VERIFY: u32 = 1;
const WTD_STATE_CLOSE: u32 = 2;

#[repr(C)]
struct WTFileInfo { cb: u32, path: *const u16, hfile: isize, known_subject: *const u8 }
#[repr(C)]
struct WTData {
    cb: u32,
    policy: *mut u8,
    sip: *mut u8,
    ui_choice: u32,
    revoke_checks: u32,
    union_choice: u32,
    pfile: *mut u8,
    state_action: u32,
    h_wvt_state: isize,
    url_ref: *const u16,
    prov_flags: u32,
    ui_context: u32,
    sig_settings: *mut u8,
}

#[repr(C)]
struct CatalogInfo { cb: u32, file: [u16; 260] }   /* sizeof = 4 + 260*2 = 524 */
#[repr(C)]
struct WTCatInfo {                                 /* mingw 扩展版 WINTRUST_CATALOG_INFO, x64 = 64B */
    cb: u32,
    ver: u32,
    cat_path: *const u16,
    tag: *const u16,
    path: *const u16,
    h_member_file: isize,
    hash_ptr: *const u8,
    hash_len: u32,
    pc_ctx: *const u8,
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
    let r4 = Arc::clone(&results);
    handles.push(thread::spawn(move || {
        let mut f = scan_wb();
        f.extend(scan_windir());
        r4.lock().unwrap().extend(f);
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
            /* 仅 Start=4 (禁用) 才报; 3=demand 是 Win11 默认手动启动, 误报 */
            let disabled = txt.lines().any(|l| {
                l.contains("Start") && l.contains("REG_DWORD") && l.trim_end().ends_with("0x4")
            });
            if disabled {
                out.push(Finding { kind: "WU".into(), high: true,
                    detail: format!("Windows 更新服务被禁用: {} (Start=4)", svc),
                    action: format!("sc config {} start= auto", svc) });
            }
        }
    }
    out
}

/* 版本资源 OriginalFilename: 改名白加黑核心信号 (腾讯ACE改名steam.exe) */
fn ver_orig_name(p: &Path) -> Option<String> {
    let wpath = utf16(&p.to_string_lossy());
    unsafe {
        let mut h: u32 = 0;
        let sz = GetFileVersionInfoSizeW(wpath.as_ptr(), &mut h);
        if sz == 0 || sz > 262144 { return None; }
        let mut vbuf = vec![0u8; sz as usize];
        if GetFileVersionInfoW(wpath.as_ptr(), 0, sz, vbuf.as_mut_ptr()) == 0 { return None; }
        let mut sub = utf16("\\VarFileInfo\\Translation");
        let mut ptrans: *mut u8 = std::ptr::null_mut();
        let mut tsz: u32 = 0;
        if VerQueryValueW(vbuf.as_ptr(), sub.as_mut_ptr(), &mut ptrans, &mut tsz) == 0 || tsz < 4 {
            return None;
        }
        let lang = u16::from_le_bytes([*ptrans, *ptrans.add(1)]);
        let cp = u16::from_le_bytes([*ptrans.add(2), *ptrans.add(3)]);
        sub = utf16(&format!("\\StringFileInfo\\{:04x}{:04x}\\OriginalFilename", lang, cp));
        let mut porig: *mut u8 = std::ptr::null_mut();
        let mut olen: u32 = 0;
        if VerQueryValueW(vbuf.as_ptr(), sub.as_mut_ptr(), &mut porig, &mut olen) == 0 || olen < 2 {
            return None;
        }
        let ws: Vec<u16> = std::slice::from_raw_parts(porig as *const u16, (olen / 2) as usize)
            .iter().take_while(|&&c| c != 0).copied().collect();
        Some(String::from_utf16_lossy(&ws))
    }
}

fn wb_is_signed(p: &Path) -> bool {
    let wpath = utf16(&p.to_string_lossy());
    let mut fi = WTFileInfo {
        cb: std::mem::size_of::<WTFileInfo>() as u32,
        path: wpath.as_ptr(),
        hfile: 0,
        known_subject: std::ptr::null(),
    };
    let mut wd = WTData {
        cb: std::mem::size_of::<WTData>() as u32,
        policy: std::ptr::null_mut(),
        sip: std::ptr::null_mut(),
        ui_choice: WTD_UI_NONE,
        revoke_checks: 0,
        union_choice: WTD_CHOICE_FILE,
        pfile: &mut fi as *mut WTFileInfo as *mut u8,
        state_action: WTD_STATE_VERIFY,
        h_wvt_state: 0,
        url_ref: std::ptr::null(),
        prov_flags: 0x1000, /* WTD_CACHE_ONLY_URL_RETRIEVAL */
        ui_context: 0,
        sig_settings: std::ptr::null_mut(),
    };
    let r = unsafe { WinVerifyTrust(0, &WTV_ACTION, &mut wd) };
    wd.state_action = WTD_STATE_CLOSE;
    unsafe { WinVerifyTrust(0, &WTV_ACTION, &mut wd) };
    r == 0 || wb_catalog_signed(p)
}

/* catalog 回退: 系统 PE 无内嵌签名, 由 catalog 覆盖 —
   算哈希 -> 取第一个含此哈希的 catalog -> WTD_CHOICE_CATALOG 复验 */
fn wb_catalog_signed(p: &Path) -> bool {
    use std::os::windows::io::AsRawHandle;
    let f = match fs::File::open(p) { Ok(f) => f, Err(_) => return false };
    let fh = f.as_raw_handle() as isize;
    unsafe {
        let mut hash = [0u8; 100];
        let mut cb: u32 = hash.len() as u32;
        if CryptCATAdminCalcHashFromFileHandle(fh, &mut cb, hash.as_mut_ptr(), 0) != 0
            || cb == 0 || (cb as usize) > hash.len()
        {
            return false;
        }
        let mut wtag: Vec<u16> = Vec::with_capacity(cb as usize * 2 + 1);
        for b in &hash[..cb as usize] {
            wtag.extend(format!("{:02X}", b).encode_utf16());
        }
        wtag.push(0);
        let wpath = utf16(&p.to_string_lossy());
        for sub in [&DRIVER_ACTION, &WTV_ACTION] {
            let mut hca: isize = 0;
            if CryptCATAdminAcquireContext(&mut hca, sub, 0) != 0 { continue; }
            let hc = CryptCATAdminEnumCatalogFromHash(hca, hash.as_ptr(), cb, 0, std::ptr::null_mut());
            if hc != 0 {
                let mut ci = CatalogInfo { cb: 524, file: [0u16; 260] };
                if CryptCATCatalogInfoFromContext(hc, &mut ci, 0) != 0 {
                    let mut wci = WTCatInfo {
                        cb: 64,
                        ver: 0,
                        cat_path: ci.file.as_ptr(),
                        tag: wtag.as_ptr(),
                        path: wpath.as_ptr(),
                        h_member_file: 0,
                        hash_ptr: hash.as_ptr(),
                        hash_len: cb,
                        pc_ctx: std::ptr::null(),
                    };
                    let mut wd = WTData {
                        cb: std::mem::size_of::<WTData>() as u32,
                        policy: std::ptr::null_mut(),
                        sip: std::ptr::null_mut(),
                        ui_choice: WTD_UI_NONE,
                        revoke_checks: 0,
                        union_choice: WTD_CHOICE_CATALOG,
                        pfile: &mut wci as *mut WTCatInfo as *mut u8,
                        state_action: WTD_STATE_VERIFY,
                        h_wvt_state: 0,
                        url_ref: std::ptr::null(),
                        prov_flags: 0x1000,
                        ui_context: 0,
                        sig_settings: std::ptr::null_mut(),
                    };
                    let r = WinVerifyTrust(0, &WTV_ACTION, &mut wd);
                    wd.state_action = WTD_STATE_CLOSE;
                    WinVerifyTrust(0, &WTV_ACTION, &mut wd);
                    if r == 0 {
                        CryptCATAdminReleaseCatalogContext(hca, hc, 0);
                        CryptCATAdminReleaseContext(hca, 0);
                        return true;
                    }
                }
                CryptCATAdminReleaseCatalogContext(hca, hc, 0);
            }
            CryptCATAdminReleaseContext(hca, 0);
        }
    }
    false
}

fn scan_wb() -> Vec<Finding> {
    let mut out = Vec::new();
    let roots: Vec<PathBuf> = [
        Some(r"C:\Drivers".to_string()), std::env::var("TEMP").ok(),
        std::env::var("APPDATA").ok(), std::env::var("LOCALAPPDATA").ok(),
        std::env::var("ProgramData").ok(),
    ].into_iter().flatten().map(PathBuf::from).collect();
    for r in &roots { wb_dir(r, 0, &mut out); }
    out
}

fn wb_dir(dir: &Path, depth: usize, out: &mut Vec<Finding>) {
    if depth > 4 { return; }
    let low = dir.to_string_lossy().to_lowercase();
    if low.contains("sf_quarantine") { return; }
    const WL: [&str; 5] = ["\\programs\\", "\\package cache\\", "\\windowsapps\\", "\\microsoft\\", "\\windows\\"];
    let whitelisted = WL.iter().any(|w| low.contains(w));   /* 白名单目录降级: 只跑改名检测 */
    /* 枚举先行: 无 exe 或无 dll 的目录 (绝大多数) 0 次验签; 配对才查, 找到即停 */
    let mut exes: Vec<PathBuf> = Vec::new();
    let mut dlls: Vec<PathBuf> = Vec::new();
    let mut subs: Vec<PathBuf> = Vec::new();
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            if let Ok(ft) = e.file_type() {
                if ft.is_dir() {
                    if !ft.is_symlink() { subs.push(e.path()); }
                    continue;
                }
            }
            let p = e.path();
            let fnm = p.file_name().map(|x| x.to_string_lossy().to_lowercase()).unwrap_or_default();
            if fnm.ends_with(".exe") {
                if exes.len() < 24 { exes.push(p); }
            } else if fnm.ends_with(".dll") {
                if dlls.len() < 64 { dlls.push(p); }
            }
        }
    }
    /* 改名检测 (白名单目录也跑): 签名有效但 OriginalFilename 与磁盘名不符 */
    if whitelisted || !dlls.is_empty() {
        if !whitelisted && dlls.is_empty() { /* 配对门槛: 无 dll 不逐个验 exe */ }
        else {
            for e in &exes {
                if !wb_is_signed(e) { continue; }
                if let Some(orig) = ver_orig_name(e) {
                    let base = e.file_name().map(|x| x.to_string_lossy().to_lowercase())
                        .unwrap_or_default();
                    if base != orig.to_lowercase() {
                        out.push(Finding {
                            kind: "FILE".into(),
                            detail: format!("{} [白加黑: 签名EXE被改名 (OriginalFilename={})]", e.display(), orig),
                            high: true,
                            action: format!("quarantine {}", e.display()),
                        });
                        break;
                    }
                }
            }
            if !whitelisted {
                let se = exes.iter().any(|e| wb_is_signed(e));
                if se {
                    if let Some(h) = dlls.iter().find(|d| !wb_is_signed(d)) {
                        out.push(Finding {
                            kind: "FILE".into(),
                            detail: format!("{} [白加黑: 有效签名EXE+未签名DLL]", h.display()),
                            high: false,
                            action: format!("quarantine {}", h.display()),
                        });
                    }
                }
            }
        }
    }
    for s in subs { wb_dir(&s, depth + 1, out); }
}

/* ---- SHA-512 (自足实现, 驱动制品哈希排除用) ---- */
const K512: [u64; 80] = [
    0x428a2f98d728ae22,0x7137449123ef65cd,0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,0x3956c25bf348b538,0x59f111f1b605d019,
    0x923f82a4af194f9b,0xab1c5ed5da6d8118,0xd807aa98a3030242,
    0x12835b0145706fbe,0x243185be4ee4b28c,0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,0x80deb1fe3b1696b1,0x9bdc06a725c71235,
    0xc19bf174cf692694,0xe49b69c19ef14ad2,0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65,0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,0x5cb0a9dcbd41fbd4,0x76f988da831153b5,
    0x983e5152ee66dfab,0xa831c66d2db43210,0xb00327c898fb213f,
    0xbf597fc7beef0ee4,0xc6e00bf33da88fc2,0xd5a79147930aa725,
    0x06ca6351e003826f,0x142929670a0e6e70,0x27b70a8546d22ffc,
    0x2e1b21385c26c926,0x4d2c6dfc5ac42aed,0x53380d139d95b3df,
    0x650a73548baf63de,0x766a0abb3c77b2a8,0x81c2c92e47edaee6,
    0x92722c851482353b,0xa2bfe8a14cf10364,0xa81a664bbc423001,
    0xc24b8b70d0f89791,0xc76c51a30654be30,0xd192e819d6ef5218,
    0xd69906245565a910,0xf40e35855771202a,0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,0x1e376c085141ab53,0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3,0x748f82ee5defb2fc,
    0x78a5636f43172f60,0x84c87814a1f0ab72,0x8cc702081a6439ec,
    0x90befffa23631e28,0xa4506cebde82bde9,0xbef9a3f7b2c67915,
    0xc67178f2e372532b,0xca273eceea26619c,0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178,0x06f067aa72176fba,
    0x0a637dc5a2c898a6,0x113f9804bef90dae,0x1b710b35131c471b,
    0x28db77f523047d84,0x32caab7b40c72493,0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,0x4cc5d4becb3e42b6,0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,0x6c44198c4a475817,

];

struct Sha512 { h: [u64; 8], len: u64, buf: [u8; 128], bl: usize }

impl Sha512 {
    fn new() -> Self {
        Sha512 { h: [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                     0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179],
                 len: 0, buf: [0u8; 128], bl: 0 }
    }
    fn ror(x: u64, n: u32) -> u64 { x.rotate_right(n) }
    fn block(&mut self, p: &[u8]) {
        let mut w = [0u64; 80];
        for i in 0..16 {
            w[i] = u64::from_be_bytes(p[i*8..i*8+8].try_into().unwrap());
        }
        for i in 16..80 {
            let s0 = Self::ror(w[i-15], 1) ^ Self::ror(w[i-15], 8) ^ (w[i-15] >> 7);
            let s1 = Self::ror(w[i-2], 19) ^ Self::ror(w[i-2], 61) ^ (w[i-2] >> 6);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) =
            (self.h[0], self.h[1], self.h[2], self.h[3], self.h[4], self.h[5], self.h[6], self.h[7]);
        for i in 0..80 {
            let s1 = Self::ror(e, 14) ^ Self::ror(e, 18) ^ Self::ror(e, 41);
            let ch = (e & f) ^ (!e & g);
            let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K512[i]).wrapping_add(w[i]);
            let s0 = Self::ror(a, 28) ^ Self::ror(a, 34) ^ Self::ror(a, 39);
            let mj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(mj);
            h = g; g = f; f = e; e = d.wrapping_add(t1);
            d = c; c = b; b = a; a = t1.wrapping_add(t2);
        }
        self.h[0] = self.h[0].wrapping_add(a); self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c); self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e); self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g); self.h[7] = self.h[7].wrapping_add(h);
    }
    fn update(&mut self, mut d: &[u8]) {
        self.len = self.len.wrapping_add(d.len() as u64);
        while !d.is_empty() {
            let take = (128 - self.bl).min(d.len());
            self.buf[self.bl..self.bl + take].copy_from_slice(&d[..take]);
            self.bl += take; d = &d[take..];
            if self.bl == 128 { let b128 = self.buf; self.block(&b128); self.bl = 0; }
        }
    }
    fn finalize(&mut self) -> [u8; 64] {
        let bits = self.len.wrapping_mul(8);
        let mut pad = [0u8; 128];
        pad[0] = 0x80;
        let padlen = if self.bl < 112 { 112 - self.bl } else { 240 - self.bl };
        let mut out = [0u8; 64];
        for i in 0..8 { pad[8 + i] = (bits >> (56 - i * 8)) as u8; }
        self.update(&pad[..padlen]);
        self.update(&pad[120..128]);   /* 尾 8B = bits (高 8B 已零) */
        for i in 0..8 {
            out[i*8]   = (self.h[i] >> 56) as u8; out[i*8+1] = (self.h[i] >> 48) as u8;
            out[i*8+2] = (self.h[i] >> 40) as u8; out[i*8+3] = (self.h[i] >> 32) as u8;
            out[i*8+4] = (self.h[i] >> 24) as u8; out[i*8+5] = (self.h[i] >> 16) as u8;
            out[i*8+6] = (self.h[i] >> 8) as u8;  out[i*8+7] =  self.h[i] as u8;
        }
        out
    }
}

fn sha512(data: &[u8]) -> [u8; 64] {
    let mut s = Sha512::new();
    s.update(data);
    s.finalize()
}


/* ---- %WINDIR% 随机名 PE/bat 检测 ---- */
const WD_SKIP: [&str; 38] = [
    "\\winsxs", "\\softwaredistribution", "\\driverstore", "\\installer",
    "\\assembly", "\\microsoft.net", "\\servicing", "\\logfiles", "\\logs",
    "\\spool", "\\catroot", "\\fonts", "\\media", "\\ime", "\\web",
    "\\wallpaper", "\\oledb", "\\mui", "\\ehome", "\\pchealth", "\\resources",
    "\\livekernelreports", "\\minidump", "\\prefetch", "\\appcompat",
    "\\apppatch", "\\csc", "\\diagnostics", "\\panther", "\\performance",
    "\\pla", "\\registration", "\\shellcomponents", "\\triage", "\\winstore",
    "\\tokens", "\\csp", "\\msdtc",
];

fn wd_random_name(fnm: &str) -> Option<bool> /* Some(true)=PE Some(false)=bat None=不匹配 */ {
    let dot = fnm.rfind('.')?;
    let ext = fnm[dot..].to_lowercase();
    let is_pe = matches!(ext.as_str(), ".exe" | ".dll" | ".sys");
    if !is_pe && ext != ".bat" { return None; }
    let base = &fnm[..dot];
    let bl = base.len();
    if bl < 6 || bl > 16 { return None; }
    let mut dig = 0usize;
    let mut up = 0usize;
    for c in base.chars() {
        if c.is_ascii_digit() { dig += 1; }
        else if c.is_ascii_uppercase() { up += 1; }
        else if c.is_ascii_lowercase() { continue; }
        else { return None; }
    }
    if !is_pe { return Some(false); }
    if dig >= 2 || up > 0 || bl >= 8 { return Some(true); }
    None
}

fn wd_scan_dir(dir: &Path, depth: usize, out: &mut Vec<Finding>, self_sha: &Option<(u64, [u8; 64])>) {
    if depth > 4 { return; }
    let low = dir.to_string_lossy().to_lowercase();
    if WD_SKIP.iter().any(|w| low.contains(w)) { return; }
    let mut subs: Vec<PathBuf> = Vec::new();
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            let is_dir;
            let is_link;
            if let Ok(ft) = e.file_type() {
                is_dir = ft.is_dir();
                is_link = ft.is_symlink();
            } else { continue; }
            if is_dir {
                if !is_link { subs.push(p); }
                continue;
            }
            let fnm = p.file_name().map(|x| x.to_string_lossy().to_string()).unwrap_or_default();
            match wd_random_name(&fnm) {
                Some(true) => {
                    /* SHA-512 哈希排除: 逐字节等于本版驱动才豁免 (改名伪装照样被扫) */
                    if let Some((dl, dsha)) = self_sha {
                        if fs::metadata(&p).map(|m| m.len() == *dl).unwrap_or(false)
                            && fs::read(&p).map(|b| sha512(&b) == *dsha).unwrap_or(false) { continue; }
                    }
                    if wb_is_signed(&p) { continue; }   /* 随机名但签名有效 → 放行 */
                    out.push(Finding {
                        kind: "FILE".into(),
                        detail: format!("{} [随机名未签名PE]", p.display()),
                        high: true,
                        action: format!("quarantine {}", p.display()),
                    });
                }
                Some(false) => out.push(Finding {
                    kind: "FILE".into(),
                    detail: format!("{} [随机名bat]", p.display()),
                    high: true,
                    action: format!("quarantine {}", p.display()),
                }),
                None => {}
            }
        }
    }
    for sdir in subs { wd_scan_dir(&sdir, depth + 1, out, self_sha); }
}

fn scan_windir() -> Vec<Finding> {
    let mut out = Vec::new();
    /* 本版驱动 SHA-512 (embed-drv feature 才有; 无内嵌时不做哈希豁免) */
    let self_sha: Option<(u64, [u8; 64])> = {
        #[cfg(feature = "embed-drv")]
        { Some((DRV_EMBED.len() as u64, sha512(DRV_EMBED))) }
        #[cfg(not(feature = "embed-drv"))]
        { None }
    };
    let wd = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".into());
    wd_scan_dir(Path::new(&wd), 0, &mut out, &self_sha);
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
        "wow64log.dll", "vafdska.sys", "vmservice.sys", "steam.exe"];
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
                    if hd.starts_with(&[0x89, b'P', b'N', b'G']) && !fnm.ends_with(".png")
                        && !s.contains("\\packages\\") { md.push_str(" [PNG伪装]"); } /* UWP 磁贴缓存合法 */
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
        // 优先 8.3 短路径写 Run/RunOnce (无括号/空格歧义), 拿不到才回退引号长路径
        let d = {
            let wide = utf16(&exe.to_string_lossy());
            let mut buf = vec![0u16; 520];
            let n = unsafe { GetShortPathNameW(wide.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
            if n > 0 && (n as usize) < buf.len() {
                format!("{} --extreme", String::from_utf16_lossy(&buf[..n as usize]))
            } else {
                format!("\"{}\" --extreme", exe.display())
            }
        };
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
        "/v", "SFCleaner", "/f"]);
    run(&["reg", "delete", r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "/v", "*SFCleaner", "/f"]);
}

/* 不客气 phase2 自启动: RunOnce 一次性 (普通登录 + 安全模式), 短路径消歧义 */
fn nomore_autorun_set() {
    if let Ok(exe) = std::env::current_exe() {
        let d = {
            let wide = utf16(&exe.to_string_lossy());
            let mut buf = vec![0u16; 520];
            let n = unsafe { GetShortPathNameW(wide.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
            if n > 0 && (n as usize) < buf.len() {
                format!("{} --nomore2", String::from_utf16_lossy(&buf[..n as usize]))
            } else {
                format!("\"{}\" --nomore2", exe.display())
            }
        };
        let ro = r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce";
        run(&["reg", "add", ro, "/v", "SFCleaner", "/t", "REG_SZ", "/d", &d, "/f"]);
        run(&["reg", "add", ro, "/v", "*SFCleaner", "/t", "REG_SZ", "/d", &d, "/f"]);
    }
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

#[cfg(feature = "embed-drv")]
const DRV_EMBED: &[u8] = include_bytes!("../SFCleanerDrv.sys");
#[cfg(feature = "embed-drv")]
const CER_EMBED: &[u8] = include_bytes!("../SFCleanerCert.cer");
const CERT_CN: &str = "SFCleaner Test";

fn nomore_material_paths() -> (String, String, String) {
    let dir = std::env::current_exe().ok()
        .and_then(|p| p.parent().map(|d| d.to_string_lossy().to_string()))
        .unwrap_or_default();
    (format!("{dir}\\SFCleanerDrv.sys"),
     format!("{dir}\\SFCleanerCert.pfx"),
     format!("{dir}\\SFCleanerCert.cer"))
}

fn secureboot_on() -> bool {
    // HKLM\...\SecureBoot\State\UEFISecureBootEnabled == 1 (无键 = 非 UEFI/未启用)
    match Command::new("reg")
        .args(["query", r"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State", "/v", "UEFISecureBootEnabled"])
        .output()
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout).contains("0x1"),
        Err(_) => false,
    }
}

fn nomore_phase1() -> bool {
    let (drv, pfx, cer) = nomore_material_paths();
    #[cfg(feature = "embed-drv")]
    {
        // 材料先落盘再导入; cer 内容写 cer 名, 不再伪装 pfx
        let _ = std::fs::write(&drv, DRV_EMBED);
        xlog("nomore: 内嵌驱动已释放");
        if !Path::new(&pfx).exists() && !Path::new(&cer).exists() {
            let _ = std::fs::write(&cer, CER_EMBED);
            xlog("nomore: 内嵌证书已释放 (cer)");
        }
    }
    if !Path::new(&drv).exists() {
        xlog(&format!("nomore: [中止] 缺 {}", drv));
        return false;
    }
    let hp = Path::new(&pfx).exists();
    let hc = Path::new(&cer).exists();
    if !hp && !hc {
        xlog(&format!("nomore: [中止] 缺证书材料 ({} 或 {})", pfx, cer));
        return false;
    }
    // Secure Boot 预检: 开启时 bcdedit testsigning 会被策略拒绝, 提前给出指引
    if secureboot_on() {
        xlog("nomore: [中止] Secure Boot 开启 — testsigning 会被安全启动策略拒绝");
        xlog("nomore: VMware: 虚拟机设置->选项->高级->固件类型UEFI, 取消勾选'启用安全引导'后重启 VM");
        return false;
    }
    xlog("nomore: testsigning on");
    if !run(&["bcdedit", "/set", "testsigning", "on"]) {
        xlog("nomore: [中止] bcdedit testsigning 失败 — 固件 Secure Boot 开着会被拒, 请在 VM 设置里关掉再试");
        return false;
    }
    xlog(&format!("nomore: import cert ({})", if hp { "pfx" } else { "cer" }));
    if hp {
        let r1 = run(&["certutil", "-f", "-p", "sf-cleaner", "-importpfx", &pfx, "ROOT"]);
        let r2 = run(&["certutil", "-f", "-p", "sf-cleaner", "-importpfx", &pfx, "TrustedPublisher"]);
        if !r1 && !r2 { xlog("nomore: [中止] pfx 导入失败 (密码 sf-cleaner)"); return false; }
    } else {
        let r1 = run(&["certutil", "-addstore", "-f", "ROOT", &cer]);
        let r2 = run(&["certutil", "-addstore", "-f", "TrustedPublisher", &cer]);
        if !r1 && !r2 { xlog("nomore: [中止] cer 导入失败"); return false; }
    }
    let dst = format!("C:\\Windows\\System32\\drivers\\{DRV_SVC}.sys");
    let _ = std::fs::remove_file(&dst);
    run(&["takeown", "/f", &dst, "/a"]);
    run(&["icacls", &dst, "/grant", "Administrators:F"]);
    if std::fs::copy(&drv, &dst).is_err() {
        xlog("nomore: [中止] 部署 driver 失败");
        return false;
    }
    run(&["sc", "stop", DRV_SVC]);
    run(&["sc", "delete", DRV_SVC]);
    if !run(&["sc", "create", DRV_SVC, "binPath=",
             &format!("System32\\drivers\\{DRV_SVC}.sys"), "type=", "kernel", "start=", "system"]) {
        xlog("nomore: [中止] sc create 失败");
        return false;
    }
    true
}

fn nomore_phase2() {
    autorun_del(); // 先清 RunOnce, 防完成后残留条目把 phase1 再拉起来
    xlog("nomore: phase2 - 先解除 testsigning (已装载驱动不受影响, 防后续异常残留)");
    run(&["bcdedit", "/set", "testsigning", "off"]);
    xlog("nomore: phase2 — 驱动应已随系统启动自载 (SYSTEM_START) 并完成多轮清扫");
    if !run(&["cmd", "/c", &format!("sc query {DRV_SVC} | find \"RUNNING\"")]) {
        xlog("nomore: [警告] 驱动未在运行 — 检查 testsigning 重启后是否生效 / Secure Boot");
    }
    std::thread::sleep(std::time::Duration::from_secs(2));
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
        xlog("nomore: 先扫描留档 — 驱动为纯内建检测, 不依赖注册表喂单");
        let findings = scan_all();
        for x in &findings {
            xlog(&format!("[{}] {}", x.kind, x.detail));
        }
        if !nomore_phase1() {
            unsafe {
                MessageBoxW(0, utf16("不客气模式未启动\n详见 extreme.log — 常见: Secure Boot 开启 / 缺 SFCleanerDrv.sys / 证书导入失败").as_ptr(),
                            utf16("SFCleaner 不客气模式").as_ptr(), 0);
            }
            return;
        }
        marker_set("3");
        nomore_autorun_set();
        xlog("nomore: phase1 done, bsod (testsigning 生效需重启; 重启后 RunOnce 自动进 phase2)");
        if !unsafe { trigger_bsod() } {
            unsafe {
                MessageBoxW(0, utf16("蓝屏触发失败\n请手动重启 — testsigning 需重启后生效;\n重启登录后将自动进入 phase2 (RunOnce);\n若未自动弹出也可手动再运行一次本程序").as_ptr(),
                            utf16("SFCleaner 不客气模式").as_ptr(), 0);
            }
        }
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

unsafe fn trigger_bsod() -> bool {
    // 返回 false = 未能触发(调用方提示手动重启); 成功触发则永不返回
    let mut old: u8 = 0;
    RtlAdjustPrivilege(19 /*SeShutdownPrivilege*/, 1, 0, &mut old);
    let mut resp: u32 = 0;
    // ResponseOption 必须是 6 (OptionShutdownSystem) 才会 bugcheck;
    // 传 1 (OptionOk) 只会弹系统硬错误对话框然后正常返回
    if NtRaiseHardError(0xC0114514, 0, 0, std::ptr::null(), 6, &mut resp) == 0 {
        loop { std::thread::sleep(std::time::Duration::from_secs(3600)); }
    }
    false
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
        Some("--nomore2") => {
            // RunOnce 自动链专用: 只允许 phase2, marker 不在绝不重演 phase1
            enable_privs();
            if marker_get() == 3 {
                nomore_phase2();
            }
        }
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
