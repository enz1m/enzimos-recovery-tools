// SPDX-License-Identifier: MIT
use crate::accounts;
use enzimos_platform::{Error, Result, json, require};
use serde_json::{Value, json as value};
use std::{
    io::{Read, Write},
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};
static CANCELLED: AtomicBool = AtomicBool::new(false);
extern "C" fn cancelled(_: libc::c_int) {
    CANCELLED.store(true, Ordering::SeqCst);
}
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (getppid, prctl, setrlimit, sigaction and others)."
)]
pub fn install_lifetime_guard() -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    require(
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } == 0
            && unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0,
        "private authentication memory unavailable",
    )?;
    let parent = unsafe { libc::getppid() };
    require(parent != 1, "recovery interface closed")?;
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = cancelled as *const () as usize;
    unsafe { libc::sigemptyset(&mut action.sa_mask) };
    for signal in [libc::SIGTERM, libc::SIGINT] {
        require(
            unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } == 0,
            "cancellation handler unavailable",
        )?;
    }
    require(
        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) } == 0
            && unsafe { libc::getppid() } == parent,
        "recovery interface closed",
    )
}
fn alive() -> Result<()> {
    require(
        !CANCELLED.load(Ordering::SeqCst),
        "recovery operation cancelled",
    )
}
pub fn read_line<R: Read>(mut reader: R, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    require(limit <= 65536, "authentication request bound")?;
    let mut out = Zeroizing::new(Vec::with_capacity(limit));
    let mut b = Zeroizing::new([0u8; 1]);
    loop {
        alive()?;
        match reader.read(&mut *b) {
            Ok(0) => return Err(Error("recovery input closed".into())),
            Ok(_) => {
                if b[0] == b'\n' {
                    return Ok(out);
                }
                require(out.len() < limit, "recovery request too large")?;
                out.push(b[0]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
}
pub fn validate_request(v: &Value, admins: &Value) -> Result<(String, Zeroizing<String>, Value)> {
    json::fields(v, "user password request")?;
    let user = v["user"]
        .as_str()
        .ok_or_else(|| Error("choose an administrator".into()))?;
    require(
        accounts::valid_name(user)
            && admins
                .as_array()
                .is_some_and(|a| a.iter().any(|a| a["name"] == user)),
        "choose an administrator",
    )?;
    let password = v["password"]
        .as_str()
        .ok_or_else(|| Error("enter the account password".into()))?;
    require(
        !password.is_empty() && password.len() <= 4096 && !password.contains(['\n', '\r', '\0']),
        "enter the account password",
    )?;
    require(v["request"].is_object(), "invalid recovery request")?;
    let mut request = v["request"].clone();
    require(
        request["action"].as_str().is_some_and(|s| !s.is_empty()),
        "recovery action required",
    )?;
    request["_stream"] = value!(true);
    Ok((user.into(), Zeroizing::new(password.into()), request))
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
fn nonblocking(fd: i32) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    require(
        flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0,
        "authentication pipe unavailable",
    )
}
struct OwnedChild(Child, bool);
impl Drop for OwnedChild {
    #[allow(unsafe_code, reason = "Linux syscall ABI (kill).")]
    fn drop(&mut self) {
        if !self.1 {
            return;
        }
        unsafe { libc::kill(-(self.0.id() as i32), libc::SIGKILL) };
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[allow(unsafe_code, reason = "Linux syscall ABI (waitid).")]
fn exited(child: &Child) -> Result<bool> {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let r = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id(),
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if r < 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() == std::io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(e.into());
    }
    Ok(unsafe { info.si_pid() } != 0)
}
struct PrivateRequest(Value);
impl std::ops::Deref for PrivateRequest {
    type Target = Value;
    fn deref(&self) -> &Value {
        &self.0
    }
}
impl std::ops::DerefMut for PrivateRequest {
    fn deref_mut(&mut self) -> &mut Value {
        &mut self.0
    }
}
impl Drop for PrivateRequest {
    fn drop(&mut self) {
        fn clear(value: &mut Value) {
            match value {
                Value::String(s) => s.zeroize(),
                Value::Array(a) => {
                    for value in a {
                        clear(value);
                    }
                }
                Value::Object(o) => {
                    for value in o.values_mut() {
                        clear(value);
                    }
                }
                _ => (),
            }
        }
        clear(&mut self.0);
    }
}
#[allow(unsafe_code, reason = "Fork-child setup must run before exec.")]
pub fn run(v: Value) -> Result<i32> {
    let mut v = PrivateRequest(v);
    let admins = accounts::administrators()?;
    if v["action"] == "accounts" {
        json::fields(&v, "action")?;
        println!("{}", value!({"accounts":admins}));
        return Ok(0);
    }
    let (user, mut password, request) = validate_request(&v, &admins)?;
    // Clear owned secret storage before subprocess processing.
    if let Some(s) = v.get_mut("password") {
        if let Value::String(s) = s {
            s.zeroize();
        }
    }
    drop(v);
    let mut command = Command::new("/usr/bin/su");
    command.args(["--shell","/bin/sh",&user,"-c","exec /usr/bin/sudo -k -S -p ENZIMOS_ADMIN_AUTH: -- /usr/lib/enzimos-recovery/enzimos-recovery-helper --stdin"])
 .env_clear().env("PATH","/usr/bin").env("LANG","C").env("LC_ALL","C").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            let parent = libc::getppid();
            if libc::setsid() < 0
                || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0
                || libc::getppid() != parent
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = OwnedChild(command.spawn()?, true);
    let mut input = Some(
        child
            .0
            .stdin
            .take()
            .ok_or_else(|| Error("authentication input unavailable".into()))?,
    );
    let mut out = child.0.stdout.take().unwrap();
    let mut err = child.0.stderr.take().unwrap();
    for fd in [
        input.as_ref().unwrap().as_raw_fd(),
        out.as_raw_fd(),
        err.as_raw_fd(),
    ] {
        nonblocking(fd)?;
    }
    let mut out_open = true;
    let mut err_open = true;
    let browse = request["action"] == "browse_session";
    let mut input_open = true;
    let mut stdin_open = browse;
    let mut queue = Zeroizing::new(Vec::<u8>::with_capacity(128 * 1024));
    let mut offset = 0;
    let mut prompts = Vec::new();
    let mut sent = [false; 2];
    let mut lines = Vec::new();
    let mut requests = Vec::new();
    let mut ready = false;
    let mut request_sent = false;
    let mut output = false;
    let deadline = Instant::now() + Duration::from_secs(30);
    while out_open || err_open {
        alive()?;
        require(
            ready || Instant::now() < deadline,
            "administrator authentication timed out",
        )?;
        let mut poll = [
            libc::pollfd {
                fd: if out_open { out.as_raw_fd() } else { -1 },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if err_open { err.as_raw_fd() } else { -1 },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if input_open && offset < queue.len() {
                    input.as_ref().unwrap().as_raw_fd()
                } else {
                    -1
                },
                events: libc::POLLOUT,
                revents: 0,
            },
            libc::pollfd {
                fd: if ready && request_sent && stdin_open {
                    0
                } else {
                    -1
                },
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let n = unsafe { libc::poll(poll.as_mut_ptr(), poll.len() as libc::nfds_t, 200) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e.into());
        }
        if poll[2].revents != 0 {
            match input.as_mut().unwrap().write(&queue[offset..]) {
                Ok(0) => return Err(Error("authentication input closed".into())),
                Ok(n) => offset += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
            if offset == queue.len() {
                queue.zeroize();
                queue.clear();
                offset = 0;
                if request_sent && (!browse || !stdin_open) {
                    input_open = false;
                    input.take();
                }
            }
        }
        for index in 0..2 {
            if poll[index].revents == 0 {
                continue;
            }
            let mut buffer = [0u8; 8192];
            let stream: &mut dyn Read = if index == 0 { &mut out } else { &mut err };
            let n = match stream.read(&mut buffer) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e.into()),
            };
            if n == 0 {
                if index == 0 {
                    out_open = false;
                } else {
                    err_open = false;
                }
                continue;
            }
            if index == 0 {
                lines.extend_from_slice(&buffer[..n]);
                require(
                    lines.len() <= 32 * 1024 * 1024 + 1,
                    "recovery output line bound",
                )?;
                while let Some(end) = lines.iter().position(|b| *b == b'\n') {
                    let line = lines.drain(..=end).collect::<Vec<_>>();
                    let message = json::decode(&line, 32 * 1024 * 1024)?;
                    if !ready {
                        require(
                            message["ready"] == true,
                            "recovery authentication handoff failed",
                        )?;
                        ready = true;
                        password.zeroize();
                        queue.extend_from_slice(&json::canonical(&request)?);
                        queue.push(b'\n');
                        request_sent = true;
                    } else {
                        output = true;
                    }
                    let mut stdout = std::io::stdout().lock();
                    stdout.write_all(&line)?;
                    stdout.flush()?;
                }
            } else {
                prompts.extend_from_slice(&buffer[..n]);
                require(prompts.len() <= 8192, "authentication prompt bound")?;
                for (i, marker) in [b"Password:".as_slice(), b"ENZIMOS_ADMIN_AUTH:".as_slice()]
                    .iter()
                    .enumerate()
                {
                    let count = prompts
                        .windows(marker.len())
                        .filter(|s| *s == *marker)
                        .count();
                    require(
                        count <= 1,
                        "authentication failed; check administrator password",
                    )?;
                    if count == 1 && !sent[i] {
                        require(!ready, "unexpected authentication prompt")?;
                        queue.extend_from_slice(password.as_bytes());
                        queue.push(b'\n');
                        sent[i] = true;
                    }
                }
            }
        }
        if poll[3].revents != 0 {
            let mut buffer = [0; 4096];
            let n = unsafe { libc::read(0, buffer.as_mut_ptr().cast(), buffer.len()) };
            if n < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            if n == 0 {
                stdin_open = false;
            } else {
                requests.extend_from_slice(&buffer[..n as usize]);
                require(requests.len() <= 65536, "browsing request bound")?;
                while let Some(end) = requests.iter().position(|b| *b == b'\n') {
                    let line = requests.drain(..=end).collect::<Vec<_>>();
                    let q = json::decode(&line, 65536)?;
                    require(
                        matches!(
                            q["action"].as_str(),
                            Some("files_list" | "files_destination" | "files_drives")
                        ),
                        "browsing connection is read-only",
                    )?;
                    require(
                        queue.len() + line.len() <= 128 * 1024,
                        "browsing input queue bound",
                    )?;
                    queue.extend_from_slice(&line);
                }
            }
        }
        if request_sent && input_open && !stdin_open && offset == queue.len() {
            input_open = false;
            input.take();
        }
        if exited(&child.0)? {
            if !out_open && !err_open {
                break;
            }
        }
    }
    require(lines.is_empty(), "truncated recovery response")?;
    require(
        ready && output,
        "authentication failed or recovery service unavailable",
    )?;
    // Keep the leader unreaped until group cleanup, preventing PID reuse races.
    unsafe { libc::kill(-(child.0.id() as i32), libc::SIGTERM) };
    let status = child.0.wait()?;
    child.1 = false;
    let code = status.code().unwrap_or(1);
    Ok(code)
}
