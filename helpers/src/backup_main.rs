// SPDX-License-Identifier: MIT
//! enzimos-recovery-backup: the recovery environment's restore from an
//! encrypted backup on an external drive, an SMB share or a REST server.
//! One JSON request on stdin, JSON lines out. It runs only in the recovery
//! environment; there the repository password is the authorization.
use enzimos_platform::{Error, Result, files, mount_identity, require};
use enzimos_recovery_tools::{backup, drives};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    os::fd::AsFd,
    path::Path,
    process::{Command, Stdio},
};
use zeroize::Zeroizing;

const BASE: &str = "/run/enzimos-recovery-backup";
const RESTIC: &str = "/usr/bin/restic";

fn emit(value: &Value) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{value}");
    let _ = out.flush();
}

fn run(program: &str, args: &[&str], env: &[(&str, &str)]) -> Result<std::process::Output> {
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("LANG", "C");
    for (key, value) in env {
        command.env(key, value);
    }
    let output = command.stdin(Stdio::null()).output()?;
    Ok(output)
}

fn mountpoint(name: &str) -> Result<String> {
    let base = Path::new(BASE);
    let path = base.join(name);
    std::fs::create_dir_all(&path)?;
    let parent = files::directory(base, Some(0))?;
    let directory = files::directory(&path, Some(0))?;
    require(
        mount_identity::id(parent.as_fd(), true)? == mount_identity::id(directory.as_fd(), true)?,
        "a recovery drive is already mounted; leave it connected",
    )?;
    Ok(path.to_string_lossy().into_owned())
}

/// Mount the repository's location (if it is one) and return the restic
/// repository argument; `mounted` records what to unmount.
fn attach(source: &backup::Source, request: &Value, mounted: &mut Vec<String>) -> Result<String> {
    match source {
        backup::Source::Drive { drive, .. } => {
            let d = drives::selected(drive)?;
            let point = mountpoint("source")?;
            let kind = match d["fstype"].as_str().unwrap_or_default() {
                "ntfs" | "ntfs3" => "ntfs-3g",
                other => other,
            };
            let name = d["name"]
                .as_str()
                .ok_or_else(|| Error("drive name unavailable".into()))?;
            let out = run(
                "/usr/bin/mount",
                &[
                    "-t",
                    kind,
                    "-o",
                    "ro,nodev,nosuid,noexec",
                    "--",
                    name,
                    &point,
                ],
                &[],
            )?;
            require(out.status.success(), "the backup drive could not be opened")?;
            mounted.push(point.clone());
            Ok(source.repository(&point))
        }
        backup::Source::Share {
            server,
            share,
            user,
            domain,
            ..
        } => {
            let point = mountpoint("source")?;
            let secret = Zeroizing::new(
                request["share_password"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            );
            let mut options = format!("ro,nodev,nosuid,noexec,username={user}");
            if let Some(domain) = domain {
                options.push_str(",domain=");
                options.push_str(domain);
            }
            let unc = format!("//{server}/{share}");
            // mount.cifs reads the password from PASSWD, never the command line.
            let out = run(
                "/usr/bin/mount",
                &["-t", "cifs", "-o", &options, "--", &unc, &point],
                &[("PASSWD", secret.as_str())],
            )?;
            require(
                out.status.success(),
                "the network share could not be opened; check its address, user and password",
            )?;
            mounted.push(point.clone());
            Ok(source.repository(&point))
        }
        backup::Source::Rest { .. } => Ok(source.repository("")),
    }
}

/// A repository and the secrets restic gets through its environment only.
struct Repository {
    location: String,
    password: Zeroizing<String>,
    /// A REST server's HTTP user and password.
    server: Option<(String, Zeroizing<String>)>,
}

fn restic(repository: &Repository, args: &[&str]) -> Command {
    let mut command = Command::new(RESTIC);
    command
        .arg("--repo")
        .arg(&repository.location)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("HOME", BASE)
        .env("RESTIC_CACHE_DIR", format!("{BASE}/cache"))
        .env("RESTIC_PASSWORD", repository.password.as_str())
        .stdin(Stdio::null());
    if let Some((user, password)) = &repository.server {
        command
            .env("RESTIC_REST_USERNAME", user)
            .env("RESTIC_REST_PASSWORD", password.as_str());
    }
    command
}

fn snapshots(repository: &Repository) -> Result<Value> {
    let out = restic(repository, &["snapshots", "--json", "--no-lock"]).output()?;
    if !out.status.success() {
        let why = String::from_utf8_lossy(&out.stderr);
        return Err(Error(
            if why.contains("wrong password") || why.contains("no key found") {
                "the backup password is not correct".into()
            } else if why.contains("401 Unauthorized") || why.contains("403 Forbidden") {
                "the backup server refused the user and password".into()
            } else if why.contains("does not exist") || why.contains("unable to open config") {
                "there is no backup at this location".into()
            } else {
                "the backup could not be read".into()
            },
        ));
    }
    backup::snapshots(
        &serde_json::from_slice(&out.stdout)
            .map_err(|_| Error("unreadable backup listing".into()))?,
    )
}

fn restore(request: &Value, repository: &Repository, mounted: &mut Vec<String>) -> Result<Value> {
    let id = backup::snapshot_id(request["snapshot"].as_str().unwrap_or_default())?.to_owned();
    let listed = snapshots(repository)?;
    let snapshot = listed
        .as_array()
        .into_iter()
        .flatten()
        .find(|snapshot| snapshot["id"] == id.as_str())
        .ok_or_else(|| Error("that backup snapshot is gone".into()))?;
    let top = restic(repository, &["ls", "--json", "--no-lock", &id, "/"]).output()?;
    require(
        top.status.success(),
        "the backup snapshot could not be read",
    )?;
    let listing =
        std::str::from_utf8(&top.stdout).map_err(|_| Error("unreadable backup contents".into()))?;
    let personal = backup::personal(snapshot, listing)?;
    let target = drives::selected(request["target"].as_str().unwrap_or_default())?;
    let point = mountpoint("target")?;
    let kind = match target["fstype"].as_str().unwrap_or_default() {
        "ntfs" | "ntfs3" => "ntfs-3g",
        other => other,
    };
    let name = target["name"]
        .as_str()
        .ok_or_else(|| Error("drive name unavailable".into()))?;
    let out = run(
        "/usr/bin/mount",
        &["-t", kind, "-o", "nodev,nosuid,noexec", "--", name, &point],
        &[],
    )?;
    require(
        out.status.success(),
        "the destination drive could not be opened",
    )?;
    mounted.push(point.clone());
    let folder = format!("{point}/enzimOS restore {}", &id[..8]);
    require(
        !Path::new(&folder).exists(),
        "this snapshot was already restored to that drive",
    )?;
    std::fs::create_dir(&folder)?;
    // The repository is read-only here (a drive mounted read-only, a share):
    // no lock is taken.
    let mut args = vec![
        "restore".to_owned(),
        id.clone(),
        "--target".into(),
        folder.clone(),
        "--json".into(),
        "--no-lock".into(),
    ];
    if let Some(path) = personal {
        args.extend(["--include".into(), path.into()]);
    }
    let borrowed = args.iter().map(String::as_str).collect::<Vec<_>>();
    let mut child = restic(repository, &borrowed)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error("restore output unavailable".into()))?;
    // Drained apart, so a chatty stderr never blocks the restore.
    let stderr = child.stderr.take().map(|mut e| {
        std::thread::spawn(move || {
            let mut sink = Vec::new();
            let _ = (&mut e).take(65536).read_to_end(&mut sink);
            let _ = std::io::copy(&mut e, &mut std::io::sink());
            sink
        })
    });
    let mut last = -1.0;
    for line in BufReader::new(stdout)
        .lines()
        .map_while(std::result::Result::ok)
    {
        if let Some(done) = backup::progress(&line)
            && done - last >= 0.01
        {
            last = done;
            emit(&json!({"progress": done}));
        }
    }
    let status = child.wait()?;
    let errors = stderr.and_then(|t| t.join().ok()).unwrap_or_default();
    if !status.success() {
        eprintln!(
            "{}",
            String::from_utf8_lossy(&errors)
                .chars()
                .take(2000)
                .collect::<String>()
        );
    }
    require(
        status.success(),
        "the restore did not finish; the files restored so far are on the drive",
    )?;
    let _ = run("/usr/bin/sync", &[], &[]);
    Ok(
        json!({"restored_to": target["label"], "folder": Path::new(&folder).file_name().map(|n| n.to_string_lossy().into_owned())}),
    )
}

#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
fn handle() -> Result<Value> {
    require(
        unsafe { libc::geteuid() } == 0 && Path::new("/etc/enzimos-recovery-env").is_file(),
        "restoring a backup here runs only in the recovery environment",
    )?;
    let mut raw = Zeroizing::new(Vec::new());
    std::io::stdin().take(65537).read_to_end(&mut raw)?;
    require(raw.len() <= 65536, "request too large")?;
    let request: Value =
        serde_json::from_slice(&raw).map_err(|_| Error("invalid request".into()))?;
    if request["action"] == "drives" {
        return drives::query();
    }
    require(
        matches!(request["action"].as_str(), Some("snapshots" | "restore")),
        "unknown backup action",
    )?;
    let source = backup::Source::parse(&request["source"])?;
    let password = Zeroizing::new(
        request["password"]
            .as_str()
            .filter(|p| !p.is_empty() && p.len() <= 1024)
            .ok_or_else(|| Error("the backup password is required".into()))?
            .to_owned(),
    );
    let base = Path::new(BASE);
    let _mount_lock = files::Lock::acquire(Path::new("/run/enzimos-recovery-backup.lock"), 0)?;
    std::fs::create_dir_all(base.join("cache"))?;
    files::directory(base, Some(0))?;
    files::directory(&base.join("cache"), Some(0))?;
    let server = match &source {
        backup::Source::Rest {
            user: Some(user), ..
        } => Some((
            user.clone(),
            Zeroizing::new(
                request["source"]["server_password"]
                    .as_str()
                    .filter(|p| p.len() <= 1024)
                    .unwrap_or_default()
                    .to_owned(),
            ),
        )),
        _ => None,
    };
    let mut mounted = Vec::new();
    let result = (|| {
        let repository = Repository {
            location: attach(&source, &request["source"], &mut mounted)?,
            password,
            server,
        };
        match request["action"].as_str() {
            Some("snapshots") => snapshots(&repository),
            Some("restore") => restore(&request, &repository, &mut mounted),
            _ => Err(Error("unknown backup action".into())),
        }
    })();
    let mut unmounted = true;
    for point in mounted.iter().rev() {
        unmounted &=
            run("/usr/bin/umount", &["--", point], &[]).is_ok_and(|output| output.status.success());
    }
    if !unmounted {
        return Err(Error(
            "a recovery drive could not be unmounted; leave it connected".into(),
        ));
    }
    result
}

fn main() {
    match handle() {
        Ok(result) => emit(&json!({"result": result})),
        Err(error) => {
            emit(&json!({"error": error.to_string()}));
            std::process::exit(1);
        }
    }
}
