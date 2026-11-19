// SPDX-License-Identifier: MIT
//! Existing external filesystems only. Never format or offer a live system disk.
use enzimos_platform::{Error, Result, files, json, mount_identity, process, require};
use serde_json::{Value, json as value};
use std::{
    os::fd::AsFd,
    path::{Path, PathBuf},
    time::Duration,
};
pub const STATE: &str = "/run/enzimos-recovery-backup";
pub const MEDIA: &str = "/run/enzimos-recovery-media";
pub fn private() -> Result<()> {
    enzimos_policy::operation::root_only()?;
    require(
        std::fs::read_link("/proc/self/ns/mnt")? == std::fs::read_link("/proc/1/ns/mnt")?,
        "initial recovery mount namespace required",
    )?;
    for path in [STATE, MEDIA] {
        files::ensure_directory(Path::new(path), 0o700, 0)?;
    }
    Ok(())
}
fn text<'a>(v: &'a Value, k: &str, max: usize) -> Result<&'a str> {
    let s = v[k]
        .as_str()
        .ok_or_else(|| Error("drive identity field".into()))?;
    require(
        !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control),
        "drive identity bound",
    )?;
    Ok(s)
}
fn flag(v: &Value, k: &str) -> Result<bool> {
    v[k].as_bool()
        .ok_or_else(|| Error("drive flag type".into()))
}
fn optional_text(v: &Value, k: &str, max: usize) -> Result<Value> {
    if v[k].is_null() {
        return Ok(Value::Null);
    }
    let s = v[k]
        .as_str()
        .ok_or_else(|| Error("optional drive field type".into()))?;
    require(
        s.len() <= max && !s.chars().any(char::is_control),
        "optional drive field bound",
    )?;
    Ok(value!(s))
}
fn mountpoints(row: &Value) -> Result<Vec<&str>> {
    if row["mountpoints"].is_null() {
        return Ok(vec![]);
    }
    let rows = row["mountpoints"]
        .as_array()
        .ok_or_else(|| Error("drive mount list".into()))?;
    require(rows.len() <= 64, "drive mount list bound")?;
    let mut result = Vec::new();
    for p in rows {
        if p.is_null() {
            continue;
        }
        let s = p.as_str().ok_or_else(|| Error("drive mount type".into()))?;
        require(
            s.len() < 4096 && !s.contains('\0'),
            "drive mount path bound",
        )?;
        if !s.is_empty() {
            result.push(s);
        }
    }
    Ok(result)
}
fn flatten<'a>(v: &'a Value, depth: usize, rows: &mut Vec<&'a Value>) -> Result<()> {
    require(
        v.is_object() && depth < 32 && rows.len() < 4096,
        "drive inventory bound",
    )?;
    rows.push(v);
    if let Some(c) = v.get("children") {
        let children = c
            .as_array()
            .ok_or_else(|| Error("drive children type".into()))?;
        for child in children {
            flatten(child, depth + 1, rows)?;
        }
    }
    Ok(())
}
pub fn parse(v: &Value) -> Result<Value> {
    json::fields(v, "blockdevices")?;
    let disks = v["blockdevices"]
        .as_array()
        .ok_or_else(|| Error("drive inventory type".into()))?;
    require(disks.len() <= 256, "disk inventory bound")?;
    let mut found = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut count = 0;
    for disk in disks {
        if disk["type"] != "disk" {
            continue;
        }
        let removable = flag(disk, "rm")?;
        if disk["tran"] != "usb" && !removable {
            continue;
        }
        let mut rows = Vec::new();
        flatten(disk, 0, &mut rows)?;
        count += rows.len();
        require(count <= 4096, "drive inventory bound")?;
        let mut system = false;
        for row in &rows {
            if mountpoints(row)?.iter().any(|m| {
                *m == "/"
                    || ["/home", "/boot", "/etc", "/var"]
                        .iter()
                        .any(|b| m.starts_with(b))
            }) {
                system = true;
            }
        }
        if system {
            continue;
        }
        for row in rows {
            if !matches!(row["type"].as_str(), Some("disk" | "part"))
                || !matches!(
                    row["fstype"].as_str(),
                    Some("ext4" | "exfat" | "vfat" | "ntfs" | "ntfs3")
                )
                || flag(row, "ro")?
                || row["uuid"].is_null()
            {
                continue;
            }
            let name = text(row, "name", 255)?;
            let path = Path::new(name);
            require(
                path.starts_with("/dev")
                    && path.components().all(|c| {
                        matches!(
                            c,
                            std::path::Component::RootDir | std::path::Component::Normal(_)
                        )
                    }),
                "drive device path",
            )?;
            let device = text(row, "maj:min", 32)?;
            let numbers = device.split(':').collect::<Vec<_>>();
            require(
                numbers.len() == 2
                    && numbers.iter().all(|s| {
                        !s.is_empty()
                            && s.bytes().all(|b| b.is_ascii_digit())
                            && s.parse::<u32>().is_ok()
                    }),
                "drive device number",
            )?;
            let uuid = text(row, "uuid", 128)?;
            require(
                uuid.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
                "drive UUID shape",
            )?;
            let size = row["size"]
                .as_u64()
                .filter(|s| *s > 0)
                .ok_or_else(|| Error("drive size type".into()))?;
            let identity = value!({"name":name,"maj:min":device,"uuid":uuid,"fstype":text(row,"fstype",16)?,"size":size,"disk":text(disk,"name",255)?,"serial":optional_text(disk,"serial",256)?,"model":optional_text(disk,"model",256)?});
            let id = json::fingerprint(&identity)?;
            require(seen.insert(id.clone()), "duplicate external drive identity")?;
            let mount = format!("{MEDIA}/{id}");
            let mounts = mountpoints(row)?;
            let mounted = mounts == [mount.as_str()];
            let reason = if mounts.is_empty() || mounted {
                ""
            } else {
                "This volume is already mounted elsewhere."
            };
            let label = if row["label"].is_null() || row["label"] == "" {
                if disk["model"].is_null() || disk["model"] == "" {
                    "External drive"
                } else {
                    text(disk, "model", 256)?
                }
            } else {
                text(row, "label", 256)?
            };
            let mut drive = identity;
            drive["id"] = value!(id);
            drive["label"] = value!(label);
            drive["reason"] = value!(reason);
            drive["mounted"] = value!(mounted);
            found.push(drive);
            require(found.len() <= 256, "external volume bound")?;
        }
    }
    Ok(value!(found))
}
pub fn query() -> Result<Value> {
    let result = process::run(
        "/usr/bin/lsblk",
        &[
            "-J",
            "-b",
            "-p",
            "-o",
            "NAME,TYPE,TRAN,RM,FSTYPE,UUID,SIZE,LABEL,MOUNTPOINTS,RO,MAJ:MIN,SERIAL,MODEL",
        ],
        &[],
        Duration::from_secs(30),
        2 * 1024 * 1024,
    )?;
    require(result.status.success(), "drive inventory unavailable")?;
    parse(&json::decode(&result.stdout, 2 * 1024 * 1024)?)
}
pub fn selected(id: &str) -> Result<Value> {
    require(
        id.len() == 64
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid external drive selection",
    )?;
    let rows = query()?;
    let selected = rows
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["id"] == id)
        .collect::<Vec<_>>();
    require(
        selected.len() == 1,
        "external drive changed or disconnected",
    )?;
    require(
        selected[0]["reason"] == "",
        "external volume already mounted elsewhere",
    )?;
    Ok(selected[0].clone())
}
pub struct Pinned {
    pub drive: Value,
    pub path: PathBuf,
    pub directory: std::fs::File,
    pub unique: u64,
}
impl Pinned {
    pub fn open(id: &str) -> Result<Self> {
        Self::open_mode(id, true)
    }
    pub fn existing(id: &str) -> Result<Self> {
        Self::open_mode(id, false)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
    fn open_mode(id: &str, allow_mount: bool) -> Result<Self> {
        private()?;
        let account = crate::accounts::authenticated_account()?;
        let d = selected(id)?;
        let path = Path::new(MEDIA).join(id);
        if d["mounted"] != true {
            require(allow_mount, "external volume is not mounted by recovery")?;
            let mount = files::ensure_directory(&path, 0o700, 0)?;
            require(
                crate::file_paths::names(&mount)?.is_empty(),
                "recovery mount folder is not empty",
            )?;
            let uid = account.uid;
            let gid = account.gid;
            require(
                (1000..u32::MAX).contains(&uid),
                "ordinary administrator required",
            )?;
            let fstype = text(&d, "fstype", 16)?;
            let mut options = "nodev,nosuid,noexec".to_owned();
            if matches!(fstype, "exfat" | "vfat" | "ntfs" | "ntfs3") {
                options.push_str(&format!(",uid={uid},gid={gid},umask=077"));
            }
            let kind = if matches!(fstype, "ntfs" | "ntfs3") {
                "ntfs-3g"
            } else {
                fstype
            };
            let result = process::run(
                "/usr/bin/mount",
                &[
                    "-t",
                    kind,
                    "-o",
                    &options,
                    "--",
                    text(&d, "name", 255)?,
                    path.to_str().unwrap(),
                ],
                &[],
                Duration::from_secs(30),
                65536,
            )?;
            require(result.status.success(), "external volume mount failed")?;
        }
        let fresh = selected(id)?;
        require(
            fresh["mounted"] == true,
            "external volume mount unconfirmed",
        )?;
        // Mounted exFAT/NTFS can expose user ownership at the root. The Root-owned
        // ancestors were validated before mount; destination identity is unique.
        let parent = files::directory(Path::new(MEDIA), Some(0))?;
        let name = std::ffi::CString::new(id).unwrap();
        let raw = unsafe {
            libc::openat(
                std::os::fd::AsRawFd::as_raw_fd(&parent),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        require(raw >= 0, "external volume unavailable")?;
        let directory = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(raw) };
        let unique = mount_identity::id(directory.as_fd(), true)?;
        let pinned = Self {
            drive: fresh,
            path,
            directory,
            unique,
        };
        pinned.check()?;
        Ok(pinned)
    }
    pub fn check(&self) -> Result<()> {
        crate::file_paths::check_mount(&self.path, &self.directory, self.unique)?;
        let fresh = selected(self.drive["id"].as_str().unwrap())?;
        require(
            fresh["mounted"] == true
                && fresh["name"] == self.drive["name"]
                && fresh["uuid"] == self.drive["uuid"],
            "external drive identity changed",
        )
    }
    pub fn eject(self) -> Result<Value> {
        self.check()?;
        drop(self.directory);
        let result = process::run(
            "/usr/bin/umount",
            &["--", self.path.to_str().unwrap()],
            &[],
            Duration::from_secs(30),
            65536,
        )?;
        require(result.status.success(), "external volume is still in use")?;
        Ok(value!({"ejected":true}))
    }
}
