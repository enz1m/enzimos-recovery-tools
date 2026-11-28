// SPDX-License-Identifier: MIT
//! Existing external filesystems only. Never format or offer a live system disk.
use enzimos_platform::{Error, Result, files, json, mount_identity, process, require};
use serde_json::{Value, json as value};
use std::{
    fs::{File, OpenOptions},
    os::{fd::AsFd, unix::fs::OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
pub const STATE: &str = "/run/enzimos-recovery-backup";
pub const MEDIA: &str = "/run/enzimos-recovery-media";
const SOURCES: &str = "/run/enzimos-recovery-backup/block-sources";
pub fn private() -> Result<()> {
    enzimos_policy::operation::root_only()?;
    require(
        std::fs::read_link("/proc/self/ns/mnt")? == std::fs::read_link("/proc/1/ns/mnt")?,
        "initial recovery mount namespace required",
    )?;
    for path in [STATE, MEDIA, SOURCES] {
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
fn reserved_partition(row: &Value) -> bool {
    row["parttype"].as_str().is_some_and(|kind| {
        [
            "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
            "21686148-6449-6e6f-744e-656564454649",
            "e3c9e316-0b5c-4db8-817d-f92df00215ae",
            "de94bba4-06d1-4d40-a16a-bfd50179d6ac",
            "0xef",
            "0x27",
        ]
        .iter()
        .any(|reserved| reserved.eq_ignore_ascii_case(kind))
    })
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
                    || [
                        "/home",
                        "/boot",
                        "/etc",
                        "/var",
                        "/run/enzimos-live/",
                        "/run/archiso/",
                    ]
                    .iter()
                    .any(|b| m.starts_with(b))
            }) {
                system = true;
            }
        }
        if system {
            continue;
        }
        let Some(sequence) = disk["disk-seq"].as_u64().filter(|sequence| *sequence > 0) else {
            continue;
        };
        for row in rows {
            if reserved_partition(row)
                || row.get("children").is_some()
                || !matches!(row["type"].as_str(), Some("disk" | "part"))
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
            let identity = value!({"name":name,"maj:min":device,"disk_sequence":sequence,"uuid":uuid,"fstype":text(row,"fstype",16)?,"size":size,"disk":text(disk,"name",255)?,"serial":optional_text(disk,"serial",256)?,"model":optional_text(disk,"model",256)?});
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
            "NAME,TYPE,TRAN,RM,FSTYPE,UUID,SIZE,LABEL,MOUNTPOINTS,RO,MAJ:MIN,SERIAL,MODEL,DISK-SEQ,PARTTYPE",
        ],
        &[],
        Duration::from_secs(30),
        2 * 1024 * 1024,
    )?;
    require(result.status.success(), "drive inventory unavailable")?;
    let mut drives = parse(&json::decode(&result.stdout, 2 * 1024 * 1024)?)?;
    for drive in drives.as_array_mut().unwrap() {
        let id = drive["id"].as_str().unwrap();
        let alias = Path::new(SOURCES).join(id);
        if drive["mounted"] != true && drive["reason"] == "" && alias.exists() {
            let path = Path::new(MEDIA).join(id);
            let result = process::run(
                "/usr/bin/findmnt",
                &[
                    "--noheadings",
                    "--raw",
                    "--output",
                    "SOURCE",
                    "--mountpoint",
                    path.to_str().unwrap(),
                ],
                &[],
                Duration::from_secs(10),
                4096,
            )?;
            if result.status.success()
                && result.stdout.strip_suffix(b"\n") == Some(alias.as_os_str().as_encoded_bytes())
            {
                verified_device(&alias, drive)?;
                drive["mounted"] = value!(true);
            }
        }
    }
    Ok(drives)
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
fn device_matches(block: &Value, drive: &Value) -> bool {
    block["major"]
        .as_u64()
        .zip(block["minor"].as_u64())
        .is_some_and(|(major, minor)| drive["maj:min"] == format!("{major}:{minor}"))
        && block["disk_sequence"] == drive["disk_sequence"]
        && block["bytes"] == drive["size"]
        && block["read_only"] == false
}

fn verified_device(path: &Path, drive: &Value) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    require(
        device_matches(&enzimos_policy::block::observe(file.as_fd())?, drive),
        "external drive changed before mounting",
    )?;
    Ok(file)
}

fn unmount(path: &Path) -> Result<()> {
    let result = process::run(
        "/usr/bin/umount",
        &["--", path.to_str().unwrap()],
        &[],
        Duration::from_secs(30),
        65536,
    )?;
    require(result.status.success(), "external volume is still in use")
}

fn mount_source(drive: &Value, alias: &Path) -> Result<()> {
    let file = verified_device(Path::new(text(drive, "name", 255)?), drive)?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(alias)?;
    // NTFS-3G canonicalizes its input. A private bind mount retains the selected device node.
    let result = process::run_with_fds(
        "/usr/bin/mount",
        &[
            "--no-canonicalize",
            "--bind",
            "@fd:0",
            alias.to_str().unwrap(),
        ],
        &[],
        Duration::from_secs(30),
        65536,
        &[file.as_fd()],
    );
    match result {
        Ok(output) if output.status.success() => {
            if let Err(error) = verified_device(alias, drive) {
                release_source(alias)?;
                return Err(error);
            }
            Ok(())
        }
        result => {
            std::fs::remove_file(alias)?;
            result?;
            Err(Error(
                "could not retain the selected external block device".into(),
            ))
        }
    }
}

fn release_source(alias: &Path) -> Result<()> {
    unmount(alias)?;
    std::fs::remove_file(alias)?;
    Ok(())
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
            let alias = Path::new(SOURCES).join(id);
            mount_source(&d, &alias)?;
            let result = process::run(
                "/usr/bin/mount",
                &[
                    "-t",
                    kind,
                    "-o",
                    &options,
                    "--",
                    alias.to_str().unwrap(),
                    path.to_str().unwrap(),
                ],
                &[],
                Duration::from_secs(30),
                65536,
            );
            if !result.as_ref().is_ok_and(|output| output.status.success()) {
                release_source(&alias)?;
                result?;
                return Err(Error("external volume mount failed".into()));
            }
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
        unmount(&self.path)?;
        let alias = Path::new(SOURCES).join(self.drive["id"].as_str().unwrap());
        if alias.exists() {
            release_source(&alias)?;
        }
        Ok(value!({"ejected":true}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reused_device_number_cannot_mount_for_the_previous_drive() {
        let drive = value!({"maj:min":"8:33","disk_sequence":9,"size":900000000});
        let mut block =
            value!({"major":8,"minor":33,"disk_sequence":9,"bytes":900000000,"read_only":false});
        assert!(device_matches(&block, &drive));
        block["disk_sequence"] = value!(10);
        assert!(!device_matches(&block, &drive));
    }
}
