// SPDX-License-Identifier: MIT
//! Explicit system/external file panels, pinned mount bindings and bounded scans.
use crate::{drives, file_paths};
use enzimos_platform::{Error, Result, files, json, mount_identity, mountinfo, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeSet,
    ffi::CString,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    },
    path::{Path, PathBuf},
};
pub struct Endpoint {
    pub spec: Value,
    pub external: Option<drives::Pinned>,
    pub directory: File,
    pub unique: u64,
    pub root_path: PathBuf,
}
impl Endpoint {
    pub fn new(spec: &Value) -> Result<Self> {
        drives::private()?;
        require(spec.is_object(), "choose a file panel")?;
        let external = match spec.get("drive") {
            None | Some(Value::Null) => {
                json::fields(
                    spec,
                    if spec.get("drive").is_some() {
                        "drive"
                    } else {
                        ""
                    },
                )?;
                None
            }
            Some(Value::String(s)) if !s.is_empty() => {
                json::fields(spec, "drive")?;
                Some(drives::Pinned::open(s)?)
            }
            _ => return Err(Error("file panel drive type".into())),
        };
        let directory = if let Some(e) = &external {
            e.directory.try_clone()?
        } else {
            files::directory(Path::new("/"), Some(0))?
        };
        let unique = mount_identity::id(directory.as_fd(), true)?;
        let root_path = external
            .as_ref()
            .map(|d| d.path.clone())
            .unwrap_or_else(|| PathBuf::from("/"));
        Ok(Self {
            spec: spec.clone(),
            external,
            directory,
            unique,
            root_path,
        })
    }
    pub fn parts(&self, path: &str) -> Result<Vec<std::ffi::OsString>> {
        if self.external.is_some() {
            file_paths::destination(path)
        } else {
            Ok(file_paths::source(path)?
                .components()
                .filter_map(|c| {
                    if let std::path::Component::Normal(s) = c {
                        Some(s.to_owned())
                    } else {
                        None
                    }
                })
                .collect())
        }
    }
    pub fn normalize(&self, path: &str) -> Result<PathBuf> {
        if self.external.is_some() {
            Ok(self.parts(path)?.into_iter().collect())
        } else {
            file_paths::source(path)
        }
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
    pub fn open(&self, path: &str, directory: bool) -> Result<File> {
        let parts = self.parts(path)?;
        let mut held = self.directory.try_clone()?;
        for (i, part) in parts.iter().enumerate() {
            let name = CString::new(part.as_bytes())
                .map_err(|_| Error("file panel path encoding".into()))?;
            let flags = libc::O_RDONLY
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | if directory || i + 1 < parts.len() {
                    libc::O_DIRECTORY
                } else {
                    0
                };
            let fd = unsafe { libc::openat(held.as_raw_fd(), name.as_ptr(), flags) };
            require(fd >= 0, "file panel item unavailable")?;
            let child = unsafe { File::from_raw_fd(fd) };
            if self.external.is_some() {
                require(
                    mount_identity::id(child.as_fd(), true)? == self.unique,
                    "folder crosses another mounted filesystem",
                )?;
            }
            held = child;
        }
        Ok(held)
    }
    pub fn check(&self) -> Result<()> {
        if let Some(d) = &self.external {
            d.check()
        } else {
            file_paths::check_mount(&self.root_path, &self.directory, self.unique)?;
            let current = files::directory(&self.root_path, None)?;
            use std::os::unix::fs::MetadataExt;
            let a = current.metadata()?;
            let b = self.directory.metadata()?;
            require(
                (a.dev(), a.ino()) == (b.dev(), b.ino()),
                "file panel root was replaced",
            )
        }
    }
    pub fn binding(&self) -> Value {
        value!({"spec":self.spec,"mount":self.unique})
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fstatat).")]
    pub fn stat(&self, path: &str) -> Result<(libc::stat, u64)> {
        let path = self.normalize(path)?;
        let parent = self.open(
            path.parent()
                .and_then(Path::to_str)
                .unwrap_or(if self.external.is_some() { "" } else { "/" }),
            true,
        )?;
        let name = CString::new(
            path.file_name()
                .ok_or_else(|| Error("selected item name".into()))?
                .as_bytes(),
        )
        .map_err(|_| Error("selected item encoding".into()))?;
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        require(
            unsafe {
                libc::fstatat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    st.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } == 0,
            "selected item unavailable",
        )?;
        Ok((
            unsafe { st.assume_init() },
            mount_identity::id(parent.as_fd(), true)?,
        ))
    }
}
fn stat_identity(st: &libc::stat) -> Result<Value> {
    let ns = |a: i64, b: i64| {
        a.checked_mul(1000000000)
            .and_then(|a| a.checked_add(b))
            .ok_or_else(|| Error("file timestamp bound".into()))
    };
    require(st.st_size >= 0, "file byte count invalid")?;
    Ok(value!([
        st.st_dev,
        st.st_ino,
        st.st_mode,
        st.st_size,
        ns(st.st_mtime, st.st_mtime_nsec)?,
        ns(st.st_ctime, st.st_ctime_nsec)?
    ]))
}
pub fn roots(endpoint: &Endpoint, paths: &Value, allow_bases: bool) -> Result<Vec<PathBuf>> {
    let rows = paths
        .as_array()
        .ok_or_else(|| Error("select files or folders".into()))?;
    require(
        !rows.is_empty() && rows.len() <= 256,
        "selection count bound",
    )?;
    let mut all = BTreeSet::new();
    for p in rows {
        let p = endpoint.normalize(
            p.as_str()
                .ok_or_else(|| Error("selection path type".into()))?,
        )?;
        require(
            !p.file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with(".enzimos-")),
            "recovery records cannot be selected as file operations",
        )?;
        require(
            p != Path::new("")
                && p != Path::new("/")
                && p != Path::new(".")
                && (allow_bases
                    || endpoint.external.is_some()
                    || !file_paths::BASES.iter().any(|b| p == Path::new(b))),
            "system and top-level folders cannot be changed as one item",
        )?;
        all.insert(p);
    }
    Ok(all
        .iter()
        .filter(|p| !all.iter().any(|q| p != &q && p.starts_with(q)))
        .cloned()
        .collect())
}
/// Copy reports and incomplete-copy notes left in a destination folder are the
/// user's files once written; deleting or renaming that folder must not be blocked.
fn copy_note(name: &str) -> bool {
    name.starts_with(".enzimos-copy-report-") || name.starts_with(".enzimos-incomplete-")
}
pub struct Scan {
    pub roots: Vec<PathBuf>,
    pub records: Vec<Value>,
    pub skipped: Vec<Value>,
}
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid, getpid).")]
pub fn scan(endpoint: &Endpoint, paths: &Value, copy: bool) -> Result<Scan> {
    let selected = roots(endpoint, paths, copy)?;
    let pid = unsafe { libc::getpid() };
    let bytes = files::read_kernel_owned(
        Path::new(&format!("/proc/{pid}/mountinfo")),
        2 * 1024 * 1024,
        unsafe { libc::geteuid() },
    )?;
    let body = std::str::from_utf8(&bytes).map_err(|_| Error("mount inventory encoding".into()))?;
    let mounts = mountinfo::parse(body)?
        .into_iter()
        .map(|r| PathBuf::from(r.target))
        .collect::<BTreeSet<_>>();
    let mut result = Scan {
        roots: selected.clone(),
        records: Vec::new(),
        skipped: Vec::new(),
    };
    fn walk(
        e: &Endpoint,
        path: &Path,
        relative: &Path,
        depth: usize,
        copy: bool,
        mounts: &BTreeSet<PathBuf>,
        out: &mut Scan,
    ) -> Result<()> {
        require(
            depth < 64 && out.records.len() + out.skipped.len() < file_paths::LIMIT,
            "selection too large",
        )?;
        let p = path
            .to_str()
            .ok_or_else(|| Error("unsupported source filename".into()))?;
        let r = relative
            .to_str()
            .ok_or_else(|| Error("unsupported source filename".into()))?;
        if e.external.is_none()
            && mounts.contains(path)
            && !file_paths::BASES.iter().any(|b| path == Path::new(b))
        {
            if copy {
                out.skipped.push(value!([p, "mounted filesystem"]));
                return Ok(());
            }
            return Err(Error("selection contains a mounted filesystem".into()));
        }
        let (st, parent_mount) = e.stat(p)?;
        let kind = st.st_mode & libc::S_IFMT;
        require(
            kind == libc::S_IFREG
                || !path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(copy_note),
            "selection includes recovery records",
        )?;
        if kind == libc::S_IFLNK {
            if copy {
                out.skipped.push(value!([p, "symbolic link"]));
            } else {
                out.records.push(value!({"source":p,"relative":r,"kind":"link","identity":stat_identity(&st)?,"mount":parent_mount}));
            }
            return Ok(());
        }
        if !matches!(kind, libc::S_IFREG | libc::S_IFDIR) {
            if copy {
                out.skipped.push(value!([p, "special file"]));
                return Ok(());
            }
            return Err(Error("selection contains a special file".into()));
        }
        let fd = e.open(p, kind == libc::S_IFDIR)?;
        let before = fd.metadata()?;
        let actual = file_paths::identity(&before)?;
        require(
            actual == stat_identity(&st)?,
            "selected item changed during review",
        )?;
        out.records.push(value!({"source":p,"relative":r,"kind":if before.is_dir(){"directory"}else{"file"},"identity":actual,"mount":mount_identity::id(fd.as_fd(),true)?}));
        if before.is_dir() {
            for name in file_paths::names(&fd)? {
                let Some(s) = name.to_str() else {
                    if copy {
                        out.skipped.push(value!([p, "unsupported filename"]));
                        continue;
                    }
                    return Err(Error("selection contains unsupported filename".into()));
                };
                if s == ".snapshots" || (s.starts_with(".enzimos-") && (copy || !copy_note(s))) {
                    if copy {
                        out.skipped.push(value!([
                            path.join(&name),
                            "snapshot storage or recovery record"
                        ]));
                        continue;
                    }
                    return Err(Error(
                        "selection includes snapshot storage or recovery records".into(),
                    ));
                }
                walk(
                    e,
                    &path.join(&name),
                    &relative.join(&name),
                    depth + 1,
                    copy,
                    mounts,
                    out,
                )?;
            }
            require(
                file_paths::identity(&fd.metadata()?)? == file_paths::identity(&before)?,
                "source folder changed during review",
            )?;
        }
        Ok(())
    }
    for path in selected {
        walk(
            endpoint,
            &path,
            Path::new(path.file_name().unwrap()),
            0,
            copy,
            &mounts,
            &mut result,
        )?;
    }
    endpoint.check()?;
    Ok(result)
}
pub fn verify(endpoint: &Endpoint, records: &[Value]) -> Result<()> {
    require(records.len() <= file_paths::LIMIT, "review record bound")?;
    for r in records {
        json::fields(r, "source relative kind identity mount")?;
        let source = r["source"]
            .as_str()
            .ok_or_else(|| Error("review source path".into()))?;
        let (st, mount) = endpoint.stat(source)?;
        require(
            stat_identity(&st)? == r["identity"],
            "selected item changed after review",
        )?;
        if r["kind"] == "link" {
            require(
                st.st_mode & libc::S_IFMT == libc::S_IFLNK && r["mount"] == mount,
                "selected link changed",
            )?;
        } else {
            let directory = r["kind"] == "directory";
            require(directory || r["kind"] == "file", "review item kind")?;
            let fd = endpoint.open(source, directory)?;
            require(
                file_paths::identity(&fd.metadata()?)? == r["identity"]
                    && r["mount"] == mount_identity::id(fd.as_fd(), true)?,
                "selected item or mount changed",
            )?;
        }
    }
    endpoint.check()
}
