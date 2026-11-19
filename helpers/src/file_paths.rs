// SPDX-License-Identifier: MIT
//! Recovery file panels use pinned directories and never follow data symlinks.
use enzimos_platform::{Error, Result, mount_identity, require};
use serde_json::{Value, json};
use std::{
    ffi::{CStr, CString, OsString},
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::{
            ffi::{OsStrExt, OsStringExt},
            fs::MetadataExt,
        },
    },
    path::{Component, Path, PathBuf},
};
pub const BASES: [&str; 8] = [
    "/home", "/etc", "/root", "/var", "/usr", "/opt", "/srv", "/boot",
];
pub const LIMIT: usize = 100000;
pub fn source(value: &str) -> Result<PathBuf> {
    require(
        value.len() < 4096 && !value.contains('\0'),
        "unsupported source filename",
    )?;
    let p = Path::new(value);
    require(
        p.is_absolute()
            && !p.components().any(|c| {
                matches!(
                    c,
                    Component::ParentDir | Component::CurDir | Component::Prefix(_)
                )
            })
            && !p.components().any(|c| c.as_os_str() == ".snapshots"),
        "normal source folder required",
    )?;
    require(
        p == Path::new("/") || BASES.iter().any(|b| p.starts_with(b)),
        "normal system folder required",
    )?;
    Ok(p.components().collect())
}
pub fn destination(value: &str) -> Result<Vec<OsString>> {
    require(
        value.len() < 4096 && !value.contains('\0'),
        "invalid destination folder",
    )?;
    let p = Path::new(value);
    require(!p.is_absolute(), "relative destination required")?;
    p.components()
        .map(|c| match c {
            Component::Normal(n) => Ok(n.to_owned()),
            Component::CurDir => Ok(OsString::new()),
            _ => Err(Error("invalid destination folder".into())),
        })
        .filter(|c| !matches!(c,Ok(s)if s.is_empty()))
        .collect()
}
pub fn component(value: &str) -> Result<&str> {
    require(
        !matches!(value, "" | "." | "..") && !value.contains(['/', '\0']) && value.len() <= 255,
        "normal path component required",
    )?;
    Ok(value)
}
pub fn name(value: &str) -> Result<&str> {
    require(
        !matches!(value, "" | "." | ".." | ".snapshots")
            && !value.contains('/')
            && !value.chars().any(char::is_control)
            && value.len() <= 255
            && !value.starts_with(".enzimos-"),
        "normal unreserved filename required",
    )?;
    Ok(value)
}
fn cstring(name: &std::ffi::OsStr) -> Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| Error("invalid filename".into()))
}
#[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
fn open(parent: &File, part: &std::ffi::OsStr, directory: bool) -> Result<File> {
    let name = cstring(part)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK
                | if directory { libc::O_DIRECTORY } else { 0 },
        )
    };
    require(fd >= 0, "file panel item unavailable")?;
    Ok(unsafe { File::from_raw_fd(fd) })
}
#[allow(unsafe_code, reason = "Linux syscall ABI (open).")]
pub fn open_source(value: &str, directory: bool) -> Result<File> {
    let p = source(value)?;
    let root = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    require(root >= 0, "source root unavailable")?;
    let mut fd = unsafe { File::from_raw_fd(root) };
    let parts = p
        .components()
        .filter_map(|p| {
            if let Component::Normal(s) = p {
                Some(s)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    for (i, part) in parts.iter().enumerate() {
        fd = open(&fd, part, directory || i + 1 < parts.len())?;
    }
    let m = fd.metadata()?;
    require(
        m.is_file() || m.is_dir(),
        "only regular files and folders admitted",
    )?;
    Ok(fd)
}
pub fn open_destination(base: &File, value: &str) -> Result<File> {
    let mount = mount_identity::id(base.as_fd(), true)?;
    let mut held = base.try_clone()?;
    for part in destination(value)? {
        held = open(&held, &part, true)?;
        require(
            mount_identity::id(held.as_fd(), true)? == mount,
            "destination crossed a mount",
        )?;
    }
    Ok(held)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (open).")]
pub fn check_mount(path: &Path, base: &File, unique: u64) -> Result<()> {
    let c =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| Error("mount filename".into()))?;
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    require(fd >= 0, "destination mount unavailable")?;
    let current = unsafe { File::from_raw_fd(fd) };
    require(
        mount_identity::id(current.as_fd(), true)? == unique
            && mount_identity::id(base.as_fd(), true)? == unique,
        "drive disconnected or remounted",
    )
}
pub fn identity(m: &std::fs::Metadata) -> Result<Value> {
    let ns = |secs: i64, fraction: i64| {
        secs.checked_mul(1000000000)
            .and_then(|s| s.checked_add(fraction))
            .ok_or_else(|| Error("file timestamp bound".into()))
    };
    Ok(json!([
        m.dev(),
        m.ino(),
        m.mode(),
        m.len(),
        ns(m.mtime(), m.mtime_nsec())?,
        ns(m.ctime(), m.ctime_nsec())?
    ]))
}
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (__errno_location, close, closedir, fdopendir and others)."
)]
pub fn names(directory: &File) -> Result<Vec<OsString>> {
    // fdopendir owns this duplicate only. No displayed pathname is reopened.
    let copy = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    require(copy >= 0, "directory duplicate unavailable")?;
    let raw = unsafe { libc::fdopendir(copy) };
    if raw.is_null() {
        unsafe { libc::close(copy) };
        return Err(Error("directory inventory unavailable".into()));
    }
    struct Dir(*mut libc::DIR);
    impl Drop for Dir {
        #[allow(unsafe_code, reason = "Linux syscall ABI (closedir).")]
        fn drop(&mut self) {
            unsafe { libc::closedir(self.0) };
        }
    }
    let dir = Dir(raw);
    let mut names = Vec::new();
    loop {
        unsafe { *libc::__errno_location() = 0 };
        let item = unsafe { libc::readdir(dir.0) };
        if item.is_null() {
            require(
                unsafe { *libc::__errno_location() } == 0,
                "directory inventory incomplete",
            )?;
            break;
        }
        let bytes = unsafe { CStr::from_ptr((*item).d_name.as_ptr()) }.to_bytes();
        if matches!(bytes, b"." | b"..") {
            continue;
        }
        require(names.len() < LIMIT, "directory item bound")?;
        names.push(OsString::from_vec(bytes.into()));
    }
    names.sort();
    Ok(names)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatat).")]
pub fn listing(directory: &File, path: &str, page: Option<u64>, local_root: bool) -> Result<Value> {
    require(
        page.is_none_or(|n| n <= LIMIT as u64 / 250),
        "invalid file page",
    )?;
    let mut rows = Vec::new();
    for entry in names(directory)? {
        let Some(text) = entry.to_str() else {
            continue;
        };
        if text == ".snapshots"
            || text.starts_with(".enzimos-copy-report-")
            || (local_root && !BASES.iter().any(|p| p.strip_prefix('/') == Some(text)))
        {
            continue;
        }
        let c = cstring(&entry)?;
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        require(
            unsafe {
                libc::fstatat(
                    directory.as_raw_fd(),
                    c.as_ptr(),
                    st.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } == 0,
            "directory changed during inventory",
        )?;
        let st = unsafe { st.assume_init() };
        let kind = st.st_mode & libc::S_IFMT;
        if !matches!(kind, libc::S_IFREG | libc::S_IFDIR) {
            continue;
        }
        let displayed = text
            .chars()
            .map(|c| if c.is_control() { '�' } else { c })
            .collect::<String>();
        let full = Path::new(path).join(text);
        rows.push(json!({"path":full.to_str().ok_or_else(||Error("file panel encoding".into()))?,"name":displayed,"directory":kind==libc::S_IFDIR,"size":st.st_size}));
    }
    rows.sort_by_key(|r| r["name"].as_str().unwrap().to_lowercase());
    let total = rows.len();
    let more = page.is_some_and(|n| total > (n as usize + 1) * 250);
    let selected = if let Some(page) = page {
        rows.into_iter()
            .skip(page as usize * 250)
            .take(250)
            .collect::<Vec<_>>()
    } else {
        rows
    };
    Ok(json!({"path":path,"entries":selected,"page":page.unwrap_or(0),"more":more,"total":total}))
}
pub fn rename_new(parent: &File, from: &str, to: &str, regular: bool) -> Result<()> {
    require(
        !from.is_empty() && !matches!(from, "." | "..") && !from.contains('/') && from.len() <= 255,
        "copy temporary name",
    )?;
    let from = CString::new(from).map_err(|_| Error("copy temporary name".into()))?;
    let to = CString::new(component(to)?).unwrap();
    if regular {
        require(
            stat_at(parent, &from)?.st_mode & libc::S_IFMT == libc::S_IFREG,
            "regular file fallback required",
        )?;
    }
    move_new(parent, &from, parent, &to, true)?;
    parent.sync_all()?;
    Ok(())
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatat).")]
fn stat_at(dir: &File, name: &CStr) -> Result<libc::stat> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    require(
        unsafe {
            libc::fstatat(
                dir.as_raw_fd(),
                name.as_ptr(),
                st.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0,
        "rename source identity unavailable",
    )?;
    Ok(unsafe { st.assume_init() })
}
/// renameat2(RENAME_NOREPLACE), falling back where the filesystem lacks it
/// (FUSE such as ntfs-3g reports EINVAL).
#[allow(unsafe_code, reason = "Linux syscall ABI (renameat2).")]
pub fn move_new(from_dir: &File, from: &CStr, to_dir: &File, to: &CStr, link: bool) -> Result<()> {
    let rc = unsafe {
        libc::renameat2(
            from_dir.as_raw_fd(),
            from.as_ptr(),
            to_dir.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::EINVAL | libc::EOPNOTSUPP | libc::ENOSYS) => {
            move_new_fallback(from_dir, from, to_dir, to, link)
        }
        _ => Err(Error("no-replace publication failed".into())),
    }
}
/// With `link`, non-directories are published by linkat (which never replaces)
/// and the source name is unlinked only while it still names the moved inode.
/// Directories, and every kind when `link` is false (a private destination),
/// use absence check + renameat: a racing creation of the destination between
/// the two can only be replaced if it is an empty directory or, without `link`,
/// a name inside the caller's private directory. The source move stays atomic.
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (fstatat, linkat, renameat, unlinkat)."
)]
pub fn move_new_fallback(
    from_dir: &File,
    from: &CStr,
    to_dir: &File,
    to: &CStr,
    link: bool,
) -> Result<()> {
    let before = stat_at(from_dir, from)?;
    let same = |st: &libc::stat| (st.st_dev, st.st_ino) == (before.st_dev, before.st_ino);
    if link && before.st_mode & libc::S_IFMT != libc::S_IFDIR {
        require(
            unsafe {
                libc::linkat(
                    from_dir.as_raw_fd(),
                    from.as_ptr(),
                    to_dir.as_raw_fd(),
                    to.as_ptr(),
                    0,
                )
            } == 0,
            "no-replace link publication failed",
        )?;
        to_dir.sync_all()?;
        require(
            same(&stat_at(to_dir, to)?) && same(&stat_at(from_dir, from)?),
            "no-replace link captured another item; both names retained",
        )?;
        require(
            unsafe { libc::unlinkat(from_dir.as_raw_fd(), from.as_ptr(), 0) } == 0,
            "published copy retains temporary link",
        )?;
        return Ok(());
    }
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    let absent = unsafe {
        libc::fstatat(
            to_dir.as_raw_fd(),
            to.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT);
    require(absent, "rename destination already exists")?;
    require(
        unsafe {
            libc::renameat(
                from_dir.as_raw_fd(),
                from.as_ptr(),
                to_dir.as_raw_fd(),
                to.as_ptr(),
            )
        } == 0,
        "no-replace publication failed",
    )?;
    require(
        same(&stat_at(to_dir, to)?),
        "rename captured another item; outcome requires review",
    )
}
