// SPDX-License-Identifier: MIT
//! Private, expiring file-operation reviews are consumed durably before mutation.
use enzimos_platform::{Error, Result, files, json, publication, require};
use serde_json::{Value, json as value};
use std::{
    ffi::CString,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
const MAX_PLAN: usize = 32 * 1024 * 1024;
fn token(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn now() -> Result<f64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .map_err(|_| Error("review clock unavailable".into()))
}
pub struct Store {
    path: PathBuf,
    held: std::fs::File,
    writer: u32,
}
impl Store {
    pub fn new(path: &Path, writer: u32) -> Result<Self> {
        let held = files::ensure_directory(path, 0o700, writer)?;
        let store = Self {
            path: path.into(),
            held,
            writer,
        };
        store.guard()?;
        Ok(store)
    }
    fn guard(&self) -> Result<()> {
        let current = files::directory(&self.path, Some(self.writer))?;
        let a = self.held.metadata()?;
        let b = current.metadata()?;
        require(
            (a.dev(), a.ino(), a.uid(), a.mode()) == (b.dev(), b.ino(), b.uid(), b.mode())
                && b.uid() == self.writer
                && b.mode() & 0o777 == 0o700,
            "review store changed",
        )?;
        let mut count = 0;
        for e in std::fs::read_dir(&self.path)? {
            count += 1;
            require(
                count <= 1024,
                "review store full; retain incomplete operations for review",
            )?;
            let name = e?.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| Error("review filename encoding".into()))?;
            if name == "review.lock" {
                continue;
            }
            let known = [".json", ".consumed", ".result.json"]
                .iter()
                .any(|suffix| name.strip_suffix(suffix).is_some_and(token));
            require(known, "interrupted review publication requires inspection")?;
        }
        Ok(())
    }
    /// Under the review lock: drop plans past their 900 s expiry, consumed
    /// markers whose result is published, and results older than an hour.
    /// Without this every file operation left files behind until the store
    /// refused all further operations (and large plans pinned tmpfs memory).
    /// Consumed operations without a result (uncertain) are kept for review.
    fn prune(&self) -> Result<()> {
        let now = std::time::SystemTime::now();
        let age = |m: &std::fs::Metadata| {
            m.modified()
                .ok()
                .and_then(|t| now.duration_since(t).ok())
                .unwrap_or_default()
        };
        let mut removed = false;
        for entry in std::fs::read_dir(&self.path)?.take(4096) {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let m = std::fs::symlink_metadata(entry.path())?;
            if !m.is_file() || m.uid() != self.writer {
                continue;
            }
            let stale = if let Some(stem) = name.strip_suffix(".result.json").filter(|s| token(s)) {
                let _ = stem;
                age(&m) > std::time::Duration::from_secs(3600)
            } else if let Some(stem) = name.strip_suffix(".consumed").filter(|s| token(s)) {
                self.path.join(format!("{stem}.result.json")).exists()
            } else if let Some(stem) = name.strip_suffix(".json").filter(|s| token(s)) {
                let _ = stem;
                age(&m) > std::time::Duration::from_secs(900)
            } else {
                false
            };
            if stale {
                std::fs::remove_file(entry.path())?;
                removed = true;
            }
        }
        if removed {
            self.held.sync_all()?;
        }
        Ok(())
    }
    pub fn save(&self, payload: &Value, uid: u32, gid: u32) -> Result<Value> {
        require(
            (1000..u32::MAX).contains(&uid)
                && payload.is_object()
                && !payload
                    .as_object()
                    .unwrap()
                    .keys()
                    .any(|k| matches!(k.as_str(), "owner" | "gid" | "created" | "digest")),
            "review administrator or payload",
        )?;
        let _lock = files::Lock::acquire(&self.path.join("review.lock"), self.writer)?;
        self.prune()?;
        self.guard()?;
        let mut record = payload.clone();
        record["owner"] = value!(uid);
        record["gid"] = value!(gid);
        record["created"] = value!(now()?);
        let sha = json::fingerprint(&record)?;
        record["digest"] = value!(&sha);
        let name = files::random_hex(16)?;
        let body = json::canonical(&record)?;
        require(body.len() <= MAX_PLAN, "file review byte bound")?;
        // Large scan records are bounded separately from small API requests.
        files::atomic_bounded(
            &self.path.join(format!("{name}.json")),
            &body,
            0o600,
            Some(self.writer),
            false,
            MAX_PLAN,
        )?;
        let roots = record["roots"].as_array();
        Ok(
            value!({"plan":name,"digest":sha,"operation":record["operation"],"items":roots.map_or(0,Vec::len),"names":roots.map(|r|r.iter().map(|p|p.as_str().and_then(|p|Path::new(p).file_name()).and_then(|p|p.to_str()).unwrap_or("")).collect::<Vec<_>>()).unwrap_or_default(),"bytes":record.get("bytes").cloned().unwrap_or(value!(0))}),
        )
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (renameat2).")]
    pub fn consume<F: FnOnce(&Value) -> Result<()>>(
        &self,
        name: &str,
        sha: &str,
        uid: u32,
        verify: F,
    ) -> Result<Value> {
        require(
            token(name) && digest(sha) && (1000..u32::MAX).contains(&uid),
            "invalid file operation review",
        )?;
        let _lock = files::Lock::acquire(&self.path.join("review.lock"), self.writer)?;
        self.guard()?;
        let path = self.path.join(format!("{name}.json"));
        let before = std::fs::symlink_metadata(&path)?;
        require(
            before.uid() == self.writer && before.mode() & 0o077 == 0 && before.nlink() == 1,
            "unsafe private review",
        )?;
        let body = files::read(&path, MAX_PLAN, Some(self.writer), true)?;
        let record = json::decode(&body, MAX_PLAN)?;
        require(
            record.is_object()
                && record["owner"].as_u64() == Some(uid as u64)
                && record["digest"] == sha,
            "file review belongs to another administrator",
        )?;
        let created = record["created"]
            .as_f64()
            .filter(|n| n.is_finite() && *n >= 0.0)
            .ok_or_else(|| Error("review creation time".into()))?;
        let age = now()? - created;
        require(
            (0.0..900.0).contains(&age),
            "file review expired or clock changed",
        )?;
        let mut payload = record.clone();
        payload.as_object_mut().unwrap().remove("digest");
        require(
            json::fingerprint(&payload)? == sha,
            "file review digest changed",
        )?;
        verify(&record)?;
        require(
            (0.0..900.0).contains(&(now()? - created)),
            "file review expired during preflight",
        )?;
        self.guard()?;
        let after = std::fs::symlink_metadata(&path)?;
        require(
            (
                before.dev(),
                before.ino(),
                before.len(),
                before.mtime(),
                before.mtime_nsec(),
                before.ctime(),
                before.ctime_nsec(),
            ) == (
                after.dev(),
                after.ino(),
                after.len(),
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec(),
            ),
            "file review changed during preflight",
        )?;
        let from = CString::new(format!("{name}.json")).unwrap();
        let to = CString::new(format!("{name}.consumed")).unwrap();
        require(
            unsafe {
                libc::renameat2(
                    self.held.as_raw_fd(),
                    from.as_ptr(),
                    self.held.as_raw_fd(),
                    to.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } == 0,
            "file review already consumed or outcome uncertain",
        )?;
        self.held.sync_all()?;
        Ok(record)
    }
    pub fn complete(&self, name: &str, result: &Value) -> Result<()> {
        require(token(name) && result.is_object(), "file operation result")?;
        let _lock = files::Lock::acquire(&self.path.join("review.lock"), self.writer)?;
        self.guard()?;
        require(
            files::read_optional(
                &self.path.join(format!("{name}.consumed")),
                MAX_PLAN,
                Some(self.writer),
                true,
            )?
            .is_some(),
            "unconsumed file review",
        )?;
        let body = json::canonical(result)?;
        require(
            files::read_optional(
                &self.path.join(format!("{name}.result.json")),
                2 * 1024 * 1024,
                Some(self.writer),
                true,
            )?
            .is_none(),
            "file operation result already completed",
        )?;
        publication::Prepared::write(
            &self.path.join(format!("{name}.result.json")),
            &body,
            self.writer,
        )?
        .commit(false)
    }
}
