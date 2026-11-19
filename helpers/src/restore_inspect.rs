// SPDX-License-Identifier: MIT
//! Online restore choices refer only to exact recorded publisher-origin roots.
use crate::inventory;
use enzimos_platform::{Error, Result, files, json, require};
use enzimos_policy::{
    birth_runtime::{self, Store},
    catalog, operation,
    recovery_journal::{Journal, Kind},
    subvolume,
};
use serde_json::{Value, json as value};
use std::{os::fd::AsFd, path::Path, time::Duration};
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .ok_or_else(|| Error("Recovery record field is missing.".into()))
}
#[allow(unsafe_code, reason = "Linux syscall ABI (localtime_r).")]
pub fn display_time(seconds: i64) -> Result<String> {
    require(
        (0..=253402300799).contains(&seconds),
        "Snapshot date is out of range.",
    )?;
    let mut tm = std::mem::MaybeUninit::<libc::tm>::uninit();
    require(
        !unsafe { libc::localtime_r(&seconds, tm.as_mut_ptr()) }.is_null(),
        "Snapshot date is unavailable.",
    )?;
    let tm = unsafe { tm.assume_init() };
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let month = months
        .get(usize::try_from(tm.tm_mon).map_err(|_| Error("Snapshot date is invalid.".into()))?)
        .ok_or_else(|| Error("Snapshot date is invalid.".into()))?;
    let offset = tm.tm_gmtoff;
    let timezone = if offset == 0 {
        "UTC".into()
    } else {
        format!(
            "UTC{}{:02}:{:02}",
            if offset < 0 { '-' } else { '+' },
            offset.abs() / 3600,
            offset.abs() % 3600 / 60
        )
    };
    Ok(format!(
        "{:02} {month} {} · {:02}:{:02} {timezone}",
        tm.tm_mday,
        tm.tm_year + 1900,
        tm.tm_hour,
        tm.tm_min
    ))
}
fn created(top: &Path, record: &Value) -> Result<String> {
    let relative = text(&record["root"], "path")?;
    let (file, observed, _) = birth_runtime::observe(
        &top.join(relative),
        relative,
        text(record, "filesystem_uuid")?,
    )?;
    require(observed == record["root"], "Snapshot identity changed.")?;
    display_time(subvolume::creation_time(file.as_fd())?)
}
pub fn inspect() -> Result<Value> {
    let lock = operation::lock()?;
    inspect_locked(&lock)
}
pub fn inspect_locked(_operation: &files::Lock) -> Result<Value> {
    operation::root_only()?;
    let catalog = catalog::Transaction::begin()?;
    let sources = Store::open(false)?;
    let bytes = operation::query(
        "/usr/bin/btrfs",
        &["subvolume", "list", "-a", "-u", "-q", "/"],
        Duration::from_secs(30),
        2 * 1024 * 1024,
        &[0],
    )?;
    let observed = birth_runtime::parse_inventory(
        std::str::from_utf8(&bytes).map_err(|_| Error("Storage inventory encoding.".into()))?,
    )?;
    let mut choices = Vec::new();
    for (generation, record) in catalog.data["generations"].as_object().unwrap() {
        if record["state"] != "ready" {
            continue;
        }
        for (birth, source) in &sources.records {
            if source["phase"] != "ready"
                || record["material"]["root_identity"]["uuid"] != source["root"]["uuid"]
            {
                continue;
            }
            // A matching UUID alone cannot adopt changed path/ID/inventory metadata.
            let root = &record["material"]["root_identity"];
            require(
                ["path", "id", "uuid"]
                    .iter()
                    .all(|k| root[*k] == source["root"][*k])
                    && record["material"]["inventory_sha256"] == source["inventory_sha256"],
                "Restore point origin changed.",
            )?;
            let path = text(&source["source"], "path")?;
            let prefix = format!("{path}/");
            let snapshots = format!("{path}/.snapshots");
            let blocked = observed.keys().any(|p| {
                p.starts_with(&prefix)
                    && p != &snapshots
                    && !p.starts_with(&format!("{snapshots}/"))
            });
            choices.push(value!({"available":!blocked,"reason":if blocked { "This source contains independently managed volumes. Review its storage layout before recovery." } else { "" },"birth":birth,"generation":generation,"ordinal":record["ordinal"],"kernels":["linux","linux-lts"]}));
        }
    }
    let mut top = birth_runtime::top(&sources)?;
    for choice in &mut choices {
        choice["created"] = value!(created(
            top.path(),
            &sources.records[text(choice, "birth")?]
        )?);
    }
    top.close()?;
    choices.sort_by_key(|v| std::cmp::Reverse(v["ordinal"].as_u64().unwrap()));
    let images = Journal::open(Kind::Images, false)?;
    let activations = Journal::open(Kind::Activations, false)?;
    let runs = Journal::open(Kind::Runs, false)?;
    let ready = images
        .records
        .iter()
        .filter(|(_, r)| r["phase"] == "ready")
        .map(|(id, _)| id)
        .collect::<Vec<_>>();
    let hostname = files::read(Path::new("/etc/hostname"), 4096, Some(0), true)?;
    let hostname = std::str::from_utf8(&hostname)
        .map_err(|_| Error("System name encoding.".into()))?
        .trim();
    require(
        !hostname.is_empty() && !hostname.chars().any(char::is_control),
        "Invalid system name.",
    )?;
    let mut result = value!({"choices":choices,"images":ready,"activations":activations.records,"runs":runs.records,"system":hostname});
    result["digest"] = value!(json::fingerprint(&result)?);
    sources.recheck()?;
    catalog.recheck()?;
    images.unchanged()?;
    activations.unchanged()?;
    runs.unchanged()?;
    Ok(result)
}
pub fn details(request: &Value) -> Result<Value> {
    json::fields(request, "action digest birth generation")?;
    let lock = operation::lock()?;
    let state = inspect_locked(&lock)?;
    require(
        state["digest"] == request["digest"],
        "Snapshot choices changed. Refresh the list.",
    )?;
    let choice = state["choices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["birth"] == request["birth"] && c["generation"] == request["generation"])
        .ok_or_else(|| Error("Snapshot is no longer available.".into()))?;
    let sources = Store::open(false)?;
    let record = sources
        .records
        .get(text(choice, "birth")?)
        .ok_or_else(|| Error("Snapshot is no longer recorded.".into()))?;
    let mut top = birth_runtime::top(&sources)?;
    let created = created(top.path(), record)?;
    let root = top.path().join(text(&record["root"], "path")?);
    let (held_root, root_identity, readonly) = birth_runtime::observe(
        &root,
        text(&record["root"], "path")?,
        text(record, "filesystem_uuid")?,
    )?;
    require(
        root_identity == record["root"] && !readonly,
        "Restore point identity changed.",
    )?;
    let before = enzimos_platform::process::run_with_fds(
        "/usr/bin/pacman",
        &[
            "--root",
            "@fd:0",
            "--config",
            "/usr/lib/enzimos-native/recovery-pacman.conf",
            "-Q",
        ],
        &[],
        Duration::from_secs(30),
        2 * 1024 * 1024,
        &[held_root.as_fd()],
    )?;
    require(
        before.status.success(),
        &format!(
            "Snapshot package inventory query refused (exit {:?}): {}",
            before.status.code(),
            String::from_utf8_lossy(&before.stderr)
                .chars()
                .take(512)
                .collect::<String>()
        ),
    )?;
    let before = before.stdout;
    let before = std::str::from_utf8(&before)
        .map_err(|_| Error("Snapshot package inventory encoding.".into()))?
        .trim();
    require(
        json::sha256(before.as_bytes()) == record["inventory_sha256"],
        "Snapshot package inventory changed.",
    )?;
    let now = operation::query(
        "/usr/bin/pacman",
        &[
            "--config",
            "/usr/lib/enzimos-native/recovery-pacman.conf",
            "-Q",
        ],
        Duration::from_secs(30),
        2 * 1024 * 1024,
        &[0],
    )?;
    let mut result = inventory::changes(
        before,
        std::str::from_utf8(&now)
            .map_err(|_| Error("Current package inventory encoding.".into()))?
            .trim(),
    )?;
    sources.recheck()?;
    top.recheck()?;
    require(
        subvolume::observe(held_root.as_fd(), text(&record["root"], "path")?)?
            == (root_identity.clone(), false)
            && birth_runtime::observe(
                &root,
                text(&record["root"], "path")?,
                text(record, "filesystem_uuid")?,
            )?
            .1 == root_identity,
        "Restore point changed while querying packages.",
    )?;
    drop(held_root);
    top.close()?;
    result["created"] = value!(created);
    result["description"] = value!("System restore point · linux, linux-lts");
    Ok(result)
}
