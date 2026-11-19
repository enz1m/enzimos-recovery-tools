// SPDX-License-Identifier: MIT
use crate::{
    accounts, drives,
    endpoints::{self, Endpoint},
    file_paths, quarantine, rescue_copy, reviews,
};
use enzimos_platform::{Error, Result, json, require};
use serde_json::{Value, json as value};
use std::{os::unix::fs::MetadataExt, path::Path};
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .ok_or_else(|| Error("file operation review field".into()))
}
pub(crate) fn binding(v: &Value) -> Result<Endpoint> {
    json::fields(v, "spec mount")?;
    let e = Endpoint::new(&v["spec"])?;
    require(
        v["mount"].as_u64() == Some(e.unique),
        "file panel was remounted; select again",
    )?;
    Ok(e)
}
pub fn apply<F: FnMut(Value) -> Result<()>>(request: &Value, mut emit: F) -> Result<Value> {
    drives::private()?;
    let user = accounts::authenticated_account()?;
    let _operation = enzimos_policy::operation::lock()?;
    let name = text(request, "plan")?;
    let sha = text(request, "digest")?;
    let store = reviews::Store::new(Path::new(drives::STATE), 0)?;
    let mut source = None;
    let mut destination = None;
    let record = store.consume(name, sha, user.uid, |record| {
        let operation = text(record, "operation")?;
        let extra = match operation {
            "mkdir" => "parent parent_identity name",
            "rename" => "roots records skipped name",
            "delete" => "roots records skipped",
            "copy" => "roots records skipped destination parent parent_identity bytes",
            _ => return Err(Error("unknown reviewed file operation".into())),
        };
        json::fields(
            record,
            &format!("operation source owner gid created digest {extra}"),
        )?;
        require(
            record["gid"].as_u64() == Some(user.gid as u64),
            "administrator account group changed",
        )?;
        let e = binding(&record["source"])?;
        if operation == "mkdir" {
            let parent = e.open(text(record, "parent")?, true)?;
            let m = parent.metadata()?;
            require(
                record["parent_identity"] == value!([m.dev(), m.ino()]),
                "parent folder changed",
            )?;
            crate::manager_plan::absent(
                &parent,
                std::ffi::OsStr::new(file_paths::name(text(record, "name")?)?),
            )?;
        } else {
            let records = record["records"]
                .as_array()
                .ok_or_else(|| Error("reviewed file record list".into()))?;
            endpoints::verify(&e, records)?;
            if operation == "rename" {
                require(
                    record["roots"].as_array().is_some_and(|r| r.len() == 1),
                    "rename review requires one item",
                )?;
                file_paths::name(text(record, "name")?)?;
            }
        }
        if operation == "copy" {
            let d = binding(&record["destination"])?;
            let parent = d.open(text(record, "parent")?, true)?;
            let m = parent.metadata()?;
            require(
                record["parent_identity"] == value!([m.dev(), m.ino()]),
                "copy destination folder changed",
            )?;
            crate::manager_plan::free(
                &parent,
                record["bytes"]
                    .as_u64()
                    .ok_or_else(|| Error("copy reviewed bytes".into()))?,
                record["records"].as_array().map_or(0, Vec::len) as u64,
            )?;
            for root in record["roots"]
                .as_array()
                .ok_or_else(|| Error("copy reviewed roots".into()))?
            {
                let path = Path::new(
                    root.as_str()
                        .ok_or_else(|| Error("copy root path".into()))?,
                );
                crate::manager_plan::absent(
                    &parent,
                    path.file_name()
                        .ok_or_else(|| Error("copy root name".into()))?,
                )?;
            }
            d.check()?;
            destination = Some(d);
        }
        require(
            accounts::authenticated_account()? == user,
            "administrator identity changed",
        )?;
        e.check()?;
        source = Some(e);
        Ok(())
    })?;
    let source = source.ok_or_else(|| Error("reviewed source unavailable".into()))?;
    let operation = text(&record, "operation")?;
    let result = match operation {
        "copy" => rescue_copy::execute(
            &source,
            &destination.ok_or_else(|| Error("reviewed destination unavailable".into()))?,
            &record,
            name,
            &mut emit,
        )?,
        "mkdir" => {
            source.check()?;
            let parent = source.open(text(&record, "parent")?, true)?;
            let m = parent.metadata()?;
            require(
                record["parent_identity"] == value!([m.dev(), m.ino()]),
                "parent folder changed after consumption",
            )?;
            rescue_copy::mkdir(
                &parent,
                file_paths::name(text(&record, "name")?)?,
                user.uid,
                user.gid,
            )?;
            completed(&record)
        }
        "rename" => {
            source.check()?;
            let old = record["roots"][0]
                .as_str()
                .ok_or_else(|| Error("rename root path".into()))?;
            let path = source.normalize(old)?;
            let parent = source.open(
                path.parent()
                    .and_then(Path::to_str)
                    .unwrap_or(if source.external.is_some() { "" } else { "/" }),
                true,
            )?;
            endpoints::verify(&source, record["records"].as_array().unwrap())?;
            let new = file_paths::name(text(&record, "name")?)?;
            let (st, _) = source.stat(old)?;
            let regular = st.st_mode & libc::S_IFMT == libc::S_IFREG;
            file_paths::rename_new(
                &parent,
                path.file_name()
                    .unwrap()
                    .to_str()
                    .ok_or_else(|| Error("rename filename encoding".into()))?,
                new,
                regular,
            )?;
            let renamed = path.parent().unwrap().join(new);
            let (after, _) = source.stat(
                renamed
                    .to_str()
                    .ok_or_else(|| Error("rename path encoding".into()))?,
            )?;
            require(
                (
                    st.st_dev,
                    st.st_ino,
                    st.st_mode,
                    st.st_size,
                    st.st_mtime,
                    st.st_mtime_nsec,
                ) == (
                    after.st_dev,
                    after.st_ino,
                    after.st_mode,
                    after.st_size,
                    after.st_mtime,
                    after.st_mtime_nsec,
                ),
                "rename captured another item; outcome requires review",
            )?;
            completed(&record)
        }
        "delete" => {
            for (index, r) in record["records"]
                .as_array()
                .unwrap()
                .iter()
                .rev()
                .enumerate()
            {
                source.check()?;
                let p = source.normalize(text(r, "source")?)?;
                let parent = source.open(
                    p.parent()
                        .and_then(Path::to_str)
                        .unwrap_or(if source.external.is_some() { "" } else { "/" }),
                    true,
                )?;
                quarantine::remove(
                    &parent,
                    p.file_name()
                        .ok_or_else(|| Error("delete item name".into()))?,
                    &r["identity"],
                    r["kind"] == "directory",
                    name,
                    index,
                    || {
                        source.check()?;
                        require(
                            accounts::authenticated_account()? == user,
                            "administrator identity changed",
                        )
                    },
                )?;
            }
            completed(&record)
        }
        _ => return Err(Error("unknown consumed file operation".into())),
    };
    store.complete(name, &result)?;
    Ok(result)
}
fn completed(record: &Value) -> Value {
    value!({"operation":record["operation"],"items":record["roots"].as_array().map_or(1,Vec::len).max(1),"completed":true,"skipped":record["skipped"].as_array().map_or(0,Vec::len)})
}
