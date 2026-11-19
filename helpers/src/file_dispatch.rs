// SPDX-License-Identifier: MIT
use crate::{accounts, drives, file_paths, file_rescue, manager_apply, manager_plan, protocol};
use enzimos_platform::{Error, Result, json, require};
use serde_json::{Value, json as value};
use std::io::Write;
fn text<'a>(request: &'a Value, key: &str, default: Option<&'a str>) -> Result<&'a str> {
    match request.get(key) {
        None => default.ok_or_else(|| Error("Recovery request field is missing.".into())),
        Some(Value::String(s)) => Ok(s),
        _ => Err(Error("Recovery request field has the wrong type.".into())),
    }
}
fn page(request: &Value) -> Result<Option<u64>> {
    match request.get("page") {
        None => Ok(Some(0)),
        Some(Value::Null) => Ok(None),
        Some(v) => Ok(Some(
            v.as_u64()
                .ok_or_else(|| Error("Invalid file page.".into()))?,
        )),
    }
}
fn optional_fields(request: &Value, allowed: &[&str]) -> Result<()> {
    let object = request
        .as_object()
        .ok_or_else(|| Error("Invalid recovery request.".into()))?;
    require(
        object
            .keys()
            .all(|s| s == "action" || allowed.contains(&s.as_str())),
        "Unknown recovery request field.",
    )
}
pub fn execute<W: Write>(request: &Value, output: &mut W) -> Result<Value> {
    let _account = accounts::authenticated_account()?;
    match text(request, "action", None)? {
        "files_list" => {
            optional_fields(request, &["path", "page"])?;
            let path = text(request, "path", Some("/home"))?;
            let path = file_paths::source(path)?;
            let path = path
                .to_str()
                .ok_or_else(|| Error("Recovery file path encoding.".into()))?;
            let directory = file_paths::open_source(path, true)?;
            file_paths::listing(&directory, path, page(request)?, path == "/")
        }
        "files_destination" => {
            optional_fields(request, &["drive", "path", "page"])?;
            let drive = drives::Pinned::open(text(request, "drive", None)?)?;
            let path = text(request, "path", Some(""))?;
            let directory = file_paths::open_destination(&drive.directory, path)?;
            let result = file_paths::listing(&directory, path, page(request)?, false)?;
            drive.check()?;
            Ok(result)
        }
        "files_drives" => {
            json::fields(request, "action")?;
            Ok(value!({"drives":drives::query()?}))
        }
        "files_eject" => {
            json::fields(request, "action drive")?;
            drives::Pinned::existing(text(request, "drive", None)?)?.eject()
        }
        "files_manager_plan" => manager_plan::plan(request),
        "files_manager_apply" => manager_apply::apply(request, |v| protocol::emit(output, &v)),
        "files_plan" => file_rescue::plan(request),
        "files_copy" => file_rescue::copy(request, |v| protocol::emit(output, &v)),
        _ => Err(Error("Unknown recovery file action.".into())),
    }
}
