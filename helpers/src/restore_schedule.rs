// SPDX-License-Identifier: MIT
//! Freshly authenticated preview schedules one durable independent restore attempt.
use crate::{accounts, restore_inspect};
use enzimos_platform::{Error, Result, files, json, require};
use enzimos_policy::{
    boot_menu,
    boot_volume::Volume,
    namespaces, native_policy_files, operation, recovery_image,
    recovery_journal::{Journal, Kind},
    recovery_plan, recovery_records, recovery_run_stage,
};
use serde_json::{Value, json as value};
use std::path::Path;
pub fn restore(request: &Value) -> Result<Value> {
    json::fields(request, "action digest birth generation")?;
    for key in ["birth", "generation"] {
        enzimos_policy::identity::safe_id(recovery_records::text(request, key)?)?;
    }
    enzimos_policy::identity::sha(recovery_records::text(request, "digest")?)?;
    accounts::authenticated_account()?;
    let lock = operation::lock()?;
    let state = restore_inspect::inspect_locked(&lock)?;
    require(
        state["digest"] == request["digest"],
        "Recovery choices changed. Refresh and review them again.",
    )?;
    let choice = state["choices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["birth"] == request["birth"] && row["generation"] == request["generation"])
        .ok_or_else(|| Error("Snapshot is no longer available.".into()))?;
    require(
        choice["available"] == true,
        "This source requires a storage layout review before recovery.",
    )?;
    let policies = native_policy_files::observe(Path::new("/usr/lib/enzimos-native"))?;
    let images = Journal::open(Kind::Images, false)?;
    let kernel = namespaces::kernel_release()?;
    let mut compatible = images
        .records
        .iter()
        .filter(|(_, record)| {
            record["phase"] == "ready"
                && record["inputs"]["identity"]["schema"] == 2
                && record["inputs"]["identity"]["policy_files"] == policies
        })
        .collect::<Vec<_>>();
    compatible.sort_by(|(a, ar), (b, br)| {
        let score = |v: &Value| {
            (
                v["inputs"]["identity"]["kernel_release"] == kernel,
                v["observations"].as_object().unwrap().len(),
            )
        };
        score(br).cmp(&score(ar)).then_with(|| a.cmp(b))
    });
    let (image, record) = compatible.first().copied().ok_or_else(|| {
        Error("The recovery image needs to be rebuilt before restoring this system.".into())
    })?;
    recovery_image::verify_published(record)?;
    images.unchanged()?;
    accounts::authenticated_account()?;
    let id = format!("ui-{}", files::random_hex(12)?);
    let plan = recovery_plan::prepare_locked(
        &id,
        recovery_records::text(request, "birth")?,
        recovery_records::text(request, "generation")?,
        &lock,
    )?;
    accounts::authenticated_account()?;
    let result = recovery_run_stage::stage_locked(
        &id,
        recovery_records::text(&plan, "plan_sha256")?,
        "linux",
        image,
        "reboot",
        true,
        &lock,
    )?;
    // Scheduling is already durable. Presentation failure must not repeat it.
    let refreshed = (|| {
        let volume = Volume::observe()?;
        boot_menu::render_live(&volume, true)
    })();
    if let Err(error) = refreshed {
        eprintln!("Recovery run scheduled; boot menu refresh requires inspection: {error}");
    }
    Ok(
        value!({"message":"Restarting to restore this snapshot. Your personal files are preserved.","run":id,"result":result}),
    )
}
