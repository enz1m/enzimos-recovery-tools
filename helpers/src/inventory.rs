// SPDX-License-Identifier: MIT
use enzimos_platform::{Error, Result, require};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
fn parse(s: &str) -> Result<BTreeMap<&str, &str>> {
    require(s.len() <= 8 * 1024 * 1024, "package inventory bound")?;
    let mut out = BTreeMap::new();
    for line in s.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        require(
            fields.len() == 2 && out.insert(fields[0], fields[1]).is_none(),
            "invalid or duplicate package inventory",
        )?;
        require(out.len() <= 32768, "package inventory count")?;
    }
    Ok(out)
}
pub fn changes(snapshot: &str, current: &str) -> Result<Value> {
    let old = parse(snapshot)?;
    let now = parse(current)?;
    let names = old
        .keys()
        .chain(now.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    let mut changes = Vec::new();
    let (mut added, mut removed, mut changed) = (0, 0, 0);
    for name in names {
        match (old.get(name), now.get(name)) {
            (Some(v), None) => {
                added += 1;
                changes.push(format!("Restore {name} {v}"));
            }
            (None, Some(v)) => {
                removed += 1;
                changes.push(format!("Remove {name} {v}"));
            }
            (Some(a), Some(b)) if a != b => {
                changed += 1;
                changes.push(format!("{name}   {b} → {a}"));
            }
            (Some(_), Some(_)) => {}
            _ => return Err(Error("invalid inventory merge".into())),
        }
    }
    Ok(
        json!({"summary":format!("{} packages in snapshot · {changed} version changes · {added} restored · {removed} removed",old.len()),"changes":changes}),
    )
}
