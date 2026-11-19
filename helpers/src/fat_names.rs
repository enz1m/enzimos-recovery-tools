// SPDX-License-Identifier: MIT
//! Names FAT32/exFAT cannot store are skipped at plan time with a reason.
//! The kernel refuses them only at publication, which aborted a whole copy
//! after most data was written and reported it as a link failure.
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub fn restricted(fstype: &str) -> bool {
    matches!(fstype, "vfat" | "exfat")
}

fn component_ok(name: &str) -> bool {
    !name.is_empty()
        && name.encode_utf16().count() <= 255
        && !name.ends_with('.')
        && !name.ends_with(' ')
        && !name.chars().any(|c| {
            (c as u32) < 0x20 || matches!(c, '"' | '*' | ':' | '<' | '>' | '?' | '\\' | '|')
        })
}

/// Move records (and everything below them) whose relative path has a
/// component FAT cannot hold, or that collides case-insensitively with an
/// earlier sibling, into `skipped`.
pub fn partition(records: &mut Vec<Value>, skipped: &mut Vec<Value>) {
    let mut refused: Vec<String> = Vec::new();
    let mut seen = BTreeSet::new();
    let mut kept = Vec::with_capacity(records.len());
    for record in records.drain(..) {
        let relative = record["relative"].as_str().unwrap_or("").to_owned();
        let source = record["source"].clone();
        if refused
            .iter()
            .any(|prefix| relative.starts_with(&format!("{prefix}/")))
        {
            skipped.push(json!([source, "inside a folder this drive cannot store"]));
            continue;
        }
        let invalid = relative
            .split('/')
            .filter(|c| !c.is_empty())
            .any(|c| !component_ok(c));
        let folded = relative.to_lowercase();
        let reason = if invalid {
            Some("name not allowed on FAT/exFAT drives")
        } else if !seen.insert(folded) {
            Some("name differs only in letter case from another item")
        } else {
            None
        };
        match reason {
            Some(reason) => {
                skipped.push(json!([source, reason]));
                refused.push(relative);
            }
            None => kept.push(record),
        }
    }
    *records = kept;
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(relative: &str) -> Value {
        json!({"source":format!("/home/a/{relative}"),"relative":relative,"kind":"file"})
    }
    #[test]
    fn invalid_names_and_case_collisions_are_skipped_with_their_children() {
        let mut records = vec![
            record("Docs"),
            record("Docs/Notes: Q3.txt"),
            record("Docs/ok.txt"),
            record("Bad?Dir"),
            record("Bad?Dir/inner.txt"),
            record("photo.JPG"),
            record("photo.jpg"),
            record("trailing."),
        ];
        let mut skipped = Vec::new();
        partition(&mut records, &mut skipped);
        let kept = records
            .iter()
            .map(|r| r["relative"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(kept, ["Docs", "Docs/ok.txt", "photo.JPG"]);
        assert_eq!(skipped.len(), 5);
        assert!(restricted("vfat") && restricted("exfat") && !restricted("ntfs3"));
    }
}
