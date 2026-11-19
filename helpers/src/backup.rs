// SPDX-License-Identifier: MIT
//! Restore from an encrypted backup in the recovery environment: where the
//! repository is, which snapshot, and where its files go. The repository
//! password is the authorization; it reaches restic only through its
//! environment, never arguments or logs.
use enzimos_platform::{Error, Result, require};
use serde_json::{Value, json};

/// Where a restic repository is.
#[derive(Debug, PartialEq, Eq)]
pub enum Source {
    /// A folder on an external drive (lsblk identity), relative to its root.
    Drive { drive: String, path: String },
    /// An SMB share (`//server/share`) and a folder in it: the layout an
    /// enzimOS NAS backup uses (`smb://server/share/folder`). The user may be
    /// given as `DOMAIN\user` or `DOMAIN/user`.
    Share {
        server: String,
        share: String,
        path: String,
        user: String,
        /// The user's domain or workgroup, from `DOMAIN\user`.
        domain: Option<String>,
    },
    /// A restic REST server over HTTPS, with its HTTP user if it asks for one.
    /// The user's password goes to restic through its environment.
    Rest { url: String, user: Option<String> },
}

fn drive_id(value: &str) -> Result<String> {
    require(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid external drive selection",
    )?;
    Ok(value.to_owned())
}

/// A relative folder without `..`, empty for the root.
fn folder(value: &str) -> Result<String> {
    let clean = value.trim_matches('/');
    require(
        clean.len() < 1024
            && !clean.chars().any(char::is_control)
            && clean.split('/').all(|part| !matches!(part, ".." | ".")),
        "invalid backup folder",
    )?;
    Ok(clean.to_owned())
}

fn text<'a>(request: &'a Value, key: &str, max: usize) -> Result<&'a str> {
    request[key]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control))
        .ok_or_else(|| Error(format!("invalid {key}")))
}

impl Source {
    pub fn parse(request: &Value) -> Result<Self> {
        match request["kind"].as_str() {
            Some("drive") => Ok(Self::Drive {
                drive: drive_id(text(request, "drive", 64)?)?,
                path: folder(request["path"].as_str().unwrap_or_default())?,
            }),
            Some("share") => {
                let location = text(request, "location", 512)?;
                let rest = location
                    .strip_prefix("smb://")
                    .or_else(|| location.strip_prefix("//"))
                    .ok_or_else(|| Error("a share is smb://server/share/folder".into()))?;
                let mut parts = rest.splitn(3, '/');
                let server = parts.next().unwrap_or_default();
                let share = parts.next().unwrap_or_default();
                require(
                    !server.is_empty()
                        && !share.is_empty()
                        && server.len() <= 253
                        && server
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"-.:[]".contains(&b))
                        && !share.contains([',', '\\']),
                    "a share is smb://server/share/folder",
                )?;
                let given = request["user"].as_str().unwrap_or("guest");
                let (domain, user) = match given.split_once(['\\', '/']) {
                    Some((domain, user)) => (Some(domain), user),
                    None => (None, given),
                };
                let plain = |s: &str| {
                    !s.is_empty()
                        && s.len() <= 128
                        && !s.contains([',', '=', '\\', '/'])
                        && !s.chars().any(char::is_control)
                };
                let valid = match domain {
                    Some(d) => plain(d) && plain(user),
                    None => given.is_empty() || plain(user),
                };
                require(valid, "invalid share user")?;
                Ok(Self::Share {
                    server: server.to_owned(),
                    share: share.to_owned(),
                    path: folder(parts.next().unwrap_or_default())?,
                    user: user.to_owned(),
                    domain: domain.map(str::to_owned),
                })
            }
            Some("rest") => {
                let url = text(request, "location", 512)?;
                require(
                    url.starts_with("https://") && !url.contains(char::is_whitespace),
                    "a REST server address starts with https://",
                )?;
                // Credentials in the address would reach restic's arguments.
                let authority = url
                    .strip_prefix("https://")
                    .unwrap_or_default()
                    .split(['/', '?', '#'])
                    .next()
                    .unwrap_or_default();
                require(
                    !authority.contains('@'),
                    "enter the server's user and password in their own fields, not in its address",
                )?;
                let user = request["user"].as_str().filter(|u| !u.is_empty());
                require(
                    user.is_none_or(|u| {
                        u.len() <= 128 && !u.contains(':') && !u.chars().any(char::is_control)
                    }),
                    "invalid server user",
                )?;
                Ok(Self::Rest {
                    url: url.to_owned(),
                    user: user.map(str::to_owned),
                })
            }
            _ => Err(Error("unknown backup location".into())),
        }
    }

    /// The restic repository argument once any mount is at `mounted`.
    pub fn repository(&self, mounted: &str) -> String {
        match self {
            Self::Drive { path, .. } | Self::Share { path, .. } => {
                if path.is_empty() {
                    mounted.to_owned()
                } else {
                    format!("{mounted}/{path}")
                }
            }
            Self::Rest { url, .. } => format!("rest:{url}"),
        }
    }
}

/// A snapshot id restic prints (8 to 64 hex digits).
pub fn snapshot_id(value: &str) -> Result<&str> {
    require(
        (8..=64).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid backup snapshot",
    )?;
    Ok(value)
}

/// `restic snapshots --json` as the screen lists it: newest first.
pub fn snapshots(listed: &Value) -> Result<Value> {
    let rows = listed
        .as_array()
        .ok_or_else(|| Error("unreadable backup listing".into()))?;
    let mut out = rows
        .iter()
        .take(4096)
        .filter_map(|row| {
            Some(json!({
                "id": snapshot_id(row["id"].as_str()?).ok()?,
                "short": row["short_id"].as_str().unwrap_or_default(),
                "time": row["time"].as_str()?,
                "host": row["hostname"].as_str().unwrap_or_default(),
                "paths": row["paths"].clone(),
            }))
        })
        .collect::<Vec<_>>();
    out.sort_by(|a, b| b["time"].as_str().cmp(&a["time"].as_str()));
    Ok(Value::Array(out))
}

/// Choose the home subtree for a system snapshot. A standalone folder snapshot
/// can be restored as a whole once its listing has been checked.
pub fn personal(snapshot: &Value, listing: &str) -> Result<Option<&'static str>> {
    let paths = snapshot["paths"]
        .as_array()
        .filter(|paths| !paths.is_empty() && paths.iter().all(Value::is_string))
        .ok_or_else(|| Error("backup snapshot has no source paths".into()))?;
    let mut saw_node = false;
    let mut home = false;
    for line in listing.lines().filter(|line| !line.trim().is_empty()) {
        let entry: Value =
            serde_json::from_str(line).map_err(|_| Error("unreadable backup contents".into()))?;
        if entry["struct_type"] == "node" {
            saw_node = true;
            home |= entry["path"] == "/home" && entry["type"] == "dir";
        }
    }
    require(saw_node, "backup snapshot has no readable files")?;
    for (root, home) in [
        ("/backup-source/", "/backup-source/home"),
        ("/run/enzimos-backup/", "/run/enzimos-backup/home"),
    ] {
        if paths
            .iter()
            .filter_map(Value::as_str)
            .any(|path| path.starts_with(root))
        {
            require(
                paths.iter().any(|path| path == home),
                "this enzimOS backup has no personal files subtree",
            )?;
            return Ok(Some(home));
        }
    }
    Ok(home.then_some("/home"))
}

/// A progress line of `restic restore --json` as a fraction, if it is one.
pub fn progress(line: &str) -> Option<f64> {
    let value: Value = serde_json::from_str(line).ok()?;
    (value["message_type"] == "status")
        .then(|| value["percent_done"].as_f64())
        .flatten()
        .map(|p| p.clamp(0.0, 1.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locations_are_checked_and_become_repositories() {
        let drive = "a".repeat(64);
        let source =
            Source::parse(&json!({"kind": "drive", "drive": drive, "path": "/backups/enzimos/"}))
                .unwrap();
        assert_eq!(source.repository("/run/x"), "/run/x/backups/enzimos");
        assert!(
            Source::parse(&json!({"kind": "drive", "drive": drive, "path": "../etc"})).is_err()
        );
        assert!(Source::parse(&json!({"kind": "drive", "drive": "abc"})).is_err());
        let share = Source::parse(
            &json!({"kind": "share", "location": "smb://nas.local/backup/enzimos", "user": "ann"}),
        )
        .unwrap();
        assert_eq!(
            share,
            Source::Share {
                server: "nas.local".into(),
                share: "backup".into(),
                path: "enzimos".into(),
                user: "ann".into(),
                domain: None
            }
        );
        // An enzimOS NAS backup: share `backups`, folder `enzimos/laptop`, a domain account.
        let nas = Source::parse(&json!({"kind": "share", "location": "smb://nas.local/backups/enzimos/laptop", "user": "HOME\\ann"})).unwrap();
        assert_eq!(nas.repository("/run/x"), "/run/x/enzimos/laptop");
        assert!(
            matches!(nas, Source::Share { ref user, ref domain, .. } if user == "ann" && domain.as_deref() == Some("HOME"))
        );
        assert!(
            Source::parse(
                &json!({"kind": "share", "location": "smb://nas/backup", "user": "a/b/c"})
            )
            .is_err()
        );
        assert!(
            Source::parse(
                &json!({"kind": "share", "location": "smb://nas/backup", "user": "a,uid=0"})
            )
            .is_err()
        );
        assert!(Source::parse(&json!({"kind": "share", "location": "nas/backup"})).is_err());
        let rest = Source::parse(
            &json!({"kind": "rest", "location": "https://backup.example.org/ann", "user": "ann"}),
        )
        .unwrap();
        assert_eq!(rest.repository(""), "rest:https://backup.example.org/ann");
        assert_eq!(
            rest,
            Source::Rest {
                url: "https://backup.example.org/ann".into(),
                user: Some("ann".into())
            }
        );
        assert!(
            Source::parse(&json!({"kind": "rest", "location": "http://backup.example.org"}))
                .is_err()
        );
        // Credentials stay out of the address (and so out of restic's arguments).
        assert!(
            Source::parse(
                &json!({"kind": "rest", "location": "https://ann:pw@backup.example.org/ann"})
            )
            .is_err()
        );
        assert!(
            Source::parse(&json!({"kind": "rest", "location": "https://backup.example.org/a@b"}))
                .is_ok()
        );
        assert!(
            Source::parse(
                &json!({"kind": "rest", "location": "https://backup.example.org", "user": "a:b"})
            )
            .is_err()
        );
    }

    #[test]
    fn listings_progress_and_personal_paths() {
        let listed = json!([
            {"id": "a".repeat(64), "short_id": "aaaaaaaa", "time": "2026-10-01T10:00:00Z", "hostname": "pc", "paths": ["/run/enzimos-backup/root", "/run/enzimos-backup/home"]},
            {"id": "b".repeat(64), "short_id": "bbbbbbbb", "time": "2026-10-20T10:00:00Z", "hostname": "pc", "paths": ["/home/ann"]},
            {"id": "not hex", "time": "2026-10-21T10:00:00Z"}
        ]);
        let rows = snapshots(&listed).unwrap();
        assert_eq!(rows.as_array().unwrap().len(), 2);
        assert_eq!(rows[0]["short"], "bbbbbbbb", "newest first");
        let top = concat!(
            r#"{"struct_type":"snapshot","paths":["/x/home"]}"#,
            "\n",
            r#"{"struct_type":"node","path":"/etc","type":"dir"}"#,
            "\n",
            r#"{"struct_type":"node","path":"/home","type":"dir"}"#,
            "\n"
        );
        let whole = json!({"paths":["/backup-source/system","/backup-source/home","/backup-source/boot","/backup-source/inventory"]});
        let folder = json!({"paths":["/data"]});
        let ordinary = r#"{"struct_type":"node","path":"/data","type":"dir"}"#;
        assert_eq!(
            personal(&whole, ordinary).unwrap(),
            Some("/backup-source/home")
        );
        assert_eq!(
            personal(&rows[1], ordinary).unwrap(),
            Some("/run/enzimos-backup/home")
        );
        assert_eq!(personal(&folder, top).unwrap(), Some("/home"));
        assert_eq!(personal(&folder, ordinary).unwrap(), None);
        assert!(personal(&json!({"paths":["/backup-source/system"]}), ordinary).is_err());
        assert!(personal(&whole, "invalid JSON").is_err());
        assert_eq!(
            progress(r#"{"message_type":"status","percent_done":0.25}"#),
            Some(0.25)
        );
        assert_eq!(progress(r#"{"message_type":"summary"}"#), None);
        assert!(snapshot_id("abc").is_err() && snapshot_id("abcdef01").is_ok());
    }
}
