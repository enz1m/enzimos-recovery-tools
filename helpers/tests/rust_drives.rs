// SPDX-License-Identifier: MIT
use enzimos_recovery_tools::drives;
use serde_json::{Value, json};
fn fixture() -> Value {
    json!({"blockdevices":[{"name":"/dev/sdx","type":"disk","tran":"usb","rm":false,"fstype":null,"uuid":null,"size":1000000000,"label":null,"mountpoints":[null],"ro":false,"maj:min":"8:32","disk-seq":7,"serial":"","model":"Test external volume","children":[{"name":"/dev/sdx1","type":"part","tran":null,"rm":false,"fstype":"exfat","uuid":"1234-ABCD","size":900000000,"label":"Rescue","mountpoints":[null],"ro":false,"maj:min":"8:33","serial":null,"model":null}]}]})
}
#[test]
fn only_existing_external_filesystems_on_non_system_disks_are_offered() {
    let mut v = fixture();
    let offered = drives::parse(&v).unwrap();
    assert_eq!(offered.as_array().unwrap().len(), 1);
    assert_eq!(offered[0]["name"], "/dev/sdx1");
    assert_eq!(offered[0]["mounted"], false);
    let id = offered[0]["id"].as_str().unwrap().to_owned();
    v["blockdevices"][0]["children"][0]["mountpoints"] =
        json!([format!("{}/{}", drives::MEDIA, id)]);
    assert_eq!(drives::parse(&v).unwrap()[0]["mounted"], true);
    v["blockdevices"][0]["children"][0]["mountpoints"] = json!(["/mnt/other"]);
    assert!(
        !drives::parse(&v).unwrap()[0]["reason"]
            .as_str()
            .unwrap()
            .is_empty()
    );
    for system in ["/", "/home", "/boot/efi", "/var/lib"] {
        v["blockdevices"][0]["children"][0]["mountpoints"] = json!([system]);
        assert!(drives::parse(&v).unwrap().as_array().unwrap().is_empty());
    }
    let mut v = fixture();
    v["blockdevices"][0]["tran"] = json!("sata");
    assert!(drives::parse(&v).unwrap().as_array().unwrap().is_empty());
    v["blockdevices"][0]["rm"] = json!(true);
    assert_eq!(drives::parse(&v).unwrap().as_array().unwrap().len(), 1);
    let mut v = fixture();
    v["blockdevices"][0]["children"][0]["ro"] = json!(true);
    assert!(drives::parse(&v).unwrap().as_array().unwrap().is_empty());
    let mut v = fixture();
    v["blockdevices"][0]["children"][0]["fstype"] = json!("btrfs");
    assert!(drives::parse(&v).unwrap().as_array().unwrap().is_empty());
    for (key, bad) in [
        ("ro", json!(0)),
        ("name", json!("/dev/../etc/shadow")),
        ("size", json!(-1)),
        ("maj:min", json!("8:-1")),
    ] {
        let mut v = fixture();
        v["blockdevices"][0]["children"][0][key] = bad;
        assert!(drives::parse(&v).is_err());
    }
}

#[test]
fn foreign_boot_and_recovery_partitions_are_not_backup_targets() {
    let mut row = fixture();
    for kind in [
        "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
        "de94bba4-06d1-4d40-a16a-bfd50179d6ac",
        "0xef",
    ] {
        row["blockdevices"][0]["children"][0]["parttype"] = json!(kind);
        assert_eq!(drives::parse(&row).unwrap(), json!([]));
    }
}
