// Copyright (C) 2026 Shirofune Security Co., Ltd.
//
// Unless explicitly acquired and licensed from Licensor under another license, the contents of this
// file are subject to the Reciprocal Public License ("RPL") Version 1.5, or subsequent versions as
// allowed by the RPL, and You may not copy or use this file in either source code or executable
// form, except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS" basis, WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing rights
// and limitations under the RPL.

//! A user's remote connections on notatin's Windows 7 `NTUSER.DAT` (Apache-2.0;
//! `tests/fixtures/notatin/`): Remote Desktop computers and the accounts used on them, a PuTTY
//! and a WinSCP host key, a WinSCP session with a stored password, mapped drives, the paths typed
//! into *Map Network Drive* and the shares Explorer mounted. Every record is what regipy's
//! `terminal_services_history`, `winscp_saved_sessions` and `network_drives_plugin` and Plaso's
//! `mstsc_rdp`, `mstsc_rdp_mru`, `network_drives`, `explorer_mountpoints2` and `mrulist_string`
//! give; the host key's fingerprint is what dissect's `putty` gives.
#![allow(clippy::unwrap_used)]

use std::io::Read;

use ys_registry_parser::Hive;
use ys_registry_parser::remote_access::{
    Client, Connection, Kind, connections, host_key_fingerprint,
};

fn win7_ntuser() -> Hive {
    let path = format!(
        "{}/tests/fixtures/notatin/win7_ntuser.dat.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut data = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut data)
        .unwrap();
    Hive::open(data, &[]).unwrap().0
}

/// A record as `kind target:port user | position | drive`.
fn line(c: &Connection) -> String {
    let port = c.port.map(|p| format!(":{p}")).unwrap_or_default();
    let user = c
        .username
        .as_ref()
        .map(|u| format!(" {u}"))
        .unwrap_or_default();
    let position = c
        .mru_position
        .map(|n| format!(" | {n}"))
        .unwrap_or_default();
    let drive = c
        .drive_letter
        .as_ref()
        .map(|d| format!(" | {d}:"))
        .unwrap_or_default();
    format!(
        "{} {}{port}{user}{position}{drive}",
        c.kind.name(),
        c.target.as_deref().unwrap_or("-")
    )
}

#[test]
#[allow(clippy::too_many_lines)]
fn remote_connections_of_a_windows_7_user() {
    let hive = win7_ntuser();
    let (records, problems) = connections(&hive);
    assert_eq!(problems, Vec::<String>::new());
    let lines: Vec<String> = records.iter().map(line).collect();
    assert_eq!(
        lines,
        [
            "rdp_mru 10.1.4.108 | 0",
            "rdp_mru 10.150.16.33 | 1",
            "rdp_mru 10.150.16.30:63389 | 2",
            "rdp_mru nyfkws0009015 | 3",
            "rdp_mru 10.164.16.16 | 4",
            r"rdp_server 10.1.4.108 10.1.4.108\admin",
            r"rdp_server 10.150.16.30 STROZLLCCOM\administrator",
            r"rdp_server 10.150.16.33 NYFKWS0009038\STROZLLC",
            r"rdp_server 10.164.16.16 STROZLLCCOM\admin",
            r"rdp_server nyfkws0009015 strozllc.com\jmroberts",
            "putty_host_key 10.1.200.20:22",
            "winscp_session -",
            "winscp_session 10.1.200.20 malware",
            "winscp_host_key 10.1.200.20:22",
            r"network_drive \\NYFKWS0009015\Scratchy | B:",
            r"network_drive \\nycelox02\data | N:",
            r"network_drive \\nyradix\NY-PRIVATE | Q:",
            r"network_drive \\nydfs02\software_we_use | T:",
            r"map_network_drive_mru \\NYFKWS0009015\Scratchy | 0",
            r"map_network_drive_mru \\nyradix\NY-PRIVATE | 1",
            r"map_network_drive_mru \\NYFKWS0009015\a$ | 2",
            r"map_network_drive_mru \\dccelox01\F | 3",
            r"map_network_drive_mru \\dcfkws0009355\D | 4",
            r"map_network_drive_mru \\nycelox02\data | 5",
            r"map_network_drive_mru \\NYDFS02\software_we_use | 6",
            r"mount_point \\dccelox01\F",
            r"mount_point \\dcfkws0009355\D",
            r"mount_point \\nycelox02\data",
            r"mount_point \\NYDFS02\software_we_use",
            r"mount_point \\NYFKWS0009015\a$",
            r"mount_point \\NYFKWS0009015\Scratchy",
            r"mount_point \\nyradix\NY-PRIVATE",
        ]
    );
    assert!(records.iter().all(|r| r.problems.is_empty()
        && r.data_raw.is_none()
        && !r.replayed
        && r.key_last_written > 0));

    // the computer typed last is the Default key's last write
    let mru = &records[0];
    assert_eq!(
        (mru.key_path.as_str(), mru.value_name.as_deref()),
        (
            r"Software\Microsoft\Terminal Server Client\Default",
            Some("MRU0")
        )
    );
    assert_eq!(mru.key_last_written, 130_632_196_148_158_305);
    assert_eq!(mru.kind.client(), Client::Rdp);
    // the certificate accepted for one of them
    assert_eq!(
        records[5].details,
        [(
            "CertHash".to_owned(),
            "f0cab303aeef9d77871d07953bcb60dc86e0f5e0".to_owned()
        )]
    );
    assert_eq!(records[5].key_last_written, 130_628_846_062_171_911);

    // the same server key accepted in PuTTY and WinSCP
    let fingerprint = "SHA256:NIWlL38s6iTDvDtHtTXpRipSrsGvuFRtIXjJS2JU7WQ";
    for at in [10, 13] {
        let key = &records[at];
        assert_eq!(key.host_key_type.as_deref(), Some("rsa2"));
        assert_eq!(key.value_name.as_deref(), Some("rsa2@22:10.1.200.20"));
        assert_eq!(key.host_key_fingerprint.as_deref(), Some(fingerprint));
        assert!(
            key.host_key
                .as_deref()
                .unwrap()
                .starts_with("0x23,0xdf9e9f1e")
        );
    }
    assert_eq!(records[10].kind.client(), Client::Putty);

    // WinSCP's template session, and a session with a stored password (not decoded)
    let template = &records[11];
    assert_eq!(template.session_name.as_deref(), Some("Default Settings"));
    assert_eq!(template.password_stored, Some(false));
    let session = &records[12];
    assert_eq!(
        (
            session.kind,
            session.session_name.as_deref(),
            session.port,
            session.protocol.as_deref(),
            session.password_stored
        ),
        (
            Kind::WinscpSession,
            Some("malware@10.1.200.20"),
            None,
            None,
            Some(true)
        )
    );
    assert_eq!(
        session.details,
        [
            ("LocalDirectory", r"C:\Users\jmroberts\Desktop"),
            (
                "RemoteDirectory",
                "/opt/cuckoo10/cuckoo/storage/analyses/71"
            ),
            ("StoredPasswords", "Password"),
        ]
        .map(|(n, v)| (n.to_owned(), v.to_owned()))
    );

    // a mapped drive: its provider, and no account of its own (UserName is a DWORD 0)
    let drive = &records[14];
    assert_eq!(drive.key_path, r"Network\B");
    assert_eq!(drive.protocol.as_deref(), Some("Microsoft Windows Network"));
    assert_eq!(drive.username, None);
    assert_eq!(
        drive.details,
        [("ConnectionType", "1 (disk)"), ("ProviderType", "0x20000")]
            .map(|(n, v)| (n.to_owned(), v.to_owned()))
    );
    assert_eq!(records[18].value_name.as_deref(), Some("g"));
    assert_eq!(records[18].kind.client(), Client::MappedDrive);
    let share = &records[31];
    assert_eq!(
        share.key_path,
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\##nyradix#NY-PRIVATE"
    );
    assert_eq!(share.kind.client(), Client::NetworkShare);
}

#[test]
fn a_user_without_remote_connections() {
    let path = format!(
        "{}/tests/fixtures/regipy/NTUSER.DAT.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut data = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut data)
        .unwrap();
    let hive = Hive::open(data, &[]).unwrap().0;
    // an empty Terminal Server Client key; one drive mapped and its share
    let (records, problems) = connections(&hive);
    assert_eq!(problems, Vec::<String>::new());
    let lines: Vec<String> = records.iter().map(line).collect();
    assert_eq!(
        lines,
        [
            r"network_drive \\controller\public | p:",
            r"mount_point \\controller\public",
        ]
    );
    assert_eq!(
        records[1].details,
        [("Label".to_owned(), "Public".to_owned())]
    );
}

/// Host keys in `SshHostKeys` form, generated for these tests (`tests/fixtures/host_keys.tsv`):
/// every type PuTTY writes, ECDSA coordinates shorter than their field, EdDSA points with `x`
/// odd and even, and RSA exponents that need no `mpint` padding. The fingerprints are OpenSSH's
/// `ssh-keygen -l`'s, but DSA's and Ed448's, which OpenSSH no longer reads: the SHA-256 of the
/// encoding pycryptodome gives.
#[test]
fn host_key_fingerprints_match_openssh() {
    let path = format!(
        "{}/tests/fixtures/host_keys.tsv",
        env!("CARGO_MANIFEST_DIR")
    );
    let vectors = std::fs::read_to_string(path).unwrap();
    let mut types = Vec::new();
    for line in vectors.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        let [key_type, stored, fingerprint, note] = fields[..] else {
            panic!("{line}");
        };
        assert_eq!(
            host_key_fingerprint(key_type, stored).as_deref(),
            Ok(fingerprint),
            "{note}"
        );
        if !types.contains(&key_type) {
            types.push(key_type);
        }
    }
    assert_eq!(
        types,
        [
            "rsa2",
            "dss",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
            "ssh-ed25519",
            "ssh-ed448"
        ]
    );
    // the point without its curve's name isn't PuTTY's form
    assert!(host_key_fingerprint("ecdsa-sha2-nistp256", "0x1,0x2").is_err());
}
