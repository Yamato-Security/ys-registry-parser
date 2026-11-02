//! The remote connections a user made, from `NTUSER.DAT`: Remote Desktop (`mstsc`), PuTTY and
//! WinSCP, mapped network drives and the shares Explorer mounted.
//!
//! - **Remote Desktop:** `Software\Microsoft\Terminal Server Client`: `Default`'s `MRU0`…`MRU9`
//!   (the computers typed into the client, the most recent first, `host` or `host:port`), a
//!   `Servers\<host>` key per computer the user signed in to (`UsernameHint`, and `CertHash`: the
//!   SHA-1 thumbprint of the certificate the user accepted), and `LocalDevices` (a value per
//!   computer the user let use local devices, its data the devices).
//! - **PuTTY:** `Software\SimonTatham\PuTTY`: a key per saved session under `Sessions` (its name
//!   escaped, `%20` for a space), the sessions started last (`Jumplist`'s `Recent sessions`), and
//!   `SshHostKeys`: a value per SSH server key the user accepted, named `<type>@<port>:<host>`,
//!   its data the key's numbers in hex (`0x<e>,0x<n>` for `rsa2`, the curve and point for ECDSA,
//!   the point for EdDSA).
//! - **WinSCP:** `Software\Martin Prikryl\WinSCP 2`: a key per saved session under `Sessions`
//!   (only settings that aren't the defaults are written; strings escaped like the names), and
//!   `SshHostKeys` as PuTTY's.
//! - **Mapped drives:** `Network\<letter>` (`RemotePath`, `UserName`, `ProviderName`) for each
//!   drive mapped to be restored at sign-in, and `Explorer\Map Network Drive MRU` (the paths
//!   typed into *Map Network Drive*, in the order of `MRUList`).
//! - **Shares:** `Explorer\MountPoints2`'s `##server#share` keys, one per share Explorer mounted.
//!
//! An SSH host key's fingerprint is OpenSSH's: `SHA256:` and the Base64 of the SHA-256 digest of
//! the key's SSH wire encoding, which is built from the numbers PuTTY and WinSCP keep.

use crate::digest::{base64_unpadded, sha256};
use crate::hive::{Hive, Key, Status, Value};
use crate::system::{number, string};

/// Remote Desktop's client settings, under the hive's root.
pub const TERMINAL_SERVER_CLIENT: &str = r"Software\Microsoft\Terminal Server Client";
/// PuTTY's settings, under the hive's root.
pub const PUTTY: &str = r"Software\SimonTatham\PuTTY";
/// WinSCP's settings, under the hive's root.
pub const WINSCP: &str = r"Software\Martin Prikryl\WinSCP 2";
/// The drives mapped to be restored at sign-in, under the hive's root.
pub const NETWORK: &str = "Network";
/// The paths typed into Explorer's *Map Network Drive*, under the hive's root.
pub const MAP_NETWORK_DRIVE_MRU: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU";
/// The volumes, drives and shares Explorer mounted, under the hive's root.
pub const MOUNT_POINTS2: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2";

/// The program a connection was made with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Client {
    /// Remote Desktop (`mstsc`).
    Rdp,
    /// PuTTY.
    Putty,
    /// WinSCP.
    Winscp,
    /// A drive letter mapped to a share.
    MappedDrive,
    /// A share Explorer mounted.
    NetworkShare,
}

impl Client {
    /// `rdp`, `putty`, `winscp`, `mapped_drive` or `network_share`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Client::Rdp => "rdp",
            Client::Putty => "putty",
            Client::Winscp => "winscp",
            Client::MappedDrive => "mapped_drive",
            Client::NetworkShare => "network_share",
        }
    }
}

/// The key or value a record comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// `Terminal Server Client\Default`'s `MRU<n>`.
    RdpMru,
    /// `Terminal Server Client\Servers\<host>`.
    RdpServer,
    /// A value of `Terminal Server Client\LocalDevices`.
    RdpLocalDevices,
    /// `PuTTY\Sessions\<name>`, or a name only `Jumplist`'s `Recent sessions` has.
    PuttySession,
    /// A value of `PuTTY\SshHostKeys`.
    PuttyHostKey,
    /// `WinSCP 2\Sessions\<name>`.
    WinscpSession,
    /// A value of `WinSCP 2\SshHostKeys`.
    WinscpHostKey,
    /// `Network\<letter>`.
    NetworkDrive,
    /// A value of `Map Network Drive MRU`.
    MapNetworkDriveMru,
    /// `MountPoints2\##server#share`.
    MountPoint,
}

impl Kind {
    /// `rdp_mru`, `rdp_server`, `rdp_local_devices`, `putty_session`, `putty_host_key`,
    /// `winscp_session`, `winscp_host_key`, `network_drive`, `map_network_drive_mru` or
    /// `mount_point`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Kind::RdpMru => "rdp_mru",
            Kind::RdpServer => "rdp_server",
            Kind::RdpLocalDevices => "rdp_local_devices",
            Kind::PuttySession => "putty_session",
            Kind::PuttyHostKey => "putty_host_key",
            Kind::WinscpSession => "winscp_session",
            Kind::WinscpHostKey => "winscp_host_key",
            Kind::NetworkDrive => "network_drive",
            Kind::MapNetworkDriveMru => "map_network_drive_mru",
            Kind::MountPoint => "mount_point",
        }
    }

    /// The program of its connections.
    #[must_use]
    pub fn client(self) -> Client {
        match self {
            Kind::RdpMru | Kind::RdpServer | Kind::RdpLocalDevices => Client::Rdp,
            Kind::PuttySession | Kind::PuttyHostKey => Client::Putty,
            Kind::WinscpSession | Kind::WinscpHostKey => Client::Winscp,
            Kind::NetworkDrive | Kind::MapNetworkDriveMru => Client::MappedDrive,
            Kind::MountPoint => Client::NetworkShare,
        }
    }
}

/// One remote connection a user made or set up: a computer, a saved session, an accepted host
/// key, a mapped drive or a share. Fields that its key or value doesn't hold are `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    /// Where it comes from (and with [`Kind::client`], the program).
    pub kind: Kind,
    /// The key, from the hive's root.
    pub key_path: String,
    /// The value, for a record that is one value (`MRU0`, `a`, `rsa2@22:host`).
    pub value_name: Option<String>,
    /// When the key was last written (FILETIME). For a list (`Default`, `SshHostKeys`, `Map
    /// Network Drive MRU`), when its most recent change was written.
    pub key_last_written: u64,
    /// The computer (`host`, an IP address) or the share (`\\server\share`).
    pub target: Option<String>,
    /// The port: given with the computer (`host:3390`), in a session, or in a host key's name.
    pub port: Option<u32>,
    /// The account on the target: `UsernameHint`, a session's `UserName` (or the `user@` of
    /// PuTTY's `HostName`), a mapped drive's `UserName`.
    pub username: Option<String>,
    /// PuTTY's `Protocol` (`ssh`, `telnet`, …), WinSCP's `FSProtocol` named (`sftp`, `scp`,
    /// `ftp`, `webdav`, `s3`), a mapped drive's `ProviderName`.
    pub protocol: Option<String>,
    /// Its place in the list (0: the most recent): `MRU<n>`'s number, its letter's place in
    /// `MRUList`, a PuTTY session's place in `Jumplist`'s `Recent sessions`.
    pub mru_position: Option<u32>,
    /// A saved session's name, unescaped (`%20` as a space).
    pub session_name: Option<String>,
    /// A host key's type, as PuTTY names it (`rsa2`, `ssh-ed25519`, `ecdsa-sha2-nistp256`, …).
    pub host_key_type: Option<String>,
    /// A host key's numbers, as stored.
    pub host_key: Option<String>,
    /// A host key's fingerprint, as OpenSSH shows it (`SHA256:…`).
    pub host_key_fingerprint: Option<String>,
    /// A mapped drive's letter.
    pub drive_letter: Option<String>,
    /// Whether a session keeps a password (WinSCP's `Password`, `PasswordPlain`, a proxy's or a
    /// tunnel's; PuTTY's `ProxyPassword`). They are not decoded.
    pub password_stored: Option<bool>,
    /// What else the key or value says: a session's key file, proxy, tunnel, port forwardings,
    /// remote command and directories, a certificate's thumbprint, a share's label, … as
    /// (name, value) pairs.
    pub details: Vec<(String, String)>,
    /// The value's bytes, for a record that is one value whose data doesn't decode.
    pub data_raw: Option<Vec<u8>>,
    /// Whether the transaction logs' replay wrote the key or a value read.
    pub replayed: bool,
    /// What couldn't be read. A value of a key that isn't of the type it should be is named,
    /// with its bytes in hex.
    pub problems: Vec<String>,
}

impl Connection {
    /// A record of `kind` from `key` at `key_path`, with nothing read yet.
    fn new(kind: Kind, key: &Key, key_path: String) -> Self {
        Connection {
            kind,
            key_path,
            value_name: None,
            key_last_written: key.last_written(),
            target: None,
            port: None,
            username: None,
            protocol: None,
            mru_position: None,
            session_name: None,
            host_key_type: None,
            host_key: None,
            host_key_fingerprint: None,
            drive_letter: None,
            password_stored: None,
            details: Vec::new(),
            data_raw: None,
            replayed: key.status() == Status::Replayed,
            problems: Vec::new(),
        }
    }

    /// The text of `key`'s string value `name`; `None` when it is missing or empty. A value that
    /// isn't a string is a problem, with its bytes.
    fn text(&mut self, key: &Key, name: &str) -> Option<String> {
        let value = key.value(name)?;
        self.replayed |= value.status() == Status::Replayed;
        let (text, why) = string(&value);
        if let Some(why) = why {
            let bytes = value.read_data().0;
            self.problems
                .push(format!("{name}: {why}; its data: {}", hex(&bytes)));
        }
        text.filter(|t| !t.is_empty())
    }

    /// The number of `key`'s `REG_DWORD` value `name`; `None` when it is missing. A value of
    /// another type is a problem, with its bytes.
    fn number(&mut self, key: &Key, name: &str) -> Option<u32> {
        let value = key.value(name)?;
        self.replayed |= value.status() == Status::Replayed;
        match number(&value) {
            Ok(n) => Some(n),
            Err(why) => {
                let bytes = value.read_data().0;
                self.problems
                    .push(format!("{name}: {why}; its data: {}", hex(&bytes)));
                None
            }
        }
    }

    /// The text of the string value the record is; with a problem and the value's bytes when it
    /// isn't a string or doesn't decode.
    fn value_text(&mut self, value: &Value) -> Option<String> {
        let (text, why) = string(value);
        if let Some(why) = why {
            self.problems.push(why);
            self.data_raw = Some(value.read_data().0);
        }
        text
    }

    /// Add a detail.
    fn detail(&mut self, name: &str, value: impl Into<String>) {
        self.details.push((name.to_owned(), value.into()));
    }
}

/// Bytes in lower-case hex.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut text, b| {
            let _ = write!(text, "{b:02x}");
            text
        })
}

/// The remote connections of `hive`, an `NTUSER.DAT`: Remote Desktop's (`MRU<n>`, `Servers`,
/// `LocalDevices`), PuTTY's (sessions, then host keys), WinSCP's (the same), the mapped drives
/// (`Network`, then `Map Network Drive MRU`) and the shares in `MountPoints2`, each list in its
/// order; with what keeps keys from being read.
#[must_use]
pub fn connections(hive: &Hive) -> (Vec<Connection>, Vec<String>) {
    let mut records = Vec::new();
    let mut problems = Vec::new();
    rdp(hive, &mut records, &mut problems);
    putty(hive, &mut records, &mut problems);
    winscp(hive, &mut records, &mut problems);
    network_drives(hive, &mut records, &mut problems);
    map_network_drive_mru(hive, &mut records, &mut problems);
    mount_points(hive, &mut records, &mut problems);
    (records, problems)
}

/// The subkeys of `key` at `path`, their problems added to `problems`.
fn subkeys_of<'h>(key: &Key<'h>, path: &str, problems: &mut Vec<String>) -> Vec<Key<'h>> {
    let (subkeys, why) = key.subkeys();
    problems.extend(why.into_iter().map(|w| format!("{path}: {w}")));
    subkeys
}

/// The values of `key` at `path`, their problems added to `problems`.
fn values_of<'h>(key: &Key<'h>, path: &str, problems: &mut Vec<String>) -> Vec<Value<'h>> {
    let (values, why) = key.values();
    problems.extend(why.into_iter().map(|w| format!("{path}: {w}")));
    values
}

// --- Remote Desktop ----------------------------------------------------------------------------

/// The computer and port of a Remote Desktop target as typed: `host`, `host:3390`, `[::1]:3390`;
/// an IPv6 address without brackets has no port.
#[must_use]
pub fn rdp_target(text: &str) -> (String, Option<u32>) {
    let port = |p: &str| {
        (!p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
            .then(|| p.parse::<u32>().ok())
            .flatten()
    };
    if let Some(rest) = text.strip_prefix('[')
        && let Some((host, after)) = rest.split_once(']')
    {
        return match after.strip_prefix(':').and_then(port) {
            Some(p) => (host.to_owned(), Some(p)),
            None if after.is_empty() => (host.to_owned(), None),
            None => (text.to_owned(), None),
        };
    }
    match text.split_once(':') {
        Some((host, p)) if !host.is_empty() && !p.contains(':') => match port(p) {
            Some(p) => (host.to_owned(), Some(p)),
            None => (text.to_owned(), None),
        },
        _ => (text.to_owned(), None),
    }
}

/// Remote Desktop's records.
fn rdp(hive: &Hive, records: &mut Vec<Connection>, problems: &mut Vec<String>) {
    let default_path = format!(r"{TERMINAL_SERVER_CLIENT}\Default");
    if let Some(default) = hive.key(&default_path) {
        let mut mru: Vec<(u32, Connection)> = Vec::new();
        for value in values_of(&default, &default_path, problems) {
            let name = value.name();
            let Some(n) = name
                .get(..3)
                .filter(|p| p.eq_ignore_ascii_case("MRU"))
                .and_then(|_| name[3..].parse::<u32>().ok())
                .filter(|n| n.to_string() == name[3..])
            else {
                continue;
            };
            let mut record = Connection::new(Kind::RdpMru, &default, default_path.clone());
            record.value_name = Some(name);
            record.mru_position = Some(n);
            record.replayed |= value.status() == Status::Replayed;
            if let Some(text) = record.value_text(&value).filter(|t| !t.is_empty()) {
                let (host, port) = rdp_target(&text);
                record.target = Some(host);
                record.port = port;
            }
            mru.push((n, record));
        }
        mru.sort_by_key(|(n, _)| *n);
        records.extend(mru.into_iter().map(|(_, r)| r));
    }
    let servers_path = format!(r"{TERMINAL_SERVER_CLIENT}\Servers");
    if let Some(servers) = hive.key(&servers_path) {
        for server in subkeys_of(&servers, &servers_path, problems) {
            let name = server.name();
            let mut record =
                Connection::new(Kind::RdpServer, &server, format!(r"{servers_path}\{name}"));
            let (host, port) = rdp_target(&name);
            record.target = Some(host);
            record.port = port;
            record.username = record.text(&server, "UsernameHint");
            if let Some(value) = server.value("CertHash") {
                record.replayed |= value.status() == Status::Replayed;
                let (bytes, why) = value.read_data();
                record
                    .problems
                    .extend(why.map(|w| format!("CertHash: {w}")));
                if !bytes.is_empty() {
                    record.detail("CertHash", hex(&bytes));
                }
            }
            records.push(record);
        }
    }
    let devices_path = format!(r"{TERMINAL_SERVER_CLIENT}\LocalDevices");
    if let Some(devices) = hive.key(&devices_path) {
        for value in values_of(&devices, &devices_path, problems) {
            let name = value.name();
            if name.is_empty() {
                continue;
            }
            let mut record = Connection::new(Kind::RdpLocalDevices, &devices, devices_path.clone());
            let (host, port) = rdp_target(&name);
            record.target = Some(host);
            record.port = port;
            record.value_name = Some(name);
            record.replayed |= value.status() == Status::Replayed;
            match number(&value) {
                Ok(flags) => record.detail("LocalDevices", format!("0x{flags:x}")),
                Err(why) => {
                    record.problems.push(why);
                    record.data_raw = Some(value.read_data().0);
                }
            }
            records.push(record);
        }
    }
}

// --- PuTTY and WinSCP ----------------------------------------------------------------------------

/// A session's name or a WinSCP string with its `%XX` escapes decoded; `None` when an escape is
/// malformed or the bytes aren't UTF-8 (then the name is kept as it is).
#[must_use]
pub fn unescape(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let pair = bytes.get(i + 1..i + 3)?;
            let digits = std::str::from_utf8(pair).ok()?;
            out.push(u8::from_str_radix(digits, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// PuTTY's `ProxyMethod` numbers.
fn putty_proxy(method: u32) -> String {
    let name = match method {
        1 => "socks4",
        2 => "socks5",
        3 => "http",
        4 => "telnet",
        5 => "local command",
        _ => return method.to_string(),
    };
    format!("{method} ({name})")
}

/// PuTTY's records: its sessions (with their places in `Jumplist`'s `Recent sessions`, and the
/// names only that list has), then its host keys.
fn putty(hive: &Hive, records: &mut Vec<Connection>, problems: &mut Vec<String>) {
    let recent = putty_recent_sessions(hive, problems);
    let mut listed = vec![false; recent.as_ref().map_or(0, |(names, _)| names.len())];
    let sessions_path = format!(r"{PUTTY}\Sessions");
    if let Some(sessions) = hive.key(&sessions_path) {
        for session in subkeys_of(&sessions, &sessions_path, problems) {
            let name = session.name();
            let mut record = Connection::new(
                Kind::PuttySession,
                &session,
                format!(r"{sessions_path}\{name}"),
            );
            let display = unescape(&name).unwrap_or_else(|| name.clone());
            if let Some((names, _)) = &recent
                && let Some(at) = names.iter().position(|n| *n == display)
            {
                record.mru_position = u32::try_from(at).ok();
                listed[at] = true;
            }
            record.session_name = Some(display);
            putty_session(&session, &mut record);
            records.push(record);
        }
    }
    if let Some((names, jumplist)) = recent {
        for (at, name) in names.iter().enumerate() {
            if listed[at] || names[..at].contains(name) {
                continue;
            }
            let mut record =
                Connection::new(Kind::PuttySession, &jumplist, format!(r"{PUTTY}\Jumplist"));
            record.value_name = Some("Recent sessions".to_owned());
            record.session_name = Some(name.clone());
            record.mru_position = u32::try_from(at).ok();
            record.detail(
                "Jumplist",
                "in Recent sessions, without a saved session of that name",
            );
            records.push(record);
        }
    }
    host_keys(
        hive,
        &format!(r"{PUTTY}\SshHostKeys"),
        Kind::PuttyHostKey,
        records,
        problems,
    );
}

/// PuTTY's `Jumplist\Recent sessions`: the session names, the most recent first, and the key.
fn putty_recent_sessions<'h>(
    hive: &'h Hive,
    problems: &mut Vec<String>,
) -> Option<(Vec<String>, Key<'h>)> {
    let path = format!(r"{PUTTY}\Jumplist");
    let key = hive.key(&path)?;
    let value = key.value("Recent sessions")?;
    let (bytes, why) = value.read_data();
    problems.extend(why.map(|w| format!(r"{path}\Recent sessions: {w}")));
    let crate::data::Data::MultiText { values, lossy } =
        crate::data::decode(value.data_type(), &bytes)
    else {
        problems.push(format!(
            r"{path}\Recent sessions: is {}, not REG_MULTI_SZ; its data: {}",
            value.value_type().name(),
            hex(&bytes)
        ));
        return None;
    };
    if lossy {
        problems.push(format!(
            r"{path}\Recent sessions: is not valid UTF-16: decoded lossily; its data: {}",
            hex(&bytes)
        ));
    }
    let names = values.into_iter().filter(|n| !n.is_empty()).collect();
    Some((names, key))
}

/// What a PuTTY session's key says.
fn putty_session(session: &Key, record: &mut Connection) {
    if let Some(host) = record.text(session, "HostName") {
        // `user@host` names the account too
        match host.rsplit_once('@') {
            Some((user, at)) if !user.is_empty() && !at.is_empty() => {
                record.target = Some(at.to_owned());
                record.username = Some(user.to_owned());
            }
            _ => record.target = Some(host),
        }
    }
    record.port = record.number(session, "PortNumber");
    if let Some(user) = record.text(session, "UserName") {
        record.username = Some(user);
    }
    record.protocol = record.text(session, "Protocol");
    for name in [
        "PublicKeyFile",
        "DetachedCertificate",
        "RemoteCommand",
        "PortForwardings",
        "SSHManualHostKeys",
    ] {
        if let Some(text) = record.text(session, name) {
            record.detail(name, text);
        }
    }
    let method = record.number(session, "ProxyMethod").unwrap_or(0);
    if method != 0 {
        record.detail("ProxyMethod", putty_proxy(method));
        if let Some(host) = record.text(session, "ProxyHost") {
            record.detail("ProxyHost", host);
        }
        if let Some(port) = record.number(session, "ProxyPort") {
            record.detail("ProxyPort", port.to_string());
        }
        if let Some(user) = record.text(session, "ProxyUsername") {
            record.detail("ProxyUsername", user);
        }
    }
    if record.number(session, "LogType").is_some_and(|t| t != 0)
        && let Some(file) = record.text(session, "LogFileName")
    {
        record.detail("LogFileName", file);
    }
    let proxy_password = record.text(session, "ProxyPassword").is_some();
    record.password_stored = Some(proxy_password);
    if proxy_password {
        record.detail("StoredPasswords", "ProxyPassword");
    }
}

/// WinSCP's `FSProtocol` numbers.
fn winscp_protocol(n: u32) -> String {
    match n {
        0 => "scp".to_owned(),
        1 => "sftp (scp fallback)".to_owned(),
        2 => "sftp".to_owned(),
        5 => "ftp".to_owned(),
        6 => "webdav".to_owned(),
        7 => "s3".to_owned(),
        _ => format!("FSProtocol {n}"),
    }
}

/// WinSCP's `Ftps` numbers.
fn winscp_ftps(n: u32) -> String {
    let name = match n {
        0 => "none",
        1 => "implicit",
        2 => "explicit SSL",
        3 => "explicit TLS",
        _ => return n.to_string(),
    };
    format!("{n} ({name})")
}

/// WinSCP's `ProxyMethod`s, in order.
const WINSCP_PROXIES: [&str; 7] = ["none", "socks4", "socks5", "http", "telnet", "cmd", "ssh"];

/// The values in which WinSCP keeps a session's passwords and passphrases.
const WINSCP_SECRETS: [&str; 10] = [
    "Password",
    "PasswordPlain",
    "ProxyPassword",
    "ProxyPasswordEnc",
    "TunnelPassword",
    "TunnelPasswordPlain",
    "TunnelPassphrase",
    "TunnelPassphrasePlain",
    "Passphrase",
    "PassphrasePlain",
];

/// The text of WinSCP's string value `name`, its escapes decoded.
fn winscp_text(record: &mut Connection, key: &Key, name: &str) -> Option<String> {
    record
        .text(key, name)
        .map(|text| unescape(&text).unwrap_or(text))
}

/// WinSCP's records: its sessions, then its host keys.
fn winscp(hive: &Hive, records: &mut Vec<Connection>, problems: &mut Vec<String>) {
    let sessions_path = format!(r"{WINSCP}\Sessions");
    if let Some(sessions) = hive.key(&sessions_path) {
        for session in subkeys_of(&sessions, &sessions_path, problems) {
            let name = session.name();
            let mut record = Connection::new(
                Kind::WinscpSession,
                &session,
                format!(r"{sessions_path}\{name}"),
            );
            record.session_name = Some(unescape(&name).unwrap_or_else(|| name.clone()));
            winscp_session(&session, &mut record);
            records.push(record);
        }
    }
    host_keys(
        hive,
        &format!(r"{WINSCP}\SshHostKeys"),
        Kind::WinscpHostKey,
        records,
        problems,
    );
}

/// What a WinSCP session's key says.
fn winscp_session(session: &Key, record: &mut Connection) {
    record.target = winscp_text(record, session, "HostName");
    record.port = record.number(session, "PortNumber");
    record.username = winscp_text(record, session, "UserName");
    record.protocol = record.number(session, "FSProtocol").map(winscp_protocol);
    if let Some(ftps) = record.number(session, "Ftps") {
        record.detail("Ftps", winscp_ftps(ftps));
    }
    for name in [
        "PublicKeyFile",
        "LocalDirectory",
        "RemoteDirectory",
        "TunnelHostName",
    ] {
        if let Some(text) = winscp_text(record, session, name) {
            record.detail(name, text);
        }
    }
    if let Some(port) = record.number(session, "TunnelPortNumber") {
        record.detail("TunnelPortNumber", port.to_string());
    }
    for name in ["TunnelUserName", "TunnelPublicKeyFile"] {
        if let Some(text) = winscp_text(record, session, name) {
            record.detail(name, text);
        }
    }
    // ProxyMethod: a number, or (newer versions) its name
    let method = match session.value("ProxyMethod") {
        Some(value) if value.value_type() == crate::data::ValueType::Dword => record
            .number(session, "ProxyMethod")
            .map(|n| match WINSCP_PROXIES.get(n as usize) {
                Some(name) => format!("{n} ({name})"),
                None => n.to_string(),
            }),
        Some(_) => winscp_text(record, session, "ProxyMethod"),
        None => None,
    };
    if let Some(method) = method.filter(|m| m != "0 (none)" && !m.eq_ignore_ascii_case("none")) {
        record.detail("ProxyMethod", method);
        if let Some(host) = winscp_text(record, session, "ProxyHost") {
            record.detail("ProxyHost", host);
        }
        if let Some(port) = record.number(session, "ProxyPort") {
            record.detail("ProxyPort", port.to_string());
        }
        if let Some(user) = winscp_text(record, session, "ProxyUsername") {
            record.detail("ProxyUsername", user);
        }
    }
    // stored passwords are present or not; their data is never read further
    let stored: Vec<&str> = WINSCP_SECRETS
        .into_iter()
        .filter(|name| {
            session.value(name).is_some_and(|value| {
                record.replayed |= value.status() == Status::Replayed;
                value.read_data().0.iter().any(|&b| b != 0)
            })
        })
        .collect();
    record.password_stored = Some(!stored.is_empty());
    if !stored.is_empty() {
        record.detail("StoredPasswords", stored.join(", "));
    }
}

// --- SSH host keys -----------------------------------------------------------------------------

/// The parts of an `SshHostKeys` value's name, `<type>@<port>:<host>`: the key's type, the port
/// and the host. `None` when the name isn't of that form.
#[must_use]
pub fn host_key_name(name: &str) -> Option<(&str, u32, &str)> {
    let (key_type, rest) = name.split_once('@')?;
    let (port, host) = rest.split_once(':')?;
    let port = port
        .bytes()
        .all(|b| b.is_ascii_digit())
        .then(|| port.parse().ok())
        .flatten()?;
    (!key_type.is_empty() && !host.is_empty()).then_some((key_type, port, host))
}

/// The records of the host keys in `path`.
fn host_keys(
    hive: &Hive,
    path: &str,
    kind: Kind,
    records: &mut Vec<Connection>,
    problems: &mut Vec<String>,
) {
    let Some(key) = hive.key(path) else {
        return;
    };
    for value in values_of(&key, path, problems) {
        let name = value.name();
        if name.is_empty() {
            continue;
        }
        let mut record = Connection::new(kind, &key, path.to_owned());
        record.replayed |= value.status() == Status::Replayed;
        match host_key_name(&name) {
            Some((key_type, port, host)) => {
                record.host_key_type = Some(key_type.to_owned());
                record.port = Some(port);
                record.target = Some(host.to_owned());
            }
            None => record
                .problems
                .push("its name isn't <type>@<port>:<host>".to_owned()),
        }
        if let Some(text) = record.value_text(&value) {
            if let Some(key_type) = &record.host_key_type {
                match host_key_fingerprint(key_type, &text) {
                    Ok(fingerprint) => record.host_key_fingerprint = Some(fingerprint),
                    Err(why) => record.problems.push(why),
                }
            }
            record.host_key = Some(text);
        }
        record.value_name = Some(name);
        records.push(record);
    }
}

/// A host key's fingerprint as OpenSSH shows it, `SHA256:` and the Base64 of its digest without
/// padding, from its type and numbers as PuTTY and WinSCP keep them ([`host_key_blob`]).
///
/// # Errors
/// As [`host_key_blob`].
pub fn host_key_fingerprint(key_type: &str, stored: &str) -> Result<String, String> {
    let blob = host_key_blob(key_type, stored)?;
    Ok(format!("SHA256:{}", base64_unpadded(&sha256(&blob))))
}

/// A host key's SSH wire encoding (RFC 4253, 5656, 8709), from its type and numbers as PuTTY and
/// WinSCP keep them: `rsa2` `0x<e>,0x<n>`; `dss` `0x<p>,0x<q>,0x<g>,0x<y>`;
/// `ecdsa-sha2-nistp256` (384, 521) `<curve>,0x<x>,0x<y>` (`nistp256`, …); `ssh-ed25519` and `ssh-ed448`
/// `0x<x>,0x<y>`, the point whose `y` and the parity of `x` the encoding keeps.
///
/// # Errors
/// When the type is unknown (or `rsa`, an SSH-1 key), or the numbers aren't what it needs.
pub fn host_key_blob(key_type: &str, stored: &str) -> Result<Vec<u8>, String> {
    let parts: Vec<&str> = stored.split(',').collect();
    let numbers = |want: usize| -> Result<Vec<Vec<u8>>, String> {
        if parts.len() != want {
            return Err(format!(
                "a {key_type} key has {want} numbers, not {}",
                parts.len()
            ));
        }
        parts.iter().map(|p| big_number(p)).collect()
    };
    let mut blob = Vec::new();
    match key_type {
        "rsa2" | "dss" => {
            let (name, count) = if key_type == "rsa2" {
                ("ssh-rsa", 2)
            } else {
                ("ssh-dss", 4)
            };
            put_string(&mut blob, name.as_bytes());
            for n in numbers(count)? {
                put_mpint(&mut blob, &n);
            }
        }
        "ssh-ed25519" | "ssh-ed448" => {
            let size = if key_type == "ssh-ed25519" { 32 } else { 57 };
            let [x, y]: [Vec<u8>; 2] = numbers(2)?
                .try_into()
                .map_err(|_| "two numbers expected".to_owned())?;
            let point = edwards_point(&x, &y, size)
                .ok_or_else(|| format!("its y is too large for a {key_type} key"))?;
            put_string(&mut blob, key_type.as_bytes());
            put_string(&mut blob, &point);
        }
        "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
            let curve = &key_type["ecdsa-sha2-".len()..];
            let size = match curve {
                "nistp256" => 32,
                "nistp384" => 48,
                _ => 66,
            };
            // the curve's name, then the point
            let coordinates = match parts.as_slice() {
                [name, x, y] if name.eq_ignore_ascii_case(curve) => [*x, *y],
                [name, _, _] => {
                    return Err(format!("its curve is {name:?}, not {curve}"));
                }
                _ => {
                    return Err(format!(
                        "a {key_type} key has its curve and 2 numbers, not {} parts",
                        parts.len()
                    ));
                }
            };
            let mut point = vec![4u8];
            for c in coordinates {
                let n = big_number(c)?;
                if n.len() > size {
                    return Err(format!("a coordinate is too large for {curve}"));
                }
                point.resize(point.len() + size - n.len(), 0);
                point.extend(n);
            }
            put_string(&mut blob, key_type.as_bytes());
            put_string(&mut blob, curve.as_bytes());
            put_string(&mut blob, &point);
        }
        "rsa" => {
            return Err("an SSH-1 RSA key: it has no SHA-256 fingerprint".to_owned());
        }
        _ => return Err(format!("unknown host key type {key_type:?}")),
    }
    Ok(blob)
}

/// A number written in hex (`0x1f…`) as big-endian bytes without leading zeros (empty for 0).
fn big_number(text: &str) -> Result<Vec<u8>, String> {
    let text = text.trim();
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{text:?} is not a number in hex"));
    }
    let nibble = |b: u8| match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        _ => b - b'A' + 10,
    };
    let digits = digits.as_bytes();
    let mut bytes = Vec::with_capacity(digits.len() / 2 + 1);
    let (first, rest) = digits.split_at(digits.len() % 2);
    if let [d] = first {
        bytes.push(nibble(*d));
    }
    for pair in rest.as_chunks::<2>().0 {
        bytes.push(nibble(pair[0]) << 4 | nibble(pair[1]));
    }
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    bytes.drain(..zeros);
    Ok(bytes)
}

/// An SSH `string`: its length, then its bytes.
fn put_string(blob: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    blob.extend(len.to_be_bytes());
    blob.extend(bytes);
}

/// An SSH `mpint` of a non-negative number's big-endian bytes (without leading zeros).
fn put_mpint(blob: &mut Vec<u8>, n: &[u8]) {
    if n.first().is_some_and(|&b| b & 0x80 != 0) {
        let mut padded = vec![0];
        padded.extend(n);
        put_string(blob, &padded);
    } else {
        put_string(blob, n);
    }
}

/// An Edwards point encoded (RFC 8032): `y` in `size` little-endian bytes, the top bit of the
/// last one the parity of `x`. `None` when `y` doesn't fit.
fn edwards_point(x: &[u8], y: &[u8], size: usize) -> Option<Vec<u8>> {
    let mut point: Vec<u8> = y.iter().rev().copied().collect();
    if point.len() > size {
        return None;
    }
    point.resize(size, 0);
    if point[size - 1] & 0x80 != 0 {
        return None;
    }
    if x.last().is_some_and(|b| b & 1 == 1) {
        point[size - 1] |= 0x80;
    }
    Some(point)
}

// --- mapped drives and shares ------------------------------------------------------------------

/// The drives mapped to be restored at sign-in.
fn network_drives(hive: &Hive, records: &mut Vec<Connection>, problems: &mut Vec<String>) {
    let Some(network) = hive.key(NETWORK) else {
        return;
    };
    for drive in subkeys_of(&network, NETWORK, problems) {
        let letter = drive.name();
        let mut record =
            Connection::new(Kind::NetworkDrive, &drive, format!(r"{NETWORK}\{letter}"));
        record.drive_letter = Some(letter);
        record.target = record.text(&drive, "RemotePath");
        // a DWORD 0 when the drive was mapped with the user's own account
        if let Some(value) = drive.value("UserName") {
            if value.value_type() == crate::data::ValueType::Dword {
                record.replayed |= value.status() == Status::Replayed;
            } else {
                record.username = record.text(&drive, "UserName");
            }
        }
        record.protocol = record.text(&drive, "ProviderName");
        if let Some(kind) = record.number(&drive, "ConnectionType") {
            let name = match kind {
                1 => " (disk)",
                2 => " (printer)",
                _ => "",
            };
            record.detail("ConnectionType", format!("{kind}{name}"));
        }
        if let Some(provider) = record.number(&drive, "ProviderType") {
            record.detail("ProviderType", format!("0x{provider:x}"));
        }
        records.push(record);
    }
}

/// The letters of an `MRUList`, the most recent first, and the problems: letters listed twice
/// (kept once).
#[must_use]
pub fn mru_list(text: &str) -> (Vec<char>, Vec<String>) {
    let mut letters = Vec::new();
    let mut problems = Vec::new();
    for c in text.chars() {
        if letters.contains(&c) {
            problems.push(format!("MRUList: {c} is listed twice"));
        } else {
            letters.push(c);
        }
    }
    (letters, problems)
}

/// The paths typed into *Map Network Drive*, in the order of `MRUList`, then the values it
/// doesn't list.
fn map_network_drive_mru(hive: &Hive, records: &mut Vec<Connection>, problems: &mut Vec<String>) {
    let path = MAP_NETWORK_DRIVE_MRU;
    let Some(key) = hive.key(path) else {
        return;
    };
    let values = values_of(&key, path, problems);
    let mut order = Vec::new();
    let mut list_replayed = false;
    match values
        .iter()
        .find(|v| v.name().eq_ignore_ascii_case("MRUList"))
    {
        Some(list) => {
            list_replayed = list.status() == Status::Replayed;
            match string(list) {
                (Some(text), why) => {
                    problems.extend(why.map(|w| format!(r"{path}\MRUList: {w}")));
                    let (letters, why) = mru_list(&text);
                    problems.extend(why.into_iter().map(|w| format!("{path}: {w}")));
                    order = letters;
                }
                (None, why) => problems.extend(why.map(|w| {
                    format!(
                        r"{path}\MRUList: {w}; its data: {}",
                        hex(&list.read_data().0)
                    )
                })),
            }
        }
        None if !values.is_empty() => {
            problems.push(format!("{path}: it has no MRUList: its order is unknown"));
        }
        None => {}
    }
    let entries: Vec<&Value> = values
        .iter()
        .filter(|v| !v.name().eq_ignore_ascii_case("MRUList"))
        .collect();
    let mut used = vec![false; entries.len()];
    let record_of = |value: &Value, position: Option<u32>| {
        let mut record = Connection::new(Kind::MapNetworkDriveMru, &key, path.to_owned());
        record.value_name = Some(value.name());
        record.mru_position = position;
        record.replayed |= list_replayed || value.status() == Status::Replayed;
        record.target = record.value_text(value).filter(|t| !t.is_empty());
        record
    };
    for (position, letter) in order.iter().enumerate() {
        let position = u32::try_from(position).ok();
        let name = letter.to_string();
        if let Some(at) = entries.iter().position(|v| v.name() == name) {
            used[at] = true;
            records.push(record_of(entries[at], position));
        } else {
            let mut record = Connection::new(Kind::MapNetworkDriveMru, &key, path.to_owned());
            record.value_name = Some(name.clone());
            record.mru_position = position;
            record.replayed |= list_replayed;
            record
                .problems
                .push(format!("MRUList lists value {name}, which is not there"));
            records.push(record);
        }
    }
    for (at, value) in entries.iter().enumerate() {
        if !used[at] {
            let mut record = record_of(value, None);
            record
                .problems
                .insert(0, "MRUList doesn't list it".to_owned());
            records.push(record);
        }
    }
}

/// The share a `MountPoints2` key's name gives: `\\server\share\folder` for
/// `##server#share#folder`; `None` for a volume's or a drive's key.
#[must_use]
pub fn mount_point_share(name: &str) -> Option<String> {
    let rest = name.strip_prefix("##").filter(|r| !r.is_empty())?;
    Some(format!(r"\\{}", rest.replace('#', r"\")))
}

/// The shares Explorer mounted, from `MountPoints2`'s `##server#share` keys.
fn mount_points(hive: &Hive, records: &mut Vec<Connection>, problems: &mut Vec<String>) {
    let Some(key) = hive.key(MOUNT_POINTS2) else {
        return;
    };
    for point in subkeys_of(&key, MOUNT_POINTS2, problems) {
        let name = point.name();
        let Some(share) = mount_point_share(&name) else {
            continue;
        };
        let mut record =
            Connection::new(Kind::MountPoint, &point, format!(r"{MOUNT_POINTS2}\{name}"));
        record.target = Some(share);
        for (value, detail) in [
            ("_LabelFromReg", "Label"),
            ("_LabelFromDesktopINI", "LabelFromDesktopINI"),
            ("_CommentFromDesktopINI", "CommentFromDesktopINI"),
        ] {
            if let Some(text) = record.text(&point, value) {
                record.detail(detail, text);
            }
        }
        records.push(record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdp_targets() {
        let t = |s: &str| rdp_target(s);
        assert_eq!(t("server01"), ("server01".into(), None));
        assert_eq!(
            t("10.150.16.30:63389"),
            ("10.150.16.30".into(), Some(63389))
        );
        assert_eq!(t("[fe80::1]:3390"), ("fe80::1".into(), Some(3390)));
        assert_eq!(t("[fe80::1]"), ("fe80::1".into(), None));
        assert_eq!(t("fe80::1"), ("fe80::1".into(), None));
        assert_eq!(t("host:"), ("host:".into(), None));
        assert_eq!(t("host:99999999999"), ("host:99999999999".into(), None));
        assert_eq!(t(":3389"), (":3389".into(), None));
        assert_eq!(t("[x]y"), ("[x]y".into(), None));
    }

    #[test]
    fn escapes() {
        assert_eq!(
            unescape("Default%20Settings").as_deref(),
            Some("Default Settings")
        );
        assert_eq!(
            unescape("C:%5CUsers%5Calice").as_deref(),
            Some(r"C:\Users\alice")
        );
        assert_eq!(unescape("caf%C3%A9").as_deref(), Some("café"));
        assert_eq!(unescape("plain").as_deref(), Some("plain"));
        // malformed or not UTF-8: kept as it is by the caller
        assert_eq!(unescape("bad%2"), None);
        assert_eq!(unescape("bad%zz"), None);
        assert_eq!(unescape("latin%E9"), None);
    }

    #[test]
    fn host_key_names() {
        assert_eq!(
            host_key_name("rsa2@22:10.1.200.20"),
            Some(("rsa2", 22, "10.1.200.20"))
        );
        assert_eq!(
            host_key_name("ssh-ed25519@2222:fe80::1"),
            Some(("ssh-ed25519", 2222, "fe80::1"))
        );
        assert_eq!(host_key_name("rsa2@x:host"), None);
        assert_eq!(host_key_name("rsa2@22:"), None);
        assert_eq!(host_key_name("@22:host"), None);
        assert_eq!(host_key_name("rsa2:22@host"), None);
    }

    #[test]
    fn big_numbers() {
        assert_eq!(big_number("0x23"), Ok(vec![0x23]));
        assert_eq!(big_number("0x123"), Ok(vec![0x01, 0x23]));
        assert_eq!(big_number("0X00ff"), Ok(vec![0xff]));
        assert_eq!(big_number("0x0"), Ok(vec![]));
        assert!(big_number("0x").is_err());
        assert!(big_number("0xg1").is_err());
        assert!(big_number("0x1é").is_err());
        let mut blob = Vec::new();
        put_mpint(&mut blob, &[0x80, 1]);
        put_mpint(&mut blob, &[]);
        assert_eq!(blob, [0, 0, 0, 3, 0, 0x80, 1, 0, 0, 0, 0]);
    }

    #[test]
    fn edwards_points() {
        // y = 2 with x odd and even; a y that doesn't fit
        let mut odd = vec![2u8];
        odd.resize(32, 0);
        odd[31] = 0x80;
        assert_eq!(edwards_point(&[3], &[2], 32), Some(odd));
        assert_eq!(edwards_point(&[2], &[2], 32).map(|p| p[31]), Some(0));
        assert_eq!(edwards_point(&[1], &[0x80; 32], 32), None);
        assert_eq!(edwards_point(&[1], &[1; 33], 32), None);
    }

    #[test]
    fn host_key_errors() {
        assert_eq!(
            host_key_fingerprint("rsa2", "0x23"),
            Err("a rsa2 key has 2 numbers, not 1".to_owned())
        );
        assert_eq!(
            host_key_fingerprint("ssh-ed25519", "0x1,zz"),
            Err("\"zz\" is not a number in hex".to_owned())
        );
        assert_eq!(
            host_key_fingerprint("ecdsa-sha2-nistp256", "nistp384,0x1,0x2"),
            Err("its curve is \"nistp384\", not nistp256".to_owned())
        );
        assert!(
            host_key_fingerprint(
                "ecdsa-sha2-nistp256",
                &format!("nistp256,0x{},0x1", "f".repeat(66))
            )
            .is_err()
        );
        assert_eq!(
            host_key_fingerprint("rsa", "0x23,0x1"),
            Err("an SSH-1 RSA key: it has no SHA-256 fingerprint".to_owned())
        );
        assert_eq!(
            host_key_fingerprint("ssh-unknown", "0x1"),
            Err("unknown host key type \"ssh-unknown\"".to_owned())
        );
    }

    #[test]
    fn mount_point_shares() {
        assert_eq!(
            mount_point_share("##server#share#folder").as_deref(),
            Some(r"\\server\share\folder")
        );
        assert_eq!(
            mount_point_share("##live.sysinternals.com#DavWWWRoot").as_deref(),
            Some(r"\\live.sysinternals.com\DavWWWRoot")
        );
        assert_eq!(
            mount_point_share("{5c1a2f4e-0000-0000-0000-100000000000}"),
            None
        );
        assert_eq!(mount_point_share("C"), None);
        assert_eq!(mount_point_share("##"), None);
        assert_eq!(mru_list("bab").0, ['b', 'a']);
        assert_eq!(mru_list("bab").1, ["MRUList: b is listed twice"]);
        assert_eq!(Kind::MountPoint.client().name(), "network_share");
        assert_eq!(Kind::WinscpHostKey.name(), "winscp_host_key");
    }
}
