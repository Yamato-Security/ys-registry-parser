//! Installed software: what Windows lists as installed, machine-wide in `SOFTWARE`
//! ([`software`]) and for one user in `NTUSER.DAT` ([`ntuser`]). One [`Program`] per key:
//!
//! - **`Uninstall`** (`Microsoft\Windows\CurrentVersion\Uninstall\*`, with `Wow6432Node`'s
//!   copy): the programs Settings and *Programs and Features* list, each with its name,
//!   version, publisher, install date (`YYYYMMDD`), folders, uninstall commands, size and
//!   whether it is hidden (`SystemComponent`).
//! - **Windows Installer products** (`SOFTWARE`'s `Classes\Installer\Products`, a user's
//!   `Software\Microsoft\Installer\Products`): each product's key is its product code
//!   *packed* ([`unpack_guid`]); `ProductName`, `PackageCode`, `Version` ([`msi_version`]) and
//!   its `SourceList`: the package's file name and the folder it was last installed from.
//! - **App Paths** (`Microsoft\Windows\CurrentVersion\App Paths\*`): the programs Windows starts
//!   by name (`Win+R`, `start`): the program's path (the default value) and the folder added to
//!   its `PATH` (`Path`).
//! - **WSL distributions** (a user's `Software\Microsoft\Windows\CurrentVersion\Lxss\{GUID}`):
//!   `DistributionName`, `BasePath` (where its disk or files are), and the WSL version its
//!   `Flags` say (`0x8`: WSL 2).
//! - **Packaged apps** (`SOFTWARE`'s `Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore`):
//!   the packages provisioned for every user (`Applications`), Windows' own (`InboxApplications`),
//!   staged, deprovisioned (removed for new users), and each user's (`<SID>`, and
//!   `EndOfLife\<SID>`: removed for that user), each named by its package full name
//!   ([`package_name`]).
//!
//! A key's last-write time is kept beside its install date: an update can change one without
//! the other.

use crate::data::ValueType;
use crate::hive::{Hive, Key, Status, Value};
use crate::system::{number, string};

/// Where Windows lists installed software, under `SOFTWARE`'s root and `NTUSER.DAT`'s
/// `Software`.
const CURRENT_VERSION: &str = r"Microsoft\Windows\CurrentVersion";
/// The packaged apps' store, under `SOFTWARE`'s root.
pub const APPX_STORE: &str = r"Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore";
/// The lists of the packaged apps' store that hold machine-wide packages.
const APPX_LISTS: [&str; 4] = [
    "Applications",
    "InboxApplications",
    "Staged",
    "Deprovisioned",
];
/// `Uninstall` values kept in [`Program::details`].
const UNINSTALL_DETAILS: [&str; 5] = [
    "DisplayIcon",
    "ModifyPath",
    "ParentKeyName",
    "ReleaseType",
    "Inno Setup: User",
];
/// `Flags` of a WSL distribution: it runs in the WSL 2 virtual machine.
const WSL_VM_MODE: u32 = 0x8;

/// Where a [`Program`] is listed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProgramSource {
    /// `Uninstall\*`: Settings' and *Programs and Features*' list.
    Uninstall,
    /// `Installer\Products\*`: a Windows Installer product.
    MsiProduct,
    /// `App Paths\*`: a program Windows starts by name.
    AppPath,
    /// `Lxss\{GUID}`: a WSL distribution.
    Wsl,
    /// `Appx\AppxAllUserStore`: a packaged app.
    Package,
}

impl ProgramSource {
    /// `uninstall`, `msi_product`, `app_path`, `wsl` or `package`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            ProgramSource::Uninstall => "uninstall",
            ProgramSource::MsiProduct => "msi_product",
            ProgramSource::AppPath => "app_path",
            ProgramSource::Wsl => "wsl",
            ProgramSource::Package => "package",
        }
    }
}

/// For whom a [`Program`] is installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    /// Every user: `SOFTWARE`'s lists.
    Machine,
    /// One user: `NTUSER.DAT`'s lists, and a user's packages in `SOFTWARE`.
    User,
}

impl Scope {
    /// `machine` or `user`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Scope::Machine => "machine",
            Scope::User => "user",
        }
    }
}

/// One program, product, distribution or package Windows lists as installed: a key of one of
/// the lists. Empty strings are left out (`None`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    /// The list.
    pub source: ProgramSource,
    /// For every user or one.
    pub scope: Scope,
    /// Its key, under the hive's root, with the names as they are written.
    pub key_path: String,
    /// When its key was last written (FILETIME).
    pub key_last_written: u64,
    /// `DisplayName`, `ProductName`, the program's file name (App Paths), `DistributionName`,
    /// or the package's name.
    pub name: Option<String>,
    /// `DisplayVersion`, the product's `Version` ([`msi_version`]), the WSL version (`1` or
    /// `2`), or the package's version.
    pub version: Option<String>,
    /// `Publisher`.
    pub publisher: Option<String>,
    /// `InstallDate` as a date (`2022-02-08`), when it is a date written `YYYYMMDD`.
    pub install_date: Option<String>,
    /// `InstallDate` as written, when it isn't a date written `YYYYMMDD`.
    pub install_date_raw: Option<String>,
    /// `InstallLocation`, an App Path's `Path`, a distribution's `BasePath`, or a package's
    /// `Path` (its folder, or its manifest).
    pub install_location: Option<String>,
    /// `InstallSource`, or the folder a Windows Installer product was last installed from.
    pub install_source: Option<String>,
    /// An App Path's program: its default value.
    pub program: Option<String>,
    /// `UninstallString`.
    pub uninstall_command: Option<String>,
    /// `QuietUninstallString`.
    pub quiet_uninstall_command: Option<String>,
    /// `EstimatedSize`, in KiB.
    pub size_kb: Option<u32>,
    /// `SystemComponent` (not 0: hidden from *Programs and Features*).
    pub system_component: Option<bool>,
    /// `WindowsInstaller` (not 0: installed by Windows Installer).
    pub windows_installer: Option<bool>,
    /// The Windows Installer product code (`{GUID}`): an `Uninstall` key's name when it is one,
    /// a product's key name unpacked.
    pub product_code: Option<String>,
    /// `x86` for a key under `Wow6432Node` (32-bit programs on 64-bit Windows), a package's
    /// architecture (`x64`, `x86`, `arm64`, `neutral`, …); `None` for the system's own.
    pub architecture: Option<String>,
    /// Whether its key is under `Wow6432Node`.
    pub wow64: bool,
    /// The user a package in `SOFTWARE` is installed for (the `<SID>` key it is under).
    pub user_sid: Option<String>,
    /// More, as names and values: an `Uninstall` entry's `DisplayIcon`, `ModifyPath`,
    /// `ParentKeyName`, `ReleaseType` and `Inno Setup: User`; a product's `PackageCode` and
    /// `PackageName`; a distribution's `Flags`, `State`, `DefaultUid`, `Version` (its file
    /// system's), `PackageFamilyName` and whether it is the default; a package's `List` (the
    /// store's list it is in), `ResourceId` and `PublisherId`.
    pub details: Vec<(String, String)>,
    /// The bytes of values that are not what their names say (a number that isn't a
    /// `REG_DWORD`, text that isn't valid UTF-16), by value name.
    pub data_raw: Vec<(String, Vec<u8>)>,
    /// Whether the transaction logs' replay wrote its key or one of its values.
    pub replayed: bool,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

impl Program {
    fn new(source: ProgramSource, scope: Scope, key: &Key, key_path: String) -> Self {
        Program {
            source,
            scope,
            key_path,
            key_last_written: key.last_written(),
            name: None,
            version: None,
            publisher: None,
            install_date: None,
            install_date_raw: None,
            install_location: None,
            install_source: None,
            program: None,
            uninstall_command: None,
            quiet_uninstall_command: None,
            size_kb: None,
            system_component: None,
            windows_installer: None,
            product_code: None,
            architecture: None,
            wow64: false,
            user_sid: None,
            details: Vec::new(),
            data_raw: Vec::new(),
            replayed: key.status() == Status::Replayed,
            problems: Vec::new(),
        }
    }

    /// The value named `name` of `values` (in any case), noting whether the logs wrote it.
    fn find<'v, 'h>(&mut self, values: &'v [Value<'h>], name: &str) -> Option<&'v Value<'h>> {
        let value = values
            .iter()
            .find(|v| v.name().eq_ignore_ascii_case(name))?;
        self.replayed |= value.status() == Status::Replayed;
        Some(value)
    }

    /// Keep the bytes of `value`, which aren't what its name says.
    fn keep(&mut self, value: &Value, why: &str) {
        self.problems.push(format!("{}: {why}", value.name()));
        let bytes = value.read_data().0;
        if !bytes.is_empty() {
            self.data_raw.push((value.name(), bytes));
        }
    }

    /// The text of value `name`; `None` when it is empty or not there.
    fn text(&mut self, values: &[Value], name: &str) -> Option<String> {
        let value = self.find(values, name)?;
        let (text, why) = string(value);
        if let Some(why) = why {
            self.keep(value, &why);
        }
        text.filter(|t| !t.is_empty())
    }

    /// The number of `REG_DWORD` value `name`; `None` when it is empty (no data, or an empty
    /// string) or not there.
    fn dword(&mut self, values: &[Value], name: &str) -> Option<u32> {
        let value = self.find(values, name)?;
        let empty_text = matches!(value.value_type(), ValueType::Sz | ValueType::ExpandSz)
            && string(value).0.is_some_and(|t| t.is_empty());
        if value.size() == 0 || empty_text {
            return None;
        }
        match number(value) {
            Ok(n) => Some(n),
            Err(why) => {
                self.keep(value, &why);
                None
            }
        }
    }

    fn detail(&mut self, name: &str, value: Option<String>) {
        if let Some(value) = value {
            self.details.push((name.to_owned(), value));
        }
    }
}

/// The installed software `SOFTWARE` lists, and what kept parts of it from being read:
/// `Uninstall` (then `Wow6432Node`'s), Windows Installer products, App Paths (then
/// `Wow6432Node`'s), and packaged apps.
#[must_use]
pub fn software(hive: &Hive) -> (Vec<Program>, Vec<String>) {
    let mut f = Found::new(hive);
    for (prefix, wow64) in [("", false), (r"Wow6432Node\", true)] {
        let path = format!(r"{prefix}{CURRENT_VERSION}\Uninstall");
        f.each(&path, |key, at, values| {
            uninstall(key, at, values, Scope::Machine, wow64)
        });
    }
    f.each(r"Classes\Installer\Products", |key, at, values| {
        msi_product(key, at, values, Scope::Machine)
    });
    for (prefix, wow64) in [("", false), (r"Wow6432Node\", true)] {
        let path = format!(r"{prefix}{CURRENT_VERSION}\App Paths");
        f.each(&path, |key, at, values| {
            app_path(key, at, values, Scope::Machine, wow64)
        });
    }
    packages(&mut f);
    f.done()
}

/// The installed software a user's `NTUSER.DAT` lists, and what kept parts of it from being
/// read: `Uninstall` (and `Wow6432Node`'s, when it has one), Windows Installer products, App
/// Paths, and WSL distributions.
#[must_use]
pub fn ntuser(hive: &Hive) -> (Vec<Program>, Vec<String>) {
    let mut f = Found::new(hive);
    for (prefix, wow64) in [("", false), (r"Wow6432Node\", true)] {
        let path = format!(r"Software\{prefix}{CURRENT_VERSION}\Uninstall");
        f.each(&path, |key, at, values| {
            uninstall(key, at, values, Scope::User, wow64)
        });
    }
    f.each(
        r"Software\Microsoft\Installer\Products",
        |key, at, values| msi_product(key, at, values, Scope::User),
    );
    f.each(
        &format!(r"Software\{CURRENT_VERSION}\App Paths"),
        |key, at, values| app_path(key, at, values, Scope::User, false),
    );
    wsl(&mut f);
    f.done()
}

/// The records found so far, and what kept parts of the hive from being read.
struct Found<'h> {
    hive: &'h Hive,
    records: Vec<Program>,
    problems: Vec<String>,
}

impl<'h> Found<'h> {
    fn new(hive: &'h Hive) -> Self {
        Found {
            hive,
            records: Vec::new(),
            problems: Vec::new(),
        }
    }

    /// The key at `path` (names in any case), with its path as written.
    fn key(&self, path: &str) -> Option<(Key<'h>, String)> {
        let mut key = self.hive.root()?;
        let mut written = String::new();
        for part in path.split('\\').filter(|p| !p.is_empty()) {
            key = key.subkey(part)?;
            if !written.is_empty() {
                written.push('\\');
            }
            written.push_str(&key.name());
        }
        Some((key, written))
    }

    /// The subkeys of `key` (at `path`) with their paths.
    fn subkeys(&mut self, key: &Key<'h>, path: &str) -> Vec<(Key<'h>, String)> {
        let (keys, why) = key.subkeys();
        self.problems
            .extend(why.into_iter().map(|w| format!(r"{path}: {w}")));
        keys.into_iter()
            .map(|k| {
                let p = format!(r"{path}\{}", k.name());
                (k, p)
            })
            .collect()
    }

    /// The values of `key` (at `path`).
    fn values(&mut self, key: &Key<'h>, path: &str) -> Vec<Value<'h>> {
        let (values, why) = key.values();
        self.problems
            .extend(why.into_iter().map(|w| format!(r"{path}: {w}")));
        values
    }

    /// A record of each subkey of the key at `path`, made by `make` from the subkey, its path
    /// and its values.
    fn each(&mut self, path: &str, make: impl Fn(&Key<'h>, &str, &[Value<'h>]) -> Program) {
        let Some((list, at)) = self.key(path) else {
            return;
        };
        for (key, key_path) in self.subkeys(&list, &at) {
            let values = self.values(&key, &key_path);
            self.records.push(make(&key, &key_path, &values));
        }
    }

    fn done(self) -> (Vec<Program>, Vec<String>) {
        (self.records, self.problems)
    }
}

/// Whether `name` is a GUID in braces: `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
fn is_braced_guid(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() == 38
        && b[0] == b'{'
        && b[37] == b'}'
        && b[1..37].iter().enumerate().all(|(i, &c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

/// An `Uninstall` entry: the key `key` at `at`, with its `values`.
fn uninstall(key: &Key, at: &str, values: &[Value], scope: Scope, wow64: bool) -> Program {
    let mut p = Program::new(ProgramSource::Uninstall, scope, key, at.to_owned());
    p.wow64 = wow64;
    p.architecture = wow64.then(|| "x86".to_owned());
    let name = key.name();
    p.product_code = is_braced_guid(&name).then(|| name.to_uppercase());
    p.name = p.text(values, "DisplayName");
    p.version = p.text(values, "DisplayVersion");
    p.publisher = p.text(values, "Publisher");
    if let Some(date) = p.text(values, "InstallDate") {
        match install_date(&date) {
            Some(iso) => p.install_date = Some(iso),
            None => p.install_date_raw = Some(date),
        }
    }
    p.install_location = p.text(values, "InstallLocation");
    p.install_source = p.text(values, "InstallSource");
    p.uninstall_command = p.text(values, "UninstallString");
    p.quiet_uninstall_command = p.text(values, "QuietUninstallString");
    p.size_kb = p.dword(values, "EstimatedSize");
    p.system_component = p.dword(values, "SystemComponent").map(|n| n != 0);
    p.windows_installer = p.dword(values, "WindowsInstaller").map(|n| n != 0);
    for detail in UNINSTALL_DETAILS {
        let text = p.text(values, detail);
        p.detail(detail, text);
    }
    p
}

/// A Windows Installer product: the key `key` at `at` (its name, the product code packed),
/// with its `values` and its `SourceList`.
fn msi_product(key: &Key, at: &str, values: &[Value], scope: Scope) -> Program {
    let mut p = Program::new(ProgramSource::MsiProduct, scope, key, at.to_owned());
    p.product_code = unpack_guid(&key.name());
    p.name = p.text(values, "ProductName");
    p.version = p.dword(values, "Version").map(msi_version);
    let package_code = p.text(values, "PackageCode");
    let unpacked = package_code.as_deref().and_then(unpack_guid);
    p.detail("PackageCode", unpacked.or(package_code));
    if let Some(list) = key.subkey("SourceList") {
        let (list_values, why) = list.values();
        let list_path = format!(r"{at}\{}", list.name());
        p.problems
            .extend(why.into_iter().map(|w| format!(r"{list_path}: {w}")));
        p.replayed |= list.status() == Status::Replayed;
        let package = p.text(&list_values, "PackageName");
        p.detail("PackageName", package);
        if let Some(last) = p.text(&list_values, "LastUsedSource") {
            match last_used_source(&last) {
                Some(folder) => p.install_source = Some(folder.to_owned()),
                None => p.problems.push(format!(
                    "LastUsedSource: {last:?} is not <type>;<index>;<source>"
                )),
            }
        }
    }
    p
}

/// The folder of a `SourceList`'s `LastUsedSource`: `<type>;<index>;<source>` (type `n`
/// a folder, `u` a URL, `m` media), its source; `None` when it isn't written so.
fn last_used_source(text: &str) -> Option<&str> {
    let mut parts = text.splitn(3, ';');
    let kind = parts.next()?;
    let index = parts.next()?;
    let source = parts.next()?;
    (kind.len() == 1
        && kind.bytes().all(|b| b.is_ascii_alphabetic())
        && !index.is_empty()
        && index.bytes().all(|b| b.is_ascii_digit())
        && !source.is_empty())
    .then_some(source)
}

/// An App Path: the key `key` at `at` (its name, the program's file name), with its `values`.
fn app_path(key: &Key, at: &str, values: &[Value], scope: Scope, wow64: bool) -> Program {
    let mut p = Program::new(ProgramSource::AppPath, scope, key, at.to_owned());
    p.wow64 = wow64;
    p.architecture = wow64.then(|| "x86".to_owned());
    p.name = Some(key.name()).filter(|n| !n.is_empty());
    p.program = p.text(values, "");
    p.install_location = p.text(values, "Path");
    p
}

/// A user's WSL distributions: `Lxss`'s `{GUID}` keys.
fn wsl(f: &mut Found) {
    let Some((lxss, at)) = f.key(&format!(r"Software\{CURRENT_VERSION}\Lxss")) else {
        return;
    };
    let lxss_values = f.values(&lxss, &at);
    let default = lxss_values
        .iter()
        .find(|v| v.name().eq_ignore_ascii_case("DefaultDistribution"))
        .and_then(|v| string(v).0);
    for (key, key_path) in f.subkeys(&lxss, &at) {
        let name = key.name();
        if !is_braced_guid(&name) {
            continue;
        }
        let values = f.values(&key, &key_path);
        let mut p = Program::new(ProgramSource::Wsl, Scope::User, &key, key_path);
        p.name = p.text(&values, "DistributionName");
        p.install_location = p.text(&values, "BasePath");
        let flags = p.dword(&values, "Flags");
        p.version = flags.map(|f| if f & WSL_VM_MODE == 0 { "1" } else { "2" }.to_owned());
        p.detail("Flags", flags.map(|f| format!("0x{f:x}")));
        for detail in ["State", "DefaultUid", "Version"] {
            let n = p.dword(&values, detail);
            p.detail(detail, n.map(|n| n.to_string()));
        }
        let family = p.text(&values, "PackageFamilyName");
        p.detail("PackageFamilyName", family);
        if default
            .as_deref()
            .is_some_and(|d| d.eq_ignore_ascii_case(&name))
        {
            p.detail("Default", Some("true".to_owned()));
        }
        f.records.push(p);
    }
}

/// Whether `name` is a SID: `S-1-…`.
fn is_sid(name: &str) -> bool {
    name.get(..4)
        .is_some_and(|s| s.eq_ignore_ascii_case("S-1-"))
}

/// The packaged apps of the store's lists: the machine's (`Applications`, …), each user's
/// (`<SID>`) and those removed for a user (`EndOfLife\<SID>`).
fn packages(f: &mut Found) {
    let Some((store, at)) = f.key(APPX_STORE) else {
        return;
    };
    for (list, list_path) in f.subkeys(&store, &at) {
        let name = list.name();
        if let Some(known) = APPX_LISTS.iter().find(|l| l.eq_ignore_ascii_case(&name)) {
            package_list(f, &list, &list_path, known, None);
        } else if is_sid(&name) {
            package_list(f, &list, &list_path, "User", Some(&name));
        } else if name.eq_ignore_ascii_case("EndOfLife") {
            for (user, user_path) in f.subkeys(&list, &list_path) {
                let sid = user.name();
                if is_sid(&sid) {
                    package_list(f, &user, &user_path, "EndOfLife", Some(&sid));
                }
            }
        }
    }
}

/// A record of each package key of the store's list `key` (at `at`), named `list`; the user's
/// when `sid` is.
fn package_list<'h>(f: &mut Found<'h>, key: &Key<'h>, at: &str, list: &str, sid: Option<&str>) {
    for (package, path) in f.subkeys(key, at) {
        let values = f.values(&package, &path);
        let scope = if sid.is_some() {
            Scope::User
        } else {
            Scope::Machine
        };
        let mut p = Program::new(ProgramSource::Package, scope, &package, path);
        p.user_sid = sid.map(str::to_owned);
        let full = package.name();
        p.details.push(("List".to_owned(), list.to_owned()));
        if let Some(parts) = package_name(&full) {
            p.name = Some(parts.name.to_owned());
            p.version = parts.version.map(str::to_owned);
            p.architecture = parts.architecture.map(str::to_owned);
            p.detail(
                "ResourceId",
                parts
                    .resource_id
                    .filter(|r| !r.is_empty())
                    .map(str::to_owned),
            );
            p.detail("PublisherId", Some(parts.publisher_id.to_owned()));
        } else {
            p.problems.push(format!(
                "{full:?} is not a package full name or family name"
            ));
        }
        p.install_location = p.text(&values, "Path");
        f.records.push(p);
    }
}

/// The parts of a package's full name (`Name_Version_Architecture_ResourceId_PublisherId`) or
/// family name (`Name_PublisherId`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageName<'a> {
    /// `Microsoft.WindowsCalculator`.
    pub name: &'a str,
    /// `10.1906.55.0`; `None` in a family name.
    pub version: Option<&'a str>,
    /// `x64`, `x86`, `arm`, `arm64`, `neutral`; `None` in a family name.
    pub architecture: Option<&'a str>,
    /// The resource id: often empty, `~` for a bundle; `None` in a family name.
    pub resource_id: Option<&'a str>,
    /// The publisher's id, a hash of its name: `8wekyb3d8bbwe` (Microsoft).
    pub publisher_id: &'a str,
}

/// The parts of package full name `full` (`Microsoft.WindowsCalculator_10.1906.55.0_x64__8wekyb3d8bbwe`)
/// or family name (`Microsoft.WindowsCalculator_8wekyb3d8bbwe`); `None` for other names. A
/// package's name has no `_`.
#[must_use]
pub fn package_name(full: &str) -> Option<PackageName<'_>> {
    let parts: Vec<&str> = full.split('_').collect();
    let named = |s: &str| !s.is_empty();
    match parts[..] {
        [name, version, architecture, resource_id, publisher_id]
            if named(name)
                && named(version)
                && version.bytes().all(|b| b.is_ascii_digit() || b == b'.')
                && named(architecture)
                && named(publisher_id) =>
        {
            Some(PackageName {
                name,
                version: Some(version),
                architecture: Some(architecture),
                resource_id: Some(resource_id),
                publisher_id,
            })
        }
        [name, publisher_id] if named(name) && named(publisher_id) => Some(PackageName {
            name,
            version: None,
            architecture: None,
            resource_id: None,
            publisher_id,
        }),
        _ => None,
    }
}

/// A product code packed as Windows Installer writes it in its keys' names (32 hex digits: the
/// first three groups reversed, each byte of the last two with its digits swapped) as a
/// `{GUID}` in upper case; `None` for other names.
#[must_use]
pub fn unpack_guid(packed: &str) -> Option<String> {
    let b = packed.as_bytes();
    if b.len() != 32 || !b.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let reversed = |s: &[u8]| -> String { s.iter().rev().map(|&c| char::from(c)).collect() };
    let swapped = |s: &[u8]| -> String {
        s.chunks(2)
            .flat_map(|pair| pair.iter().rev())
            .map(|&c| char::from(c))
            .collect()
    };
    Some(
        format!(
            "{{{}-{}-{}-{}-{}}}",
            reversed(&b[..8]),
            reversed(&b[8..12]),
            reversed(&b[12..16]),
            swapped(&b[16..20]),
            swapped(&b[20..])
        )
        .to_uppercase(),
    )
}

/// A Windows Installer product's `Version`: the major version in its high byte, the minor in
/// the next, the build in the low word (`major.minor.build`).
#[must_use]
pub fn msi_version(version: u32) -> String {
    format!(
        "{}.{}.{}",
        version >> 24,
        (version >> 16) & 0xff,
        version & 0xffff
    )
}

/// An `InstallDate` written `YYYYMMDD` as `YYYY-MM-DD`; `None` when it isn't a date written so.
#[must_use]
pub fn install_date(text: &str) -> Option<String> {
    let b = text.as_bytes();
    if b.len() != 8 || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let year: u32 = text[..4].parse().ok()?;
    let month: u32 = text[4..6].parse().ok()?;
    let day: u32 = text[6..].parse().ok()?;
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    (year >= 1601 && (1..=days).contains(&day))
        .then(|| format!("{}-{}-{}", &text[..4], &text[4..6], &text[6..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_guids() {
        // Office 2013's product code and its packed form
        assert_eq!(
            unpack_guid("00005109110000000000000000F01FEC").as_deref(),
            Some("{90150000-0011-0000-0000-0000000FF1CE}")
        );
        assert_eq!(
            unpack_guid("c3f8d9e8a7b6c5d4e3f2a1b0c9d8e7f6").as_deref(),
            Some("{8E9D8F3C-6B7A-4D5C-3E2F-1A0B9C8D7E6F}")
        );
        assert_eq!(unpack_guid("00005109110000000000000000F01FE"), None);
        assert_eq!(unpack_guid("00005109110000000000000000F01FEG"), None);
        assert_eq!(unpack_guid("{90150000-0011-0000-0000-0000000"), None);
        assert_eq!(unpack_guid("ééééééééééééééé0"), None);
    }

    #[test]
    fn versions_dates_and_sources() {
        assert_eq!(msi_version(0x0c00_7bfa), "12.0.31738");
        assert_eq!(msi_version(0), "0.0.0");
        assert_eq!(install_date("20220208").as_deref(), Some("2022-02-08"));
        assert_eq!(install_date("20240229").as_deref(), Some("2024-02-29"));
        for bad in [
            "20230229",
            "19000229",
            "20221301",
            "20220100",
            "2022020",
            "2022-02-08",
            "0000101",
            "16000101",
            "２０２２０２０８",
        ] {
            assert_eq!(install_date(bad), None, "{bad}");
        }
        assert_eq!(install_date("20000229").as_deref(), Some("2000-02-29"));
        assert_eq!(
            last_used_source(r"n;1;C:\Users\alice\Downloads\"),
            Some(r"C:\Users\alice\Downloads\")
        );
        assert_eq!(last_used_source("u;12;https://x/;y"), Some("https://x/;y"));
        for bad in ["", "n;1;", "n;;C:\\", "nn;1;C:\\", "n;x;C:\\", r"C:\setup\"] {
            assert_eq!(last_used_source(bad), None, "{bad}");
        }
    }

    #[test]
    fn package_names() {
        assert_eq!(
            package_name("Microsoft.WindowsCalculator_10.1906.55.0_x64__8wekyb3d8bbwe"),
            Some(PackageName {
                name: "Microsoft.WindowsCalculator",
                version: Some("10.1906.55.0"),
                architecture: Some("x64"),
                resource_id: Some(""),
                publisher_id: "8wekyb3d8bbwe",
            })
        );
        assert_eq!(
            package_name("Microsoft.BingNews_4.7.28001.0_neutral_~_8wekyb3d8bbwe")
                .map(|p| (p.architecture, p.resource_id)),
            Some((Some("neutral"), Some("~")))
        );
        assert_eq!(
            package_name("Microsoft.WindowsCalculator_8wekyb3d8bbwe").map(|p| p.version),
            Some(None)
        );
        for bad in [
            "",
            "x",
            "a_b_c",
            "_8wekyb3d8bbwe",
            "a_1.0_x64__",
            "a_v1_x64__p",
        ] {
            assert_eq!(package_name(bad), None, "{bad}");
        }
        assert!(is_braced_guid("{17A1BA00-E5D7-44BA-AF5F-194A2677FBB6}"));
        assert!(!is_braced_guid("{17A1BA00-E5D7-44BA-AF5F-194A2677FBB6"));
        assert!(!is_braced_guid("{17A1BA00xE5D7-44BA-AF5F-194A2677FBB6}"));
        assert!(!is_braced_guid("AppxInstallerCache"));
        assert!(is_sid("s-1-5-18") && !is_sid("S-1") && !is_sid("Staged"));
    }
}
