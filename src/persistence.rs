//! Autostart locations: the keys and values that make Windows run a program or load a DLL at
//! boot, at logon, or when something else runs, from `SOFTWARE` ([`software`]), `SYSTEM`
//! ([`system`]), `NTUSER.DAT` ([`ntuser`]) and `UsrClass.dat` ([`usrclass`]). One [`Autostart`]
//! per program, DLL or package: a value that lists several gives one for each.
//!
//! `Explorer\StartupApproved` holds what the Task Manager's Startup list has disabled: under
//! `Run` the `Run` key's entries, under `Run32` those of `Wow6432Node`'s `Run`, under
//! `StartupFolder` the files in the Startup folder. Each is 12 bytes: the first is odd when the
//! entry is disabled, and from offset 4 is the FILETIME it was disabled at
//! ([`startup_approved`]).
//!
//! A user's COM class (`CLSID\{…}`) or `shell\open\command` comes before the machine's in
//! `HKEY_CLASSES_ROOT`: given the machine's [`MachineClasses`], a record says whether the
//! machine registers the same one, which the user's then overrides.
//!
//! A command line is split into its program and arguments where that can be told:
//! see [`command_line`].

use std::collections::{HashMap, HashSet};

use crate::bytes::u64_at;
use crate::data::{Data, ValueType, decode};
use crate::hive::{Hive, Key, Status, Value};
use crate::system::{control_set_name, number, string};

/// What starts a program or loads a DLL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mechanism {
    /// `Run`: at logon.
    Run,
    /// `RunOnce` and `RunOnce\Setup`: at the next logon, then removed.
    RunOnce,
    /// `RunOnceEx`: at the next logon, a DLL's function or a program per value.
    RunOnceEx,
    /// `RunServices` (Windows 9x): before logon.
    RunServices,
    /// `RunServicesOnce` (Windows 9x).
    RunServicesOnce,
    /// `Policies\Explorer\Run`: at logon, set by policy.
    PoliciesRun,
    /// A file in a Startup folder, as `StartupApproved\StartupFolder` lists it.
    StartupFolder,
    /// `Winlogon`'s `Shell`, `Userinit`, `Taskman`, …: at logon.
    Winlogon,
    /// `Winlogon\Notify\*` `DLLName`: a DLL Winlogon loads (Windows XP and 2003).
    WinlogonNotify,
    /// `Windows NT\CurrentVersion\Windows` `Load` and `Run`: at logon.
    WindowsLoad,
    /// `AppInit_DLLs`: loaded into every process that loads `user32.dll`.
    AppInitDlls,
    /// `Session Manager\AppCertDlls`: loaded into every process that starts processes.
    AppCertDlls,
    /// `Image File Execution Options\*` `Debugger`: runs instead of the program.
    IfeoDebugger,
    /// `Image File Execution Options\*` `VerifierDlls`: loaded into the program.
    IfeoVerifierDlls,
    /// `SilentProcessExit\*` `MonitorProcess`: runs when the program exits.
    SilentProcessExit,
    /// `Session Manager`'s `BootExecute`, `SetupExecute`, `Execute`, …: native programs at
    /// boot.
    BootExecute,
    /// `Session Manager\KnownDLLs`: the DLLs only ever loaded from `System32`.
    KnownDlls,
    /// `Session Manager` `PendingFileRenameOperations`: files moved or deleted at the next boot.
    PendingFileRename,
    /// `COR_PROFILER`, `CORECLR_PROFILER`, …: a profiler DLL .NET programs load.
    DotnetProfiler,
    /// `Environment` `UserInitMprLogonScript`: a logon script.
    LogonScript,
    /// `Lsa` `Authentication Packages`.
    LsaAuthenticationPackage,
    /// `Lsa` (and `Lsa\OSConfig`) `Security Packages`.
    LsaSecurityPackage,
    /// `Lsa` `Notification Packages`: told of password changes.
    LsaNotificationPackage,
    /// `SecurityProviders` `SecurityProviders`.
    SecurityProvider,
    /// `Print\Monitors\*` `Driver`: loaded by the spooler.
    PrintMonitor,
    /// `Print\Environments\*\Print Processors\*` `Driver`: loaded by the spooler.
    PrintProcessor,
    /// `Print\Providers\*` `Name`: loaded by the spooler.
    PrintProvider,
    /// `NetSh`: a helper DLL `netsh.exe` loads.
    NetshHelper,
    /// `W32Time\TimeProviders\*` `DllName`.
    TimeProvider,
    /// `Active Setup\Installed Components\*` `StubPath`: at a user's logon, once per version.
    ActiveSetup,
    /// `Command Processor` `AutoRun`: whenever `cmd.exe` starts.
    CommandProcessorAutoRun,
    /// `Control Panel\Desktop` `SCRNSAVE.EXE`: the screen saver.
    ScreenSaver,
    /// `PackagedAppXDebug` and `ActivatableClasses\…\DebugInformation`: runs when the app starts.
    AppxDebugger,
    /// A user's `CLSID\*\InprocServer32` or `LocalServer32`.
    ComServer,
    /// A user's `shell\open\command` for a type of program (`exefile`, `batfile`, …): runs
    /// instead of them.
    FileAssociation,
    /// A user's `shell\open\command` that auto-elevating programs start (`ms-settings`,
    /// `mscfile`, `Folder`, …).
    UacBypassCommand,
}

impl Mechanism {
    /// Its name in output: `run`, `ifeo_debugger`, ….
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Mechanism::Run => "run",
            Mechanism::RunOnce => "run_once",
            Mechanism::RunOnceEx => "run_once_ex",
            Mechanism::RunServices => "run_services",
            Mechanism::RunServicesOnce => "run_services_once",
            Mechanism::PoliciesRun => "policies_run",
            Mechanism::StartupFolder => "startup_folder",
            Mechanism::Winlogon => "winlogon",
            Mechanism::WinlogonNotify => "winlogon_notify",
            Mechanism::WindowsLoad => "windows_load",
            Mechanism::AppInitDlls => "appinit_dlls",
            Mechanism::AppCertDlls => "appcert_dlls",
            Mechanism::IfeoDebugger => "ifeo_debugger",
            Mechanism::IfeoVerifierDlls => "ifeo_verifier_dlls",
            Mechanism::SilentProcessExit => "silent_process_exit",
            Mechanism::BootExecute => "boot_execute",
            Mechanism::KnownDlls => "known_dlls",
            Mechanism::PendingFileRename => "pending_file_rename",
            Mechanism::DotnetProfiler => "dotnet_profiler",
            Mechanism::LogonScript => "logon_script",
            Mechanism::LsaAuthenticationPackage => "lsa_authentication_package",
            Mechanism::LsaSecurityPackage => "lsa_security_package",
            Mechanism::LsaNotificationPackage => "lsa_notification_package",
            Mechanism::SecurityProvider => "security_provider",
            Mechanism::PrintMonitor => "print_monitor",
            Mechanism::PrintProcessor => "print_processor",
            Mechanism::PrintProvider => "print_provider",
            Mechanism::NetshHelper => "netsh_helper",
            Mechanism::TimeProvider => "time_provider",
            Mechanism::ActiveSetup => "active_setup",
            Mechanism::CommandProcessorAutoRun => "command_processor_autorun",
            Mechanism::ScreenSaver => "screensaver",
            Mechanism::AppxDebugger => "appx_debugger",
            Mechanism::ComServer => "com_server",
            Mechanism::FileAssociation => "file_association",
            Mechanism::UacBypassCommand => "uac_bypass_command",
        }
    }

    /// Its MITRE ATT&CK technique, where one names it.
    #[must_use]
    pub fn attack_technique(self) -> Option<&'static str> {
        Some(match self {
            Mechanism::Run
            | Mechanism::RunOnce
            | Mechanism::RunOnceEx
            | Mechanism::RunServices
            | Mechanism::RunServicesOnce
            | Mechanism::PoliciesRun
            | Mechanism::StartupFolder
            | Mechanism::WindowsLoad
            | Mechanism::BootExecute => "T1547.001",
            Mechanism::Winlogon | Mechanism::WinlogonNotify => "T1547.004",
            Mechanism::AppInitDlls => "T1546.010",
            Mechanism::AppCertDlls => "T1546.009",
            Mechanism::IfeoDebugger
            | Mechanism::IfeoVerifierDlls
            | Mechanism::SilentProcessExit => "T1546.012",
            Mechanism::DotnetProfiler => "T1574.012",
            Mechanism::LogonScript => "T1037.001",
            Mechanism::LsaAuthenticationPackage => "T1547.002",
            Mechanism::LsaSecurityPackage | Mechanism::SecurityProvider => "T1547.005",
            Mechanism::LsaNotificationPackage => "T1556.002",
            Mechanism::PrintMonitor => "T1547.010",
            Mechanism::PrintProcessor => "T1547.012",
            Mechanism::NetshHelper => "T1546.007",
            Mechanism::TimeProvider => "T1547.003",
            Mechanism::ActiveSetup => "T1547.014",
            Mechanism::ScreenSaver => "T1546.002",
            Mechanism::ComServer => "T1546.015",
            Mechanism::FileAssociation => "T1546.001",
            Mechanism::UacBypassCommand => "T1548.002",
            Mechanism::KnownDlls
            | Mechanism::PendingFileRename
            | Mechanism::PrintProvider
            | Mechanism::CommandProcessorAutoRun
            | Mechanism::AppxDebugger => return None,
        })
    }
}

/// One autostart: a program, DLL or package that a value names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Autostart {
    /// What starts it.
    pub mechanism: Mechanism,
    /// Its key, under the hive's root, with the names as they are written.
    pub key_path: String,
    /// Its value (`""`: the key's default value).
    pub value_name: String,
    /// What it starts or loads: the value's text, one item of a list, a number in decimal.
    /// `None` when it can't be read (see `problems`), or when only `StartupApproved` names it.
    pub data: Option<String>,
    /// The value's bytes, when they are not text, or not valid UTF-16.
    pub data_raw: Option<Vec<u8>>,
    /// The program or DLL: `data` when it is a path, the program when it is a command line that
    /// can be split ([`command_line`]).
    pub image_path: Option<String>,
    /// The command line's arguments, when it has any.
    pub arguments: Option<String>,
    /// More about it: what a `PendingFileRenameOperations` entry does, the COM class's name, ….
    pub details: Option<String>,
    /// Whether it is enabled, when something says: `StartupApproved`, `LoadAppInit_DLLs`,
    /// `GlobalFlag`, `IsInstalled`, `Enabled`, `ScreenSaveActive`.
    pub enabled: Option<bool>,
    /// When `StartupApproved` says it was disabled (FILETIME).
    pub disabled_at: Option<u64>,
    /// Whether the machine registers the same COM class or command, which this user's
    /// overrides; `None` without the machine's [`MachineClasses`].
    pub overrides_machine: Option<bool>,
    /// Whether it is under `Wow6432Node`: 32-bit programs'.
    pub wow64: bool,
    /// When its key was last written (FILETIME).
    pub last_written: u64,
    /// Whether the transaction logs' replay wrote its key or value.
    pub replayed: bool,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// What `StartupApproved` says of an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Approval {
    /// Whether it runs: the first byte is even.
    pub enabled: bool,
    /// When it was disabled (FILETIME); `None` when the time is 0.
    pub disabled_at: Option<u64>,
}

/// A `StartupApproved` value's bytes, decoded.
///
/// # Errors
/// When they are not 12 bytes.
pub fn startup_approved(bytes: &[u8]) -> Result<Approval, String> {
    if bytes.len() != 12 {
        return Err(format!("{} bytes, not 12", bytes.len()));
    }
    Ok(Approval {
        enabled: bytes[0] & 1 == 0,
        disabled_at: u64_at(bytes, 4).filter(|&t| t != 0),
    })
}

/// Extensions of files Windows runs or loads: where an unquoted program's path ends.
const PROGRAMS: [&str; 20] = [
    ".exe", ".com", ".bat", ".cmd", ".scr", ".pif", ".dll", ".cpl", ".msc", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".msi", ".jar",
];

fn ends_with_program(text: &str) -> bool {
    let lower = text.to_lowercase();
    PROGRAMS.iter().any(|ext| lower.ends_with(ext))
}

/// A command line's program and arguments (empty when it has none), where they can be told
/// apart: a quoted program; a command line without spaces; a first word without a folder (a
/// program found on the `PATH`: `cmd /c …`); the shortest start that ends with a program's
/// extension (`.exe`, `.dll`, …) and is followed by a space; or the whole line when it ends
/// with one. `None` otherwise: a path with spaces, unquoted, and no extension.
///
/// An unquoted path with spaces is split where Windows would first find a program, if no file
/// is at a shorter start: `C:\Program Files\App\app.exe /x` runs `C:\Program.exe` when there is
/// one.
#[must_use]
pub fn command_line(command: &str) -> Option<(String, String)> {
    let command = command.trim();
    if command.is_empty() {
        return None;
    }
    if let Some(rest) = command.strip_prefix('"') {
        let end = rest.find('"')?;
        return Some((rest[..end].to_owned(), rest[end + 1..].trim().to_owned()));
    }
    let Some(space) = command.find(char::is_whitespace) else {
        return Some((command.to_owned(), String::new()));
    };
    let first = &command[..space];
    if !first.contains(['\\', '/']) {
        return Some((first.to_owned(), command[space..].trim().to_owned()));
    }
    for (at, _) in command.char_indices().filter(|(_, c)| c.is_whitespace()) {
        let head = &command[..at];
        if ends_with_program(head) {
            return Some((head.to_owned(), command[at..].trim().to_owned()));
        }
    }
    ends_with_program(command).then(|| (command.to_owned(), String::new()))
}

/// What a value's data is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// A command line: its program and arguments are split off.
    Command,
    /// A program's or DLL's path.
    Path,
    /// A name, a number or a flag.
    Other,
}

/// Where a record's key is.
#[derive(Clone, Copy)]
struct Place<'p, 'h> {
    key: Key<'h>,
    path: &'p str,
    wow64: bool,
}

impl Autostart {
    /// A record of value `value_name` of the key at `at`, without data.
    fn new(mechanism: Mechanism, at: Place, value_name: String) -> Self {
        Autostart {
            mechanism,
            key_path: at.path.to_owned(),
            value_name,
            data: None,
            data_raw: None,
            image_path: None,
            arguments: None,
            details: None,
            enabled: None,
            disabled_at: None,
            overrides_machine: None,
            wow64: at.wow64,
            last_written: at.key.last_written(),
            replayed: at.key.status() == Status::Replayed,
            problems: Vec::new(),
        }
    }

    /// Its data, the program and arguments split off as `kind` says.
    fn set(&mut self, data: String, kind: Kind) {
        match kind {
            Kind::Command => {
                if let Some((image, arguments)) = command_line(&data) {
                    self.image_path = Some(image);
                    self.arguments = (!arguments.is_empty()).then_some(arguments);
                }
            }
            Kind::Path => {
                let path = data.trim().trim_matches('"').trim();
                if !path.is_empty() {
                    self.image_path = Some(path.to_owned());
                }
            }
            Kind::Other => {}
        }
        self.data = Some(data);
    }
}

/// A value's data as text (a number in decimal), its bytes when they are not text or not valid
/// UTF-16, and what is wrong with it.
fn data_of(value: &Value) -> (Option<String>, Option<Vec<u8>>, Option<String>) {
    if matches!(
        value.value_type(),
        ValueType::Dword | ValueType::DwordBigEndian | ValueType::Qword
    ) {
        let (bytes, why) = value.read_data();
        return match decode(value.data_type(), &bytes) {
            Data::Number(n) => (Some(n.to_string()), None, why),
            Data::Malformed(why) => (None, Some(bytes), Some(why)),
            _ => (None, Some(bytes), why),
        };
    }
    let (text, why) = string(value);
    let raw = if text.is_none() || why.is_some() {
        Some(value.read_data().0).filter(|b| !b.is_empty())
    } else {
        None
    };
    (text, raw, why)
}

/// The items of a list value: a multi-string's strings, or a string split at `separators`;
/// trimmed, the empty ones left out. With them, the bytes when they are not text or not valid
/// UTF-16, and what is wrong.
fn items_of(value: &Value, separators: &[char]) -> (Vec<String>, Option<Vec<u8>>, Vec<String>) {
    let (bytes, why) = value.read_data();
    let mut problems: Vec<String> = why.into_iter().collect();
    let (texts, lossy) = match decode(value.data_type(), &bytes) {
        Data::MultiText { values, lossy } => (values, lossy),
        Data::Text { value, lossy } => (vec![value], lossy),
        _ if bytes.is_empty() => (Vec::new(), false),
        _ => {
            problems.push(format!("is {}, not a string", value.value_type().name()));
            (Vec::new(), false)
        }
    };
    if lossy {
        problems.push("is not valid UTF-16: decoded lossily".to_owned());
    }
    let items = texts
        .iter()
        .flat_map(|t| t.split(|c| separators.contains(&c)))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    let raw = (!problems.is_empty() && !bytes.is_empty()).then_some(bytes);
    (items, raw, problems)
}

/// A flag value: a `REG_DWORD`, or a string of a number (`0x200`, as `gflags.exe` writes it).
fn flags_of(value: &Value) -> Result<u32, String> {
    match value.value_type() {
        ValueType::Dword => number(value),
        ValueType::Sz | ValueType::ExpandSz => {
            let (text, why) = string(value);
            if let Some(why) = why {
                return Err(why);
            }
            let text = text.unwrap_or_default();
            let t = text.trim();
            match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                Some(hex) => u32::from_str_radix(hex, 16),
                None => t.parse(),
            }
            .map_err(|_| format!("{t:?} is not a number"))
        }
        other => Err(format!("is {}, not REG_DWORD", other.name())),
    }
}

/// The records found so far, and what kept parts of the hive from being read.
struct Found<'h> {
    hive: &'h Hive,
    records: Vec<Autostart>,
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

    /// A record of `value`, its data read as one; its index. `None` for an empty value: it
    /// starts nothing.
    fn one(&mut self, mechanism: Mechanism, at: Place, value: &Value, kind: Kind) -> Option<usize> {
        let mut record = Autostart::new(mechanism, at, value.name());
        record.replayed |= value.status() == Status::Replayed;
        let (data, raw, why) = data_of(value);
        if raw.is_none() && why.is_none() && data.as_deref().is_none_or(|d| d.trim().is_empty()) {
            return None;
        }
        if let Some(data) = data {
            record.set(data, kind);
        }
        record.data_raw = raw;
        record.problems.extend(why);
        self.records.push(record);
        Some(self.records.len() - 1)
    }

    /// A record of each item of list value `value` (see [`items_of`]), or one without data
    /// when it can't be read; their indexes.
    fn list(
        &mut self,
        mechanism: Mechanism,
        at: Place,
        value: &Value,
        kind: Kind,
        separators: &[char],
    ) -> Vec<usize> {
        let (items, raw, problems) = items_of(value, separators);
        let mut record = Autostart::new(mechanism, at, value.name());
        record.replayed |= value.status() == Status::Replayed;
        record.data_raw = raw;
        record.problems = problems;
        let start = self.records.len();
        if items.is_empty() {
            if !record.problems.is_empty() {
                self.records.push(record);
            }
        } else {
            for item in items {
                let mut one = record.clone();
                one.set(item, kind);
                self.records.push(one);
            }
        }
        (start..self.records.len()).collect()
    }

    /// A record of each value of the key at `path` but its default value and those in `skip`.
    fn each_value(
        &mut self,
        mechanism: Mechanism,
        path: &str,
        wow64: bool,
        kind: Kind,
        skip: &[&str],
    ) {
        let Some((key, path)) = self.key(path) else {
            return;
        };
        let at = Place {
            key,
            path: &path,
            wow64,
        };
        for value in self.values(&key, &path) {
            let name = value.name();
            if !name.is_empty() && !skip.iter().any(|s| s.eq_ignore_ascii_case(&name)) {
                self.one(mechanism, at, &value, kind);
            }
        }
    }

    /// A record of each of the values `names` the key at `path` has.
    fn named(
        &mut self,
        mechanism: Mechanism,
        path: &str,
        wow64: bool,
        kind: Kind,
        names: &[&str],
    ) -> Vec<usize> {
        let Some((key, path)) = self.key(path) else {
            return Vec::new();
        };
        let at = Place {
            key,
            path: &path,
            wow64,
        };
        let values = self.values(&key, &path);
        names
            .iter()
            .filter_map(|name| values.iter().find(|v| v.name().eq_ignore_ascii_case(name)))
            .filter_map(|value| self.one(mechanism, at, value, kind))
            .collect()
    }

    /// For each subkey of the key at `path`, a record of its value `name`; the records' indexes,
    /// each with the subkey's values.
    fn per_subkey(
        &mut self,
        mechanism: Mechanism,
        path: &str,
        wow64: bool,
        kind: Kind,
        name: &str,
    ) -> Vec<(usize, Vec<Value<'h>>)> {
        let Some((key, path)) = self.key(path) else {
            return Vec::new();
        };
        let mut found = Vec::new();
        for (sub, sub_path) in self.subkeys(&key, &path) {
            let values = self.values(&sub, &sub_path);
            let Some(value) = values.iter().find(|v| v.name().eq_ignore_ascii_case(name)) else {
                continue;
            };
            let at = Place {
                key: sub,
                path: &sub_path,
                wow64,
            };
            if let Some(index) = self.one(mechanism, at, value, kind) {
                found.push((index, values));
            }
        }
        found
    }

    fn done(self) -> (Vec<Autostart>, Vec<String>) {
        (self.records, self.problems)
    }
}

/// The value named `name` (in any case) among `values`.
fn find<'v, 'h>(values: &'v [Value<'h>], name: &str) -> Option<&'v Value<'h>> {
    values.iter().find(|v| v.name().eq_ignore_ascii_case(name))
}

/// `CurrentVersion`, under the `SOFTWARE` root or `NTUSER.DAT`'s `Software`.
const CURRENT_VERSION: &str = r"Microsoft\Windows\CurrentVersion";
/// `Windows NT\CurrentVersion`.
const NT_CURRENT_VERSION: &str = r"Microsoft\Windows NT\CurrentVersion";
/// Terminal Server's install mode's own `CurrentVersion`.
const TS_INSTALL: &str = r"Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion";

/// The `Run` keys under `CurrentVersion`.
const RUN_KEYS: [(&str, Mechanism); 7] = [
    ("Run", Mechanism::Run),
    ("RunOnce", Mechanism::RunOnce),
    (r"RunOnce\Setup", Mechanism::RunOnce),
    ("RunOnceEx", Mechanism::RunOnceEx),
    ("RunServices", Mechanism::RunServices),
    ("RunServicesOnce", Mechanism::RunServicesOnce),
    (r"Policies\Explorer\Run", Mechanism::PoliciesRun),
];

/// `Winlogon`'s values that name programs or DLLs: what they hold, and whether they list
/// programs separated by commas.
const WINLOGON: [(&str, Kind, bool); 8] = [
    ("Shell", Kind::Command, true),
    ("Userinit", Kind::Command, true),
    ("Taskman", Kind::Command, false),
    ("AppSetup", Kind::Command, false),
    ("VmApplet", Kind::Command, false),
    ("System", Kind::Command, false),
    ("UIHost", Kind::Path, false),
    ("GinaDLL", Kind::Path, false),
];

/// The `Environment` variables that load a .NET profiler.
const PROFILER: [&str; 10] = [
    "COR_ENABLE_PROFILING",
    "COR_PROFILER",
    "COR_PROFILER_PATH",
    "COR_PROFILER_PATH_32",
    "COR_PROFILER_PATH_64",
    "CORECLR_ENABLE_PROFILING",
    "CORECLR_PROFILER",
    "CORECLR_PROFILER_PATH",
    "CORECLR_PROFILER_PATH_32",
    "CORECLR_PROFILER_PATH_64",
];

/// `Session Manager`'s values of native programs to run at boot.
const EXECUTES: [&str; 6] = [
    "BootExecute",
    "BootExecuteNoPnpSync",
    "SetupExecute",
    "Execute",
    "S0InitialCommand",
    "PlatformExecute",
];

/// The `shell\…\command` keys under a user's classes that start something in place of a type
/// of program, or that an auto-elevating program starts.
const USER_COMMANDS: [(&str, Mechanism); 17] = [
    (
        r"ms-settings\shell\open\command",
        Mechanism::UacBypassCommand,
    ),
    (r"mscfile\shell\open\command", Mechanism::UacBypassCommand),
    (r"Folder\shell\open\command", Mechanism::UacBypassCommand),
    (
        r"Launcher.SystemSettings\shell\open\command",
        Mechanism::UacBypassCommand,
    ),
    (r"exefile\shell\runas\command", Mechanism::UacBypassCommand),
    (
        r"AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command",
        Mechanism::UacBypassCommand,
    ),
    (r"exefile\shell\open\command", Mechanism::FileAssociation),
    (r"comfile\shell\open\command", Mechanism::FileAssociation),
    (r"batfile\shell\open\command", Mechanism::FileAssociation),
    (r"cmdfile\shell\open\command", Mechanism::FileAssociation),
    (r"scrfile\shell\open\command", Mechanism::FileAssociation),
    (r"piffile\shell\open\command", Mechanism::FileAssociation),
    (r"htafile\shell\open\command", Mechanism::FileAssociation),
    (r"VBSFile\shell\open\command", Mechanism::FileAssociation),
    (r"JSFile\shell\open\command", Mechanism::FileAssociation),
    (r"WSFFile\shell\open\command", Mechanism::FileAssociation),
    (r"txtfile\shell\open\command", Mechanism::FileAssociation),
];

/// `GlobalFlag`'s `FLG_APPLICATION_VERIFIER`: load `VerifierDlls`.
const FLG_APPLICATION_VERIFIER: u32 = 0x100;
/// `GlobalFlag`'s `FLG_MONITOR_SILENT_PROCESS_EXIT`: start `MonitorProcess`.
const FLG_MONITOR_SILENT_PROCESS_EXIT: u32 = 0x200;

/// The COM classes and `shell\…\command` keys the machine registers (`SOFTWARE\Classes`), to
/// tell which of a user's override them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MachineClasses {
    /// `Classes\CLSID`'s subkeys, in upper case.
    clsids: HashSet<String>,
    /// `Classes\Wow6432Node\CLSID`'s subkeys, in upper case.
    wow64_clsids: HashSet<String>,
    /// The command keys of the user list that `Classes` has, in upper case.
    commands: HashSet<String>,
}

impl MachineClasses {
    /// The classes of the `SOFTWARE` hive `software`.
    #[must_use]
    pub fn read(software: &Hive) -> Self {
        let names = |path: &str| -> HashSet<String> {
            software
                .key(path)
                .map(|k| {
                    k.subkeys()
                        .0
                        .iter()
                        .map(|s| s.name().to_uppercase())
                        .collect()
                })
                .unwrap_or_default()
        };
        MachineClasses {
            clsids: names(r"Classes\CLSID"),
            wow64_clsids: names(r"Classes\Wow6432Node\CLSID"),
            commands: USER_COMMANDS
                .iter()
                .filter(|(path, _)| software.key(&format!(r"Classes\{path}")).is_some())
                .map(|(path, _)| path.to_uppercase())
                .collect(),
        }
    }

    /// Whether the machine registers COM class `clsid` (`{…}`), its 32-bit view when `wow64`.
    #[must_use]
    pub fn has_class(&self, clsid: &str, wow64: bool) -> bool {
        let set = if wow64 {
            &self.wow64_clsids
        } else {
            &self.clsids
        };
        set.contains(&clsid.to_uppercase())
    }

    /// Whether the machine has the command key `path` (`ms-settings\shell\open\command`).
    #[must_use]
    pub fn has_command(&self, path: &str) -> bool {
        self.commands.contains(&path.to_uppercase())
    }
}

/// The autostarts of a `SOFTWARE` hive, and what kept parts of it from being read.
#[must_use]
pub fn software(hive: &Hive) -> (Vec<Autostart>, Vec<String>) {
    let mut f = Found::new(hive);
    let run = [
        run_keys(&mut f, CURRENT_VERSION, false),
        run_keys(&mut f, &format!(r"Wow6432Node\{CURRENT_VERSION}"), true),
    ];
    run_keys(&mut f, TS_INSTALL, false);
    approvals(&mut f, CURRENT_VERSION, &run);
    winlogon(&mut f, &format!(r"{NT_CURRENT_VERSION}\Winlogon"), true);
    for (prefix, wow64) in [("", false), (r"Wow6432Node\", true)] {
        let nt = format!("{prefix}{NT_CURRENT_VERSION}");
        appinit(&mut f, &format!(r"{nt}\Windows"), wow64);
        ifeo(&mut f, &nt, wow64);
        active_setup(
            &mut f,
            &format!(r"{prefix}Microsoft\Active Setup\Installed Components"),
            wow64,
        );
        f.each_value(
            Mechanism::NetshHelper,
            &format!(r"{prefix}Microsoft\NetSh"),
            wow64,
            Kind::Path,
            &[],
        );
        f.named(
            Mechanism::CommandProcessorAutoRun,
            &format!(r"{prefix}Microsoft\Command Processor"),
            wow64,
            Kind::Command,
            &["AutoRun"],
        );
    }
    f.done()
}

/// The autostarts of control set `set` of a `SYSTEM` hive, and what kept parts of it from being
/// read.
#[must_use]
pub fn system(hive: &Hive, set: u32) -> (Vec<Autostart>, Vec<String>) {
    let mut f = Found::new(hive);
    let control = format!(r"{}\Control", control_set_name(set));
    session_manager(&mut f, &format!(r"{control}\Session Manager"));
    for (path, name, mechanism) in [
        (
            "Lsa",
            "Authentication Packages",
            Mechanism::LsaAuthenticationPackage,
        ),
        ("Lsa", "Security Packages", Mechanism::LsaSecurityPackage),
        (
            "Lsa",
            "Notification Packages",
            Mechanism::LsaNotificationPackage,
        ),
        (
            r"Lsa\OSConfig",
            "Security Packages",
            Mechanism::LsaSecurityPackage,
        ),
        (
            "SecurityProviders",
            "SecurityProviders",
            Mechanism::SecurityProvider,
        ),
    ] {
        let Some((key, path)) = f.key(&format!(r"{control}\{path}")) else {
            continue;
        };
        let values = f.values(&key, &path);
        if let Some(value) = find(&values, name) {
            let at = Place {
                key,
                path: &path,
                wow64: false,
            };
            let kind = if mechanism == Mechanism::SecurityProvider {
                Kind::Path
            } else {
                Kind::Other
            };
            f.list(mechanism, at, value, kind, &[',']);
        }
    }
    spooler(&mut f, &format!(r"{control}\Print"));
    let providers = format!(r"{}\Services\W32Time\TimeProviders", control_set_name(set));
    for (index, values) in f.per_subkey(
        Mechanism::TimeProvider,
        &providers,
        false,
        Kind::Path,
        "DllName",
    ) {
        enabled_by(&mut f.records[index], find(&values, "Enabled"));
    }
    f.done()
}

/// `Session Manager` at `path`: the programs it runs at boot, the files it moves, its
/// `KnownDLLs` and `AppCertDlls`, and the .NET profiler in its `Environment`.
fn session_manager(f: &mut Found, path: &str) {
    if let Some((key, path)) = f.key(path) {
        let at = Place {
            key,
            path: &path,
            wow64: false,
        };
        for value in f.values(&key, &path) {
            let name = value.name();
            if EXECUTES.iter().any(|e| e.eq_ignore_ascii_case(&name)) {
                f.list(Mechanism::BootExecute, at, &value, Kind::Command, &[]);
            } else if name.eq_ignore_ascii_case("PendingFileRenameOperations")
                || name.eq_ignore_ascii_case("PendingFileRenameOperations2")
            {
                pending_renames(f, at, &value);
            }
        }
    }
    f.each_value(
        Mechanism::KnownDlls,
        &format!(r"{path}\KnownDLLs"),
        false,
        Kind::Path,
        &["DllDirectory", "DllDirectory32"],
    );
    f.each_value(
        Mechanism::AppCertDlls,
        &format!(r"{path}\AppCertDlls"),
        false,
        Kind::Path,
        &[],
    );
    environment(f, &format!(r"{path}\Environment"), false);
}

/// `Print` at `path`: the spooler's monitors, providers and print processors.
fn spooler(f: &mut Found, path: &str) {
    f.per_subkey(
        Mechanism::PrintMonitor,
        &format!(r"{path}\Monitors"),
        false,
        Kind::Path,
        "Driver",
    );
    f.per_subkey(
        Mechanism::PrintProvider,
        &format!(r"{path}\Providers"),
        false,
        Kind::Path,
        "Name",
    );
    if let Some((key, environments)) = f.key(&format!(r"{path}\Environments")) {
        for (_, environment) in f.subkeys(&key, &environments) {
            f.per_subkey(
                Mechanism::PrintProcessor,
                &format!(r"{environment}\Print Processors"),
                false,
                Kind::Path,
                "Driver",
            );
        }
    }
}

/// The autostarts of an `NTUSER.DAT` hive, and what kept parts of it from being read; with the
/// machine's classes, whether its classes (`Software\Classes`) override them.
#[must_use]
pub fn ntuser(hive: &Hive, machine: Option<&MachineClasses>) -> (Vec<Autostart>, Vec<String>) {
    let mut f = Found::new(hive);
    let current = format!(r"Software\{CURRENT_VERSION}");
    let run = [
        run_keys(&mut f, &current, false),
        run_keys(
            &mut f,
            &format!(r"Software\Wow6432Node\{CURRENT_VERSION}"),
            true,
        ),
    ];
    run_keys(&mut f, &format!(r"Software\{TS_INSTALL}"), false);
    approvals(&mut f, &current, &run);
    f.named(
        Mechanism::WindowsLoad,
        &format!(r"Software\{NT_CURRENT_VERSION}\Windows"),
        false,
        Kind::Command,
        &["Load", "Run"],
    );
    winlogon(
        &mut f,
        &format!(r"Software\{NT_CURRENT_VERSION}\Winlogon"),
        false,
    );
    environment(&mut f, "Environment", true);
    f.per_subkey(
        Mechanism::AppxDebugger,
        &format!(r"{current}\PackagedAppXDebug"),
        false,
        Kind::Command,
        "",
    );
    for path in [
        r"Control Panel\Desktop",
        r"Software\Policies\Microsoft\Windows\Control Panel\Desktop",
    ] {
        screensaver(&mut f, path);
    }
    for (prefix, wow64) in [("", false), (r"Wow6432Node\", true)] {
        f.named(
            Mechanism::CommandProcessorAutoRun,
            &format!(r"Software\{prefix}Microsoft\Command Processor"),
            wow64,
            Kind::Command,
            &["AutoRun"],
        );
    }
    classes(&mut f, r"Software\Classes", machine);
    f.done()
}

/// The autostarts of a `UsrClass.dat` hive (a user's `Software\Classes`), and what kept parts of
/// it from being read; with the machine's classes, whether they override them.
#[must_use]
pub fn usrclass(hive: &Hive, machine: Option<&MachineClasses>) -> (Vec<Autostart>, Vec<String>) {
    let mut f = Found::new(hive);
    classes(&mut f, "", machine);
    f.done()
}

/// The `Run` keys under `base` (`CurrentVersion`); the indexes of the records from `Run` itself,
/// which `StartupApproved` speaks of.
fn run_keys(f: &mut Found, base: &str, wow64: bool) -> Vec<usize> {
    let mut run = Vec::new();
    for (sub, mechanism) in RUN_KEYS {
        let Some((key, path)) = f.key(&format!(r"{base}\{sub}")) else {
            continue;
        };
        if mechanism == Mechanism::RunOnceEx {
            run_once_ex(f, key, &path, wow64);
            continue;
        }
        let at = Place {
            key,
            path: &path,
            wow64,
        };
        for value in f.values(&key, &path) {
            if let Some(index) = f.one(mechanism, at, &value, Kind::Command)
                && sub == "Run"
            {
                run.push(index);
            }
        }
    }
    run
}

/// `RunOnceEx`: its sections' values (a section's default value is its title), and their
/// `Depend` keys'.
fn run_once_ex<'h>(f: &mut Found<'h>, key: Key<'h>, path: &str, wow64: bool) {
    for entry in f.hive.walk_from(key, path.to_owned()) {
        f.problems.extend(
            entry
                .problems
                .iter()
                .map(|w| format!("{}: {w}", entry.path)),
        );
        if entry.key.offset() == key.offset() {
            continue;
        }
        let at = Place {
            key: entry.key,
            path: &entry.path,
            wow64,
        };
        for value in f.values(&entry.key, &entry.path) {
            if !value.name().is_empty() {
                f.one(Mechanism::RunOnceEx, at, &value, Kind::Other);
            }
        }
    }
}

/// `StartupApproved` under `base` (`CurrentVersion`): whether the `Run` records `run` (native,
/// then `Wow6432Node`'s) are enabled, with a record of each entry no `Run` value has and of each
/// Startup folder file.
fn approvals(f: &mut Found, base: &str, run: &[Vec<usize>; 2]) {
    let approved = format!(r"{base}\Explorer\StartupApproved");
    for (list, which) in [
        ("Run", Some(0)),
        ("Run32", Some(1)),
        ("StartupFolder", None),
    ] {
        let Some((key, path)) = f.key(&format!(r"{approved}\{list}")) else {
            continue;
        };
        for value in f.values(&key, &path) {
            let name = value.name();
            let (bytes, why) = value.read_data();
            let mut problems: Vec<String> = why.into_iter().collect();
            if value.value_type() != ValueType::Binary {
                problems.push(format!("is {}, not REG_BINARY", value.value_type().name()));
            }
            let approval = startup_approved(&bytes)
                .map_err(|why| problems.push(why))
                .ok();
            let replayed = value.status() == Status::Replayed;
            let matched: Vec<usize> = which
                .map(|w: usize| {
                    run[w]
                        .iter()
                        .copied()
                        .filter(|&i| f.records[i].value_name.eq_ignore_ascii_case(&name))
                        .collect()
                })
                .unwrap_or_default();
            if matched.is_empty() {
                let at = Place {
                    key,
                    path: &path,
                    wow64: which == Some(1),
                };
                let mechanism = if which.is_some() {
                    Mechanism::Run
                } else {
                    Mechanism::StartupFolder
                };
                let mut record = Autostart::new(mechanism, at, name);
                record.replayed |= replayed;
                record.enabled = approval.map(|a| a.enabled);
                record.disabled_at = approval.and_then(|a| a.disabled_at);
                record.details = Some(
                    if which.is_some() {
                        "only in StartupApproved: the Run key has no value of this name"
                    } else {
                        "a file in the Startup folder"
                    }
                    .to_owned(),
                );
                record.data_raw = (!problems.is_empty()).then_some(bytes);
                record.problems = problems;
                f.records.push(record);
            } else {
                for i in matched {
                    let record = &mut f.records[i];
                    record.enabled = approval.map(|a| a.enabled);
                    record.disabled_at = approval.and_then(|a| a.disabled_at);
                    record.replayed |= replayed;
                    record.problems.extend(
                        problems
                            .iter()
                            .map(|w| format!(r"StartupApproved\{list}: {w}")),
                    );
                }
            }
        }
    }
}

/// `Winlogon` at `path`: its programs, and with `notify` its `Notify` packages.
fn winlogon(f: &mut Found, path: &str, notify: bool) {
    let Some((key, path)) = f.key(path) else {
        return;
    };
    let at = Place {
        key,
        path: &path,
        wow64: false,
    };
    let values = f.values(&key, &path);
    for (name, kind, commas) in WINLOGON {
        let Some(value) = find(&values, name) else {
            continue;
        };
        if !commas {
            f.one(Mechanism::Winlogon, at, value, kind);
            continue;
        }
        let found = f.list(Mechanism::Winlogon, at, value, kind, &[',']);
        if found.len() > 1 {
            for i in found {
                f.records[i].details = Some(format!("one of the {name} programs, comma-separated"));
            }
        }
    }
    if notify {
        f.per_subkey(
            Mechanism::WinlogonNotify,
            &format!(r"{path}\Notify"),
            false,
            Kind::Path,
            "DLLName",
        );
    }
}

/// `AppInit_DLLs` in `Windows` at `path`: each DLL, enabled as `LoadAppInit_DLLs` says.
fn appinit(f: &mut Found, path: &str, wow64: bool) {
    let Some((key, path)) = f.key(path) else {
        return;
    };
    let values = f.values(&key, &path);
    let Some(dlls) = find(&values, "AppInit_DLLs") else {
        return;
    };
    let at = Place {
        key,
        path: &path,
        wow64,
    };
    let load = find(&values, "LoadAppInit_DLLs").map(number);
    let signed = find(&values, "RequireSignedAppInit_DLLs").map(number);
    for i in f.list(
        Mechanism::AppInitDlls,
        at,
        dlls,
        Kind::Path,
        &[',', ' ', '\t'],
    ) {
        let record = &mut f.records[i];
        match &load {
            Some(Ok(n)) => record.enabled = Some(*n != 0),
            Some(Err(why)) => record.problems.push(format!("LoadAppInit_DLLs: {why}")),
            None => {}
        }
        match &signed {
            Some(Ok(n)) => record.details = Some(format!("RequireSignedAppInit_DLLs {n}")),
            Some(Err(why)) => record
                .problems
                .push(format!("RequireSignedAppInit_DLLs: {why}")),
            None => {}
        }
    }
}

/// `Image File Execution Options` and `SilentProcessExit` under `nt` (`Windows NT\CurrentVersion`).
fn ifeo(f: &mut Found, nt: &str, wow64: bool) {
    // each program's GlobalFlag, by its name in upper case
    let mut flags: HashMap<String, u32> = HashMap::new();
    if let Some((key, path)) = f.key(&format!(r"{nt}\Image File Execution Options")) {
        for (program, program_path) in f.subkeys(&key, &path) {
            let values = f.values(&program, &program_path);
            let at = Place {
                key: program,
                path: &program_path,
                wow64,
            };
            let global = match find(&values, "GlobalFlag").map(flags_of) {
                Some(Ok(n)) => Some(n),
                Some(Err(why)) => {
                    f.problems
                        .push(format!(r"{program_path}: GlobalFlag: {why}"));
                    None
                }
                None => None,
            };
            if let Some(n) = global {
                flags.insert(program.name().to_uppercase(), n);
            }
            if let Some(value) = find(&values, "Debugger") {
                f.one(Mechanism::IfeoDebugger, at, value, Kind::Command);
            }
            if let Some(value) = find(&values, "VerifierDlls") {
                for i in f.list(Mechanism::IfeoVerifierDlls, at, value, Kind::Path, &[' ']) {
                    f.records[i].enabled =
                        Some(global.is_some_and(|g| g & FLG_APPLICATION_VERIFIER != 0));
                }
            }
            // UseFilter: a Debugger for the program at one path only
            let filtered = find(&values, "UseFilter").map(number);
            for (filter, filter_path) in f.subkeys(&program, &program_path) {
                let values = f.values(&filter, &filter_path);
                let Some(value) = find(&values, "Debugger") else {
                    continue;
                };
                let at = Place {
                    key: filter,
                    path: &filter_path,
                    wow64,
                };
                let Some(i) = f.one(Mechanism::IfeoDebugger, at, value, Kind::Command) else {
                    continue;
                };
                let record = &mut f.records[i];
                match &filtered {
                    Some(Ok(n)) => record.enabled = Some(*n != 0),
                    Some(Err(why)) => record.problems.push(format!("UseFilter: {why}")),
                    None => record.enabled = Some(false),
                }
                if let Some(full) = find(&values, "FilterFullPath") {
                    let (text, why) = string(full);
                    record.details = text.map(|t| format!("for {t} (FilterFullPath)"));
                    record
                        .problems
                        .extend(why.map(|w| format!("FilterFullPath: {w}")));
                }
            }
        }
    }
    for (index, values) in f.per_subkey(
        Mechanism::SilentProcessExit,
        &format!(r"{nt}\SilentProcessExit"),
        wow64,
        Kind::Command,
        "MonitorProcess",
    ) {
        let record = &mut f.records[index];
        let program = record
            .key_path
            .rsplit('\\')
            .next()
            .unwrap_or_default()
            .to_uppercase();
        record.enabled = Some(
            flags
                .get(&program)
                .is_some_and(|g| g & FLG_MONITOR_SILENT_PROCESS_EXIT != 0),
        );
        if let Some(mode) = find(&values, "ReportingMode") {
            match number(mode) {
                Ok(n) => record.details = Some(format!("ReportingMode {n}")),
                Err(why) => record.problems.push(format!("ReportingMode: {why}")),
            }
        }
    }
}

/// `Active Setup\Installed Components` at `path`: each component's `StubPath`, enabled as
/// `IsInstalled` and `Enabled` say, with its name. A component with a `ShellComponent` (a DLL)
/// has that DLL run with `StubPath` as its argument.
fn active_setup(f: &mut Found, path: &str, wow64: bool) {
    for (index, values) in f.per_subkey(
        Mechanism::ActiveSetup,
        path,
        wow64,
        Kind::Command,
        "StubPath",
    ) {
        let record = &mut f.records[index];
        enabled_by(record, find(&values, "IsInstalled"));
        if record.enabled != Some(false) {
            enabled_by(record, find(&values, "Enabled"));
        }
        let name = find(&values, "")
            .and_then(|v| string(v).0)
            .filter(|n| !n.is_empty());
        let shell = find(&values, "ShellComponent")
            .and_then(|v| string(v).0)
            .filter(|n| !n.trim().is_empty());
        if let Some(shell) = shell {
            record.arguments.clone_from(&record.data);
            record.image_path = Some(shell.trim().to_owned());
            record.details = Some(match name {
                Some(name) => format!("{name}; StubPath is ShellComponent's argument"),
                None => "StubPath is ShellComponent's argument".to_owned(),
            });
        } else {
            record.details = name;
        }
    }
}

/// `record` enabled as the number `value` says (0: disabled).
fn enabled_by(record: &mut Autostart, value: Option<&Value>) {
    let Some(value) = value else {
        return;
    };
    match number(value) {
        Ok(n) => record.enabled = Some(n != 0),
        Err(why) => record.problems.push(format!("{}: {why}", value.name())),
    }
}

/// `PendingFileRenameOperations`: pairs of a file and where it goes, empty to delete it.
fn pending_renames(f: &mut Found, at: Place, value: &Value) {
    let (bytes, why) = value.read_data();
    let mut problems: Vec<String> = why.into_iter().collect();
    let items = match decode(value.data_type(), &bytes) {
        Data::MultiText { values, lossy } => {
            if lossy {
                problems.push("is not valid UTF-16: decoded lossily".to_owned());
            }
            values
        }
        _ if bytes.is_empty() => Vec::new(),
        _ => {
            problems.push(format!(
                "is {}, not REG_MULTI_SZ",
                value.value_type().name()
            ));
            Vec::new()
        }
    };
    let mut record = Autostart::new(Mechanism::PendingFileRename, at, value.name());
    record.replayed |= value.status() == Status::Replayed;
    record.data_raw = (!problems.is_empty() && !bytes.is_empty()).then_some(bytes);
    record.problems = problems;
    if items.is_empty() {
        if !record.problems.is_empty() {
            f.records.push(record);
        }
        return;
    }
    for pair in items.chunks(2) {
        let mut one = record.clone();
        one.details = Some(match pair.get(1).filter(|to| !to.is_empty()) {
            Some(to) => format!("to be moved to {to}"),
            None => "to be deleted".to_owned(),
        });
        one.set(pair[0].clone(), Kind::Path);
        f.records.push(one);
    }
}

/// `Environment` at `path`: the .NET profiler's variables, and with `user` the logon script.
fn environment(f: &mut Found, path: &str, user: bool) {
    let Some((key, path)) = f.key(path) else {
        return;
    };
    let at = Place {
        key,
        path: &path,
        wow64: false,
    };
    for value in f.values(&key, &path) {
        let name = value.name().to_uppercase();
        if PROFILER.contains(&name.as_str()) {
            let kind = if name.contains("_PATH") {
                Kind::Path
            } else {
                Kind::Other
            };
            f.one(Mechanism::DotnetProfiler, at, &value, kind);
        } else if user && name == "USERINITMPRLOGONSCRIPT" {
            f.one(Mechanism::LogonScript, at, &value, Kind::Command);
        }
    }
}

/// `Control Panel\Desktop` at `path`: the screen saver, enabled as `ScreenSaveActive` says.
fn screensaver(f: &mut Found, path: &str) {
    let Some((key, path)) = f.key(path) else {
        return;
    };
    let values = f.values(&key, &path);
    let Some(value) = find(&values, "SCRNSAVE.EXE") else {
        return;
    };
    let at = Place {
        key,
        path: &path,
        wow64: false,
    };
    let Some(i) = f.one(Mechanism::ScreenSaver, at, value, Kind::Path) else {
        return;
    };
    if let Some(active) = find(&values, "ScreenSaveActive") {
        let record = &mut f.records[i];
        match data_of(active) {
            (Some(text), _, None) => record.enabled = Some(text.trim() != "0"),
            (_, _, why) => record.problems.push(format!(
                "ScreenSaveActive: {}",
                why.unwrap_or_else(|| "has no data".to_owned())
            )),
        }
    }
}

/// A user's classes under `base` (`Software\Classes` in `NTUSER.DAT`, the root of
/// `UsrClass.dat`): COM servers, shell commands, and app debuggers.
fn classes(f: &mut Found, base: &str, machine: Option<&MachineClasses>) {
    let under = |path: &str| {
        if base.is_empty() {
            path.to_owned()
        } else {
            format!(r"{base}\{path}")
        }
    };
    for (clsids, wow64) in [("CLSID", false), (r"Wow6432Node\CLSID", true)] {
        let Some((key, path)) = f.key(&under(clsids)) else {
            continue;
        };
        for (class, class_path) in f.subkeys(&key, &path) {
            let class_values = f.values(&class, &class_path);
            let name = find(&class_values, "")
                .and_then(|v| string(v).0)
                .filter(|n| !n.is_empty());
            for (server, server_path) in f.subkeys(&class, &class_path) {
                let kind = match server.name().to_ascii_lowercase().as_str() {
                    "inprocserver32" => Kind::Path,
                    "localserver32" => Kind::Command,
                    _ => continue,
                };
                let values = f.values(&server, &server_path);
                let Some(value) = find(&values, "") else {
                    continue;
                };
                let at = Place {
                    key: server,
                    path: &server_path,
                    wow64,
                };
                let Some(i) = f.one(Mechanism::ComServer, at, value, kind) else {
                    continue;
                };
                let record = &mut f.records[i];
                record.overrides_machine = machine.map(|m| m.has_class(&class.name(), wow64));
                record.details.clone_from(&name);
            }
        }
    }
    for (command, mechanism) in USER_COMMANDS {
        let Some((key, path)) = f.key(&under(command)) else {
            continue;
        };
        let at = Place {
            key,
            path: &path,
            wow64: false,
        };
        let values = f.values(&key, &path);
        let delegate = find(&values, "DelegateExecute").is_some();
        for name in ["", "IsolatedCommand"] {
            let Some(value) = find(&values, name) else {
                continue;
            };
            let Some(i) = f.one(mechanism, at, value, Kind::Command) else {
                continue;
            };
            let record = &mut f.records[i];
            record.overrides_machine = machine.map(|m| m.has_command(command));
            if delegate {
                record.details = Some("with a DelegateExecute value".to_owned());
            }
        }
    }
    if let Some((key, path)) = f.key(&under(r"ActivatableClasses\Package")) {
        for (_, package) in f.subkeys(&key, &path) {
            f.per_subkey(
                Mechanism::AppxDebugger,
                &format!(r"{package}\DebugInformation"),
                false,
                Kind::Command,
                "DebugPath",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(command: &str) -> Option<(&str, &str)> {
        // leaked for the comparisons' sake: tests only
        command_line(command).map(|(a, b)| (&*a.leak(), &*b.leak()))
    }

    #[test]
    fn command_lines() {
        assert_eq!(
            split(r#""C:\Program Files\App\app.exe" /background"#),
            Some((r"C:\Program Files\App\app.exe", "/background"))
        );
        assert_eq!(split(r#""C:\no end"#), None);
        assert_eq!(split("explorer.exe"), Some(("explorer.exe", "")));
        assert_eq!(
            split(r"C:\Windows\system32\rundll32.exe shell32.dll,Control_RunDLL"),
            Some((
                r"C:\Windows\system32\rundll32.exe",
                "shell32.dll,Control_RunDLL"
            ))
        );
        assert_eq!(
            split(r"C:\Program Files\App\app.exe -b x.exe"),
            Some((r"C:\Program Files\App\app.exe", "-b x.exe"))
        );
        assert_eq!(
            split(r"C:\Program Files\App\App.EXE"),
            Some((r"C:\Program Files\App\App.EXE", ""))
        );
        assert_eq!(split(r"cmd /c C:\x\a.exe"), Some(("cmd", r"/c C:\x\a.exe")));
        assert_eq!(
            split("autocheck autochk *"),
            Some(("autocheck", "autochk *"))
        );
        assert_eq!(split(r"C:\Program Files\App\run"), None);
        assert_eq!(split("  "), None);
    }

    #[test]
    fn startup_approved_entries() {
        let mut b = [0u8; 12];
        b[0] = 2;
        assert_eq!(
            startup_approved(&b),
            Ok(Approval {
                enabled: true,
                disabled_at: None
            })
        );
        b[0] = 3;
        b[4..].copy_from_slice(&132_888_278_320_000_000u64.to_le_bytes());
        assert_eq!(
            startup_approved(&b),
            Ok(Approval {
                enabled: false,
                disabled_at: Some(132_888_278_320_000_000)
            })
        );
        assert_eq!(startup_approved(&b[..8]), Err("8 bytes, not 12".to_owned()));
    }

    #[test]
    fn mechanisms_have_names_and_techniques() {
        assert_eq!(Mechanism::IfeoDebugger.name(), "ifeo_debugger");
        assert_eq!(Mechanism::ComServer.attack_technique(), Some("T1546.015"));
        assert_eq!(Mechanism::KnownDlls.attack_technique(), None);
    }
}
