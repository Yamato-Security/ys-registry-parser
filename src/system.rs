//! The `SYSTEM` hive: its control sets (`Select`), the computer's name, and its services with
//! their start, type, account, DLL and failure actions.
//!
//! A service's `FailureActions` is a `SERVICE_FAILURE_ACTIONS` as the Service Control Manager
//! writes it: the reset period, two fields that say whether a reboot message and a command are
//! set (the strings are the `RebootMessage` and `FailureCommand` values), the number of actions,
//! a pointer field (stale: an address in the writer's memory), then the `SC_ACTION`s (type and
//! delay in milliseconds), 8 bytes each.

use crate::bytes::u32_at;
use crate::data::{Data, decode};
use crate::hive::{Hive, Key, Status, Value};

/// The size of `FailureActions` before its actions.
const FAILURE_HEADER: usize = 20;
/// The size of one action.
const SC_ACTION: usize = 8;

/// The control sets of a `SYSTEM` hive: those `Select` names, and those it has.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ControlSets {
    /// The control set Windows used last (`Select\Current`).
    pub current: Option<u32>,
    /// `Select\Default`: the one Windows uses next.
    pub default: Option<u32>,
    /// `Select\Failed`: the one a boot failed with.
    pub failed: Option<u32>,
    /// `Select\LastKnownGood`.
    pub last_known_good: Option<u32>,
    /// The numbers of the `ControlSetNNN` keys the hive has, in order.
    pub present: Vec<u32>,
}

impl ControlSets {
    /// The control sets of `hive`.
    #[must_use]
    pub fn read(hive: &Hive) -> Self {
        let select = hive.key("Select");
        let number = |name: &str| {
            let value = select.as_ref()?.value(name)?;
            match decode(value.data_type(), &value.data().ok()?) {
                Data::Number(n) => u32::try_from(n).ok(),
                _ => None,
            }
        };
        let mut present: Vec<u32> = hive
            .root()
            .map(|root| root.subkeys().0)
            .unwrap_or_default()
            .iter()
            .filter_map(|k| control_set_number(&k.name()))
            .collect();
        present.sort_unstable();
        present.dedup();
        ControlSets {
            current: number("Current").filter(|&n| n > 0),
            default: number("Default"),
            failed: number("Failed"),
            last_known_good: number("LastKnownGood"),
            present,
        }
    }
}

/// The key name of control set `n`: `ControlSet001`.
#[must_use]
pub fn control_set_name(n: u32) -> String {
    format!("ControlSet{n:03}")
}

/// The number of a `ControlSetNNN` key name.
fn control_set_number(name: &str) -> Option<u32> {
    let digits = name
        .get(..10)?
        .eq_ignore_ascii_case("ControlSet")
        .then(|| &name[10..])?;
    (!digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
        .then(|| digits.parse().ok())
        .flatten()
}

/// The computer's name: `ComputerName` in the control set Windows used last (else the first it
/// has), or the TCP/IP host name.
#[must_use]
pub fn computer_name(hive: &Hive) -> Option<String> {
    let sets = ControlSets::read(hive);
    let set = control_set_name(sets.current.or(sets.present.first().copied()).unwrap_or(1));
    let text = |path: &str, name: &str| {
        string(&hive.key(path)?.value(name)?)
            .0
            .filter(|s| !s.is_empty())
    };
    text(
        &format!(r"{set}\Control\ComputerName\ComputerName"),
        "ComputerName",
    )
    .or_else(|| text(&format!(r"{set}\Services\Tcpip\Parameters"), "Hostname"))
}

/// A string value's text, and what is wrong with it: not a string (no text), or not valid
/// UTF-16 (the text with replacement characters). A value without data has neither.
fn string(value: &Value) -> (Option<String>, Option<String>) {
    let bytes = match value.data() {
        Ok(bytes) => bytes,
        Err(why) => return (None, Some(why)),
    };
    match decode(value.data_type(), &bytes) {
        Data::Text { value: text, lossy } => {
            let why = lossy.then(|| "is not valid UTF-16: decoded with replacements".to_owned());
            (Some(text), why)
        }
        // a string written as a multi-string: its one string (Windows shows it)
        Data::MultiText { values, lossy } if values.len() <= 1 => {
            let why = lossy.then(|| "is not valid UTF-16: decoded with replacements".to_owned());
            (values.into_iter().next(), why)
        }
        _ if bytes.is_empty() => (None, None),
        _ => (
            None,
            Some(format!("is {}, not a string", value.value_type().name())),
        ),
    }
}

/// A number value's number, or what is wrong with it.
fn number(value: &Value) -> Result<u32, String> {
    match decode(value.data_type(), &value.data()?) {
        Data::Number(n) => u32::try_from(n).map_err(|_| format!("{n} is too large")),
        Data::Malformed(why) => Err(why),
        _ => Err(format!("is {}, not a number", value.value_type().name())),
    }
}

/// What a service's `FailureActions` says to do when it fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureActions {
    /// Seconds without a failure after which the failure count goes back to 0; `u32::MAX`:
    /// never.
    pub reset_period: u32,
    /// Whether a reboot message is set (the `RebootMessage` value).
    pub reboot_message_set: bool,
    /// Whether a command is set (the `FailureCommand` value).
    pub command_set: bool,
    /// The action for the first failure, the second, …; the last one for every failure after.
    pub actions: Vec<FailureAction>,
    /// Bytes past the actions, which Windows doesn't write.
    pub trailing: usize,
}

/// One failure action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailureAction {
    /// What to do.
    pub action: Action,
    /// How long to wait first, in milliseconds.
    pub delay_ms: u32,
}

/// A failure action's type (`SC_ACTION_TYPE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// `SC_ACTION_NONE`.
    None,
    /// `SC_ACTION_RESTART`: start the service again.
    Restart,
    /// `SC_ACTION_REBOOT`: restart the computer.
    Reboot,
    /// `SC_ACTION_RUN_COMMAND`: run the `FailureCommand`.
    RunCommand,
    /// A type Windows doesn't define.
    Other(u32),
}

impl Action {
    /// The action of type `code`.
    #[must_use]
    pub fn from_code(code: u32) -> Self {
        match code {
            0 => Action::None,
            1 => Action::Restart,
            2 => Action::Reboot,
            3 => Action::RunCommand,
            other => Action::Other(other),
        }
    }

    /// `none`, `restart`, `reboot`, `run_command`; others in hex.
    #[must_use]
    pub fn name(self) -> String {
        match self {
            Action::None => "none".to_owned(),
            Action::Restart => "restart".to_owned(),
            Action::Reboot => "reboot".to_owned(),
            Action::RunCommand => "run_command".to_owned(),
            Action::Other(code) => format!("0x{code:x}"),
        }
    }
}

/// A `FailureActions` value's bytes, decoded.
///
/// # Errors
/// When they are shorter than the header, or than the actions it counts.
pub fn failure_actions(bytes: &[u8]) -> Result<FailureActions, String> {
    if bytes.len() < FAILURE_HEADER {
        return Err(format!(
            "FailureActions of {} bytes, shorter than its {FAILURE_HEADER}-byte header",
            bytes.len()
        ));
    }
    let field = |at: usize| u32_at(bytes, at).unwrap_or(0);
    let count = field(12) as usize;
    let room = (bytes.len() - FAILURE_HEADER) / SC_ACTION;
    if count > room {
        return Err(format!(
            "FailureActions counts {count} actions, its {} bytes hold {room}",
            bytes.len()
        ));
    }
    let actions = (0..count)
        .map(|i| {
            let at = FAILURE_HEADER + i * SC_ACTION;
            FailureAction {
                action: Action::from_code(field(at)),
                delay_ms: field(at + 4),
            }
        })
        .collect();
    Ok(FailureActions {
        reset_period: field(0),
        reboot_message_set: field(4) != 0,
        command_set: field(8) != 0,
        actions,
        trailing: bytes.len() - FAILURE_HEADER - count * SC_ACTION,
    })
}

/// A service: a subkey of a control set's `Services` key, with the values the Service Control
/// Manager reads. A value the key hasn't is `None`; one that can't be read or isn't of its type
/// is `None` too, and a problem.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Service {
    /// The key's name: the service's name.
    pub name: String,
    /// When the key was last written (FILETIME).
    pub last_written: u64,
    /// `DisplayName` (often a resource reference, `@%SystemRoot%\…dll,-100`).
    pub display_name: Option<String>,
    /// `Description`.
    pub description: Option<String>,
    /// `ImagePath`: the executable or driver, as written (`%SystemRoot%`, quotes, arguments).
    pub image_path: Option<String>,
    /// `Parameters\ServiceDll` (else `ServiceDll` in the key itself): the DLL a shared process
    /// loads.
    pub service_dll: Option<String>,
    /// `Start`: see [`start_name`].
    pub start: Option<u32>,
    /// `DelayedAutostart`: an automatic service started after the others.
    pub delayed_autostart: Option<bool>,
    /// `Type`: see [`type_names`].
    pub service_type: Option<u32>,
    /// `ErrorControl`: see [`error_control_name`].
    pub error_control: Option<u32>,
    /// `ObjectName`: the account it runs as (`LocalSystem`, `NT AUTHORITY\LocalService`, …).
    pub object_name: Option<String>,
    /// `Group`: its load order group.
    pub group: Option<String>,
    /// `FailureCommand`: what the `run_command` action runs.
    pub failure_command: Option<String>,
    /// `FailureActions`, decoded.
    pub failure_actions: Option<FailureActions>,
    /// `FailureActions`' bytes, when they don't decode.
    pub failure_actions_raw: Option<Vec<u8>>,
    /// Whether the transaction logs' replay wrote the key or one of its values.
    pub replayed: bool,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// The services of control set `set` (`ControlSet001` for 1), in the order of their names, and
/// what keeps others from being read; `None` when the hive has no such `Services` key.
#[must_use]
pub fn services(hive: &Hive, set: u32) -> Option<(Vec<Service>, Vec<String>)> {
    let key = hive.key(&format!(r"{}\Services", control_set_name(set)))?;
    let (keys, problems) = key.subkeys();
    Some((keys.iter().map(service).collect(), problems))
}

/// The service whose key is `key`.
fn service(key: &Key) -> Service {
    let (values, mut problems) = key.values();
    let mut replayed = key.status() == Status::Replayed;
    let mut s = Service {
        name: key.name(),
        last_written: key.last_written(),
        ..Service::default()
    };
    for value in &values {
        let name = value.name();
        let mut problem = |why: Option<String>| {
            if let Some(why) = why {
                problems.push(format!("{name}: {why}"));
            }
        };
        let text = |slot: &mut Option<String>| {
            let (text, why) = string(value);
            *slot = text;
            why
        };
        let num = |slot: &mut Option<u32>| number(value).map(|n| *slot = Some(n)).err();
        match name.to_ascii_lowercase().as_str() {
            "displayname" => problem(text(&mut s.display_name)),
            "description" => problem(text(&mut s.description)),
            "imagepath" => problem(text(&mut s.image_path)),
            "servicedll" => problem(text(&mut s.service_dll)),
            "objectname" => problem(text(&mut s.object_name)),
            "group" => problem(text(&mut s.group)),
            "failurecommand" => problem(text(&mut s.failure_command)),
            "start" => problem(num(&mut s.start)),
            "type" => problem(num(&mut s.service_type)),
            "errorcontrol" => problem(num(&mut s.error_control)),
            "delayedautostart" => {
                problem(
                    number(value)
                        .map(|n| s.delayed_autostart = Some(n != 0))
                        .err(),
                );
            }
            "failureactions" => match value.data() {
                Ok(bytes) => match failure_actions(&bytes) {
                    Ok(actions) => s.failure_actions = Some(actions),
                    Err(why) => {
                        problems.push(why);
                        s.failure_actions_raw = Some(bytes);
                    }
                },
                Err(why) => problem(Some(why)),
            },
            _ => continue,
        }
        replayed |= value.status() == Status::Replayed;
    }
    // a shared process's DLL is under Parameters (in the key itself on older systems)
    if let Some(parameters) = key.subkey("Parameters")
        && let Some(value) = parameters.value("ServiceDll")
    {
        let (dll, why) = string(&value);
        if dll.is_some() {
            s.service_dll = dll;
        }
        if let Some(why) = why {
            problems.push(format!(r"Parameters\ServiceDll: {why}"));
        }
        replayed |= value.status() == Status::Replayed;
    }
    s.replayed = replayed;
    s.problems = problems;
    s
}

/// A `Start` value's name: `boot`, `system`, `automatic`, `manual`, `disabled`; others in hex.
#[must_use]
pub fn start_name(start: u32) -> String {
    match start {
        0 => "boot".to_owned(),
        1 => "system".to_owned(),
        2 => "automatic".to_owned(),
        3 => "manual".to_owned(),
        4 => "disabled".to_owned(),
        other => format!("0x{other:x}"),
    }
}

/// The names of a `Type` value's flags (`kernel_driver`, `win32_own_process`,
/// `user_service`, …); bits Windows doesn't define in hex.
#[must_use]
pub fn type_names(service_type: u32) -> Vec<String> {
    const FLAGS: [(u32, &str); 10] = [
        (0x1, "kernel_driver"),
        (0x2, "file_system_driver"),
        (0x4, "adapter"),
        (0x8, "recognizer_driver"),
        (0x10, "win32_own_process"),
        (0x20, "win32_share_process"),
        (0x40, "user_service"),
        (0x80, "user_service_instance"),
        (0x100, "interactive_process"),
        (0x200, "package_service"),
    ];
    let mut names: Vec<String> = FLAGS
        .iter()
        .filter(|(bit, _)| service_type & bit != 0)
        .map(|(_, name)| (*name).to_owned())
        .collect();
    let known = FLAGS.iter().fold(0, |all, (bit, _)| all | bit);
    if service_type & !known != 0 {
        names.push(format!("0x{:x}", service_type & !known));
    }
    names
}

/// An `ErrorControl` value's name: `ignore`, `normal`, `severe`, `critical`; others in hex.
#[must_use]
pub fn error_control_name(error_control: u32) -> String {
    match error_control {
        0 => "ignore".to_owned(),
        1 => "normal".to_owned(),
        2 => "severe".to_owned(),
        3 => "critical".to_owned(),
        other => format!("0x{other:x}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actions(reset: u32, flags: (u32, u32), list: &[(u32, u32)]) -> Vec<u8> {
        let mut b = Vec::new();
        for v in [reset, flags.0, flags.1, list.len() as u32, 0x700f_0000] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        for (kind, delay) in list {
            b.extend_from_slice(&kind.to_le_bytes());
            b.extend_from_slice(&delay.to_le_bytes());
        }
        b
    }

    #[test]
    fn failure_actions_decode() {
        let fa = failure_actions(&actions(
            86_400,
            (0, 0),
            &[(1, 60_000), (1, 120_000), (0, 0)],
        ))
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(fa.reset_period, 86_400);
        assert!(!fa.reboot_message_set && !fa.command_set);
        assert_eq!(
            fa.actions,
            [
                FailureAction {
                    action: Action::Restart,
                    delay_ms: 60_000
                },
                FailureAction {
                    action: Action::Restart,
                    delay_ms: 120_000
                },
                FailureAction {
                    action: Action::None,
                    delay_ms: 0
                },
            ]
        );
        assert_eq!(fa.trailing, 0);
        // a command, a reboot, a type Windows doesn't define, bytes left over
        let mut bytes = actions(u32::MAX, (1, 1), &[(3, 0), (2, 5), (9, 1)]);
        bytes.extend_from_slice(&[0; 3]);
        let fa = failure_actions(&bytes).unwrap_or_else(|e| panic!("{e}"));
        let names: Vec<String> = fa.actions.iter().map(|a| a.action.name()).collect();
        assert_eq!(names, ["run_command", "reboot", "0x9"]);
        assert!(fa.reboot_message_set && fa.command_set);
        assert_eq!((fa.reset_period, fa.trailing), (u32::MAX, 3));
        // none at all
        assert_eq!(
            failure_actions(&actions(0, (0, 0), &[])).map(|f| f.actions.len()),
            Ok(0)
        );
    }

    #[test]
    fn failure_actions_that_dont_fit() {
        assert_eq!(
            failure_actions(&[0; 19]),
            Err("FailureActions of 19 bytes, shorter than its 20-byte header".to_owned())
        );
        let mut bytes = actions(0, (0, 0), &[(1, 1), (1, 1)]);
        bytes[12] = 3;
        assert_eq!(
            failure_actions(&bytes),
            Err("FailureActions counts 3 actions, its 36 bytes hold 2".to_owned())
        );
        bytes[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(failure_actions(&bytes).is_err());
    }

    #[test]
    fn names() {
        assert_eq!(start_name(2), "automatic");
        assert_eq!(start_name(7), "0x7");
        assert_eq!(type_names(0x10), ["win32_own_process"]);
        assert_eq!(
            type_names(0xe0),
            [
                "win32_share_process",
                "user_service",
                "user_service_instance"
            ]
        );
        assert_eq!(
            type_names(0x110),
            ["win32_own_process", "interactive_process"]
        );
        assert_eq!(type_names(0x1001), ["kernel_driver", "0x1000"]);
        assert_eq!(type_names(0), Vec::<String>::new());
        assert_eq!(error_control_name(1), "normal");
        assert_eq!(Action::from_code(2).name(), "reboot");
        assert_eq!(control_set_number("ControlSet001"), Some(1));
        assert_eq!(control_set_number("controlset002"), Some(2));
        assert_eq!(control_set_number("ControlSet"), None);
        assert_eq!(control_set_number("ControlSetX"), None);
        assert_eq!(control_set_name(3), "ControlSet003");
    }
}
