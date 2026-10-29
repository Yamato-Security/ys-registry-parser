//! `SOFTWARE` hives: the Task Scheduler's cache (`TaskCache`).
//!
//! `TaskCache\Tree` holds the tasks by their names and folders: a task's key has its `Id` (the
//! `{GUID}` of its `Tasks` key), `Index` (which list it is in: 1 `Boot`, 2 `Logon`, 3 `Plain`; 0
//! none) and `SD`, the security descriptor without which the Task Scheduler doesn't show it.
//! `TaskCache\Tasks\{GUID}` holds its `Path`, `URI`, `Author`, `Actions`, `Triggers` and
//! `DynamicInfo`.
//!
//! `Actions` is a version (`u16`), from version 2 the context the actions run in (a principal's
//! id: `LocalSystem`, `Author`, …), then each action: its type (`0x6666` exec, `0x7777` COM
//! handler, `0x8888` e-mail, `0x9999` message box), its id, and its fields; a string is its size
//! in bytes (`u32`) and as many bytes of UTF-16. A version 3 exec action ends with 2 more bytes.
//! `DynamicInfo` is a version (`u32`), the times the task was last registered and last run
//! (FILETIMEs), its state and last result (`u32`s), and in its 36-byte form the time it last ran
//! successfully.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

use crate::bytes::{u16_at, u32_at, u64_at, utf16_units};
use crate::data::ValueType;
use crate::hive::{Hive, Key, Status, Value};
use crate::system::{number, string};

/// Where the Task Scheduler keeps its cache, under the hive's root.
pub const TASK_CACHE: &str = r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache";
/// The lists a task's `{GUID}` may be in, by the trigger that starts it.
const LISTS: [&str; 4] = ["Boot", "Logon", "Plain", "Maintenance"];

/// A task's `Actions` value, decoded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TaskActions {
    /// Its version: 1, 2 or 3. Version 2 is used by Windows Server 2016-era systems;
    /// version 3 is used by current Windows 10 and later systems.
    pub version: u16,
    /// The context the actions run in (from version 2): a principal's id.
    pub context: Option<String>,
    /// The actions, in their order.
    pub actions: Vec<TaskAction>,
}

/// One action of a task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskAction {
    /// Start a program.
    Exec {
        /// The action's id (usually empty).
        id: String,
        /// The program.
        command: String,
        /// Its arguments.
        arguments: String,
        /// The directory it starts in.
        working_directory: String,
    },
    /// Run a COM handler.
    ComHandler {
        /// The action's id.
        id: String,
        /// The handler's class id: `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
        class_id: String,
        /// The data it gets.
        data: String,
    },
    /// Send an e-mail (no longer supported by Windows, still stored).
    SendEmail {
        /// The action's id.
        id: String,
        /// `From`, `To`, `Cc`, `Bcc`, `ReplyTo`, the SMTP server, the subject and the body.
        fields: Vec<String>,
        /// The files attached.
        attachments: Vec<String>,
        /// The headers: names and values.
        headers: Vec<(String, String)>,
    },
    /// Show a message box (no longer supported by Windows, still stored).
    ShowMessage {
        /// The action's id.
        id: String,
        /// The box's title.
        title: String,
        /// Its message.
        message: String,
    },
}

impl TaskAction {
    /// `exec`, `com_handler`, `send_email` or `show_message`.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            TaskAction::Exec { .. } => "exec",
            TaskAction::ComHandler { .. } => "com_handler",
            TaskAction::SendEmail { .. } => "send_email",
            TaskAction::ShowMessage { .. } => "show_message",
        }
    }
}

/// Reads the fields of an `Actions` value in order.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn u16(&mut self) -> Result<u16, String> {
        let n = u16_at(self.bytes, self.at).ok_or_else(|| self.short("a 2-byte field"))?;
        self.at += 2;
        Ok(n)
    }

    fn u32(&mut self) -> Result<u32, String> {
        let n = u32_at(self.bytes, self.at).ok_or_else(|| self.short("a 4-byte field"))?;
        self.at += 4;
        Ok(n)
    }

    /// A string: its size in bytes, then UTF-16 (a NUL at its end left out).
    fn string(&mut self) -> Result<String, String> {
        let start = self.at;
        let size = self.u32()? as usize;
        let Some(bytes) = self
            .at
            .checked_add(size)
            .and_then(|end| self.bytes.get(self.at..end))
        else {
            return Err(format!(
                "a string of {size} bytes at {start} is cut short ({} bytes left)",
                self.bytes.len() - self.at
            ));
        };
        if !size.is_multiple_of(2) {
            return Err(format!("a string of {size} bytes at {start} is not UTF-16"));
        }
        self.at += size;
        let mut units = utf16_units(bytes);
        while units.last() == Some(&0) {
            units.pop();
        }
        String::from_utf16(&units).map_err(|_| format!("a string at {start} is not valid UTF-16"))
    }

    fn guid(&mut self) -> Result<String, String> {
        let b = self
            .bytes
            .get(self.at..self.at + 16)
            .ok_or_else(|| self.short("a class id"))?;
        self.at += 16;
        Ok(guid(b))
    }

    fn short(&self, what: &str) -> String {
        format!("{what} at {} is cut short", self.at)
    }
}

/// A GUID's 16 bytes as `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
fn guid(b: &[u8]) -> String {
    let d1 = u32_at(b, 0).unwrap_or(0);
    let d2 = u16_at(b, 4).unwrap_or(0);
    let d3 = u16_at(b, 6).unwrap_or(0);
    let hex = |bytes: &[u8]| {
        bytes.iter().fold(String::new(), |mut out, x| {
            let _ = write!(out, "{x:02X}");
            out
        })
    };
    format!(
        "{{{d1:08X}-{d2:04X}-{d3:04X}-{}-{}}}",
        hex(&b[8..10]),
        hex(&b[10..16])
    )
}

/// An `Actions` value's bytes, decoded as far as they go, and what stopped the decoding.
#[must_use]
pub fn task_actions(bytes: &[u8]) -> (TaskActions, Option<String>) {
    let mut r = Reader { bytes, at: 0 };
    let mut decoded = TaskActions::default();
    let problem = (|| -> Result<(), String> {
        decoded.version = r.u16()?;
        if decoded.version >= 2 {
            decoded.context = Some(r.string()?);
        }
        while r.at < bytes.len() {
            let kind = r.u16()?;
            if ![0x6666, 0x7777, 0x8888, 0x9999].contains(&kind) {
                return Err(format!(
                    "an action of unknown type 0x{kind:04x} at {}",
                    r.at - 2
                ));
            }
            let id = r.string()?;
            let action = match kind {
                0x6666 => {
                    let action = TaskAction::Exec {
                        id,
                        command: r.string()?,
                        arguments: r.string()?,
                        working_directory: r.string()?,
                    };
                    if decoded.version >= 3 {
                        r.u16()?;
                    }
                    action
                }
                0x7777 => TaskAction::ComHandler {
                    id,
                    class_id: r.guid()?,
                    data: r.string()?,
                },
                0x8888 => {
                    let fields = (0..8).map(|_| r.string()).collect::<Result<Vec<_>, _>>()?;
                    let count = r.u32()?;
                    let attachments = (0..count)
                        .map(|_| r.string())
                        .collect::<Result<Vec<_>, _>>()?;
                    let count = r.u32()?;
                    let headers = (0..count)
                        .map(|_| Ok((r.string()?, r.string()?)))
                        .collect::<Result<Vec<_>, String>>()?;
                    TaskAction::SendEmail {
                        id,
                        fields,
                        attachments,
                        headers,
                    }
                }
                // 0x9999, the last type there is
                _ => TaskAction::ShowMessage {
                    id,
                    title: r.string()?,
                    message: r.string()?,
                },
            };
            decoded.actions.push(action);
        }
        Ok(())
    })()
    .err();
    let problem = problem.map(|why| format!("Actions: {why}"));
    let problem = match (problem, decoded.version) {
        (None, v) if ![1, 2, 3].contains(&v) => {
            Some(format!("Actions: version {v} is not one seen"))
        }
        (problem, _) => problem,
    };
    (decoded, problem)
}

/// A task's `DynamicInfo` value, decoded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DynamicInfo {
    /// Its version.
    pub version: u32,
    /// When the task was last registered (created or changed; FILETIME).
    pub last_registered: u64,
    /// When it last started (FILETIME).
    pub last_run: u64,
    /// Its state.
    pub task_state: u32,
    /// Its last run's result (an `HRESULT` or exit code).
    pub last_result: u32,
    /// When it last ran successfully (FILETIME; the 36-byte form only).
    pub last_successful_run: Option<u64>,
}

/// A `DynamicInfo` value's bytes, decoded.
///
/// # Errors
/// When they are neither 28 nor 36 bytes.
pub fn dynamic_info(bytes: &[u8]) -> Result<DynamicInfo, String> {
    if bytes.len() != 28 && bytes.len() != 36 {
        return Err(format!(
            "DynamicInfo of {} bytes, not 28 or 36",
            bytes.len()
        ));
    }
    Ok(DynamicInfo {
        version: u32_at(bytes, 0).unwrap_or(0),
        last_registered: u64_at(bytes, 4).unwrap_or(0),
        last_run: u64_at(bytes, 12).unwrap_or(0),
        task_state: u32_at(bytes, 20).unwrap_or(0),
        last_result: u32_at(bytes, 24).unwrap_or(0),
        last_successful_run: u64_at(bytes, 28),
    })
}

/// A scheduled task from the cache: its `Tree` entry, its `Tasks` key, or both.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScheduledTask {
    /// Its name with its folders (`\Microsoft\Windows\Defrag\ScheduledDefrag`): its `Tree`
    /// path, else its `Tasks` key's `Path`.
    pub name: String,
    /// Its `{GUID}`: the `Tree` entry's `Id`, else its `Tasks` key's name.
    pub guid: Option<String>,
    /// The `Tree` entry's `Index`.
    pub index: Option<u32>,
    /// The lists its `{GUID}` is in (`Boot`, `Logon`, `Plain`, `Maintenance`).
    pub lists: Vec<String>,
    /// Whether it has a `Tree` entry: without one, the Task Scheduler doesn't list it.
    pub in_tree: bool,
    /// Whether the `Tree` entry has its security descriptor (`SD`); `None` without an entry.
    pub has_security_descriptor: Option<bool>,
    /// When its `Tree` entry was last written (FILETIME).
    pub tree_last_written: Option<u64>,
    /// Whether it has a `Tasks` key.
    pub in_tasks: bool,
    /// When its `Tasks` key was last written (FILETIME).
    pub task_last_written: Option<u64>,
    /// `Path`.
    pub path: Option<String>,
    /// `URI`.
    pub uri: Option<String>,
    /// `Author`.
    pub author: Option<String>,
    /// `Description`.
    pub description: Option<String>,
    /// `Source`.
    pub source: Option<String>,
    /// `Date` (as written: ISO 8601, without a zone).
    pub date: Option<String>,
    /// `Actions`, decoded as far as they go.
    pub actions: Option<TaskActions>,
    /// `Actions`' bytes, when they don't all decode.
    pub actions_raw: Option<Vec<u8>>,
    /// `DynamicInfo`, decoded.
    pub dynamic_info: Option<DynamicInfo>,
    /// Whether the transaction logs' replay wrote its keys or values.
    pub replayed: bool,
    /// What couldn't be read, and what doesn't match.
    pub problems: Vec<String>,
}

/// The tasks of the cache of `hive`, and what keeps parts of it from being read; `None` when
/// the hive has no `TaskCache`. The tasks come in the order of the `Tree` (depth first), then
/// those `Tasks` keys no `Tree` entry names.
#[must_use]
pub fn task_cache(hive: &Hive) -> Option<(Vec<ScheduledTask>, Vec<String>)> {
    let cache = hive.key(TASK_CACHE)?;
    let (subkeys, mut problems) = cache.subkeys();
    let sub = |name: &str| subkeys.iter().find(|k| k.name().eq_ignore_ascii_case(name));
    // the Tasks keys by their GUIDs, in upper case
    let mut tasks: Vec<(String, Key)> = Vec::new();
    if let Some(key) = sub("Tasks") {
        let (keys, why) = key.subkeys();
        problems.extend(why.into_iter().map(|w| format!(r"Tasks: {w}")));
        tasks = keys
            .into_iter()
            .map(|k| (k.name().to_uppercase(), k))
            .collect();
    }
    let mut lists: HashMap<String, Vec<String>> = HashMap::new();
    for list in LISTS {
        if let Some(key) = sub(list) {
            let (keys, why) = key.subkeys();
            problems.extend(why.into_iter().map(|w| format!("{list}: {w}")));
            for k in keys {
                lists
                    .entry(k.name().to_uppercase())
                    .or_default()
                    .push(list.to_owned());
            }
        }
    }
    let mut found = Vec::new();
    let mut named: HashSet<String> = HashSet::new();
    if let Some(tree) = sub("Tree") {
        for entry in hive.walk_from(*tree, String::new()) {
            for why in &entry.problems {
                problems.push(format!(r"Tree\{}: {why}", entry.path));
            }
            let Some(task) = tree_task(&entry.key, &entry.path, &tasks, &lists) else {
                continue;
            };
            if let Some(guid) = &task.guid {
                named.insert(guid.to_uppercase());
            }
            found.push(task);
        }
    }
    for (guid, key) in &tasks {
        if named.contains(guid) {
            continue;
        }
        let mut task = ScheduledTask {
            guid: Some(key.name()),
            lists: lists.get(guid).cloned().unwrap_or_default(),
            ..ScheduledTask::default()
        };
        read_task(key, &mut task);
        task.name = task.path.clone().unwrap_or_default();
        found.push(task);
    }
    Some((found, problems))
}

/// The task whose `Tree` entry is `key` (at `path` under `Tree`); `None` for a folder (a key
/// without `Id`).
fn tree_task(
    key: &Key,
    path: &str,
    tasks: &[(String, Key)],
    lists: &HashMap<String, Vec<String>>,
) -> Option<ScheduledTask> {
    let (values, mut problems) = key.values();
    for name in ["Id", "Index", "SD"] {
        if values
            .iter()
            .filter(|value| value.name().eq_ignore_ascii_case(name))
            .count()
            > 1
        {
            problems.push(format!("value {name:?} is present more than once"));
        }
    }
    let find = |name: &str| values.iter().find(|v| v.name().eq_ignore_ascii_case(name));
    let id = find("Id")?;
    let mut task = ScheduledTask {
        name: format!(r"\{path}"),
        in_tree: true,
        has_security_descriptor: Some(find("SD").is_some()),
        tree_last_written: Some(key.last_written()),
        replayed: key.status() == Status::Replayed
            || values.iter().any(|v| v.status() == Status::Replayed),
        ..ScheduledTask::default()
    };
    let (guid, why) = string(id);
    problems.extend(why.map(|w| format!("Id: {w}")));
    task.guid = guid.map(|g| g.trim_end_matches('\0').to_owned());
    if let Some(index) = find("Index") {
        match number(index) {
            Ok(n) => task.index = Some(n),
            Err(why) => problems.push(format!("Index: {why}")),
        }
    }
    task.problems = problems;
    let Some(guid) = task.guid.clone() else {
        return Some(task);
    };
    task.lists = lists.get(&guid.to_uppercase()).cloned().unwrap_or_default();
    if let Some((_, key)) = tasks.iter().find(|(g, _)| *g == guid.to_uppercase()) {
        read_task(key, &mut task);
        if let Some(p) = task
            .path
            .as_ref()
            .filter(|p| !p.eq_ignore_ascii_case(&task.name))
        {
            task.problems
                .push(format!("its Tasks key's Path is {p}, not its Tree name"));
        }
    }
    Some(task)
}

/// The values of the task's `Tasks` key.
fn read_task(key: &Key, task: &mut ScheduledTask) {
    let (values, problems) = key.values();
    task.in_tasks = true;
    task.task_last_written = Some(key.last_written());
    task.replayed |= key.status() == Status::Replayed;
    task.problems
        .extend(problems.into_iter().map(|w| format!("Tasks: {w}")));
    let mut seen = HashSet::new();
    for value in &values {
        task.replayed |= value.status() == Status::Replayed;
        let name = value.name();
        let canonical = name.to_ascii_lowercase();
        let known = matches!(
            canonical.as_str(),
            "path"
                | "uri"
                | "author"
                | "description"
                | "source"
                | "date"
                | "actions"
                | "dynamicinfo"
        );
        if known && !seen.insert(canonical.clone()) {
            task.problems
                .push(format!("value {name:?} is present more than once"));
            continue;
        }
        let text = |slot: &mut Option<String>, problems: &mut Vec<String>| {
            let (text, why) = string(value);
            *slot = text;
            problems.extend(why.map(|w| format!("{name}: {w}")));
        };
        match canonical.as_str() {
            "path" => text(&mut task.path, &mut task.problems),
            "uri" => text(&mut task.uri, &mut task.problems),
            "author" => text(&mut task.author, &mut task.problems),
            "description" => text(&mut task.description, &mut task.problems),
            "source" => text(&mut task.source, &mut task.problems),
            "date" => text(&mut task.date, &mut task.problems),
            "actions" => actions(value, task),
            "dynamicinfo" => {
                let (bytes, why) = value.read_data();
                task.problems
                    .extend(why.map(|w| format!("DynamicInfo: {w}")));
                if value.value_type() != ValueType::Binary {
                    task.problems.push(format!(
                        "DynamicInfo: is {}, not REG_BINARY",
                        value.value_type().name()
                    ));
                }
                match dynamic_info(&bytes) {
                    Ok(info) => task.dynamic_info = Some(info),
                    Err(why) => task.problems.push(format!("DynamicInfo: {why}")),
                }
            }
            _ => {}
        }
    }
}

/// The task's `Actions`, with their bytes kept when they don't all decode.
fn actions(value: &Value, task: &mut ScheduledTask) {
    let (bytes, why) = value.read_data();
    let (decoded, problem) = task_actions(&bytes);
    let problems: Vec<String> = why
        .map(|w| format!("Actions: {w}"))
        .into_iter()
        .chain(
            (value.value_type() != ValueType::Binary)
                .then(|| format!("Actions: is {}, not REG_BINARY", value.value_type().name())),
        )
        .chain(problem)
        .collect();
    if !problems.is_empty() {
        task.actions_raw = Some(bytes);
    }
    task.problems.extend(problems);
    task.actions = Some(decoded);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(text: &str) -> Vec<u8> {
        let bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut out = (bytes.len() as u32).to_le_bytes().to_vec();
        out.extend(bytes);
        out
    }

    const CLSID: [u8; 16] = [
        0x9d, 0xe3, 0x0b, 0x90, 0xe8, 0x6b, 0x1a, 0x46, 0xbc, 0x4d, 0xb0, 0xfa, 0x71, 0xf5, 0xec,
        0xb1,
    ];

    #[test]
    fn version_3_actions() {
        let mut b = 3u16.to_le_bytes().to_vec();
        b.extend(s("LocalSystem"));
        b.extend([0x66, 0x66]);
        b.extend(s(""));
        b.extend(s(r"C:\ProgramData\example\run.exe"));
        b.extend(s("/quiet"));
        b.extend(s(r"C:\ProgramData"));
        b.extend([0, 0]);
        b.extend([0x77, 0x77]);
        b.extend(s(""));
        b.extend(CLSID);
        b.extend(s("data"));
        b.extend([0x99, 0x99]);
        b.extend(s(""));
        b.extend(s("Title"));
        b.extend(s("Hello"));
        let (actions, problem) = task_actions(&b);
        assert_eq!(problem, None);
        assert_eq!(actions.context.as_deref(), Some("LocalSystem"));
        assert_eq!(
            actions.actions,
            [
                TaskAction::Exec {
                    id: String::new(),
                    command: r"C:\ProgramData\example\run.exe".into(),
                    arguments: "/quiet".into(),
                    working_directory: r"C:\ProgramData".into(),
                },
                TaskAction::ComHandler {
                    id: String::new(),
                    class_id: "{900BE39D-6BE8-461A-BC4D-B0FA71F5ECB1}".into(),
                    data: "data".into(),
                },
                TaskAction::ShowMessage {
                    id: String::new(),
                    title: "Title".into(),
                    message: "Hello".into(),
                },
            ]
        );
    }

    #[test]
    fn version_1_and_e_mail_actions() {
        // version 1: no context, no 2 bytes after an exec action
        let mut b = 1u16.to_le_bytes().to_vec();
        b.extend([0x66, 0x66]);
        b.extend(s(""));
        b.extend(s(r"%windir%\system32\sc.exe"));
        b.extend(s("start w32time"));
        b.extend(s(""));
        b.extend([0x88, 0x88]);
        b.extend(s(""));
        for field in ["a@x", "b@x", "", "", "", "smtp", "Subject", "Body"] {
            b.extend(s(field));
        }
        b.extend(1u32.to_le_bytes());
        b.extend(s(r"C:\f.txt"));
        b.extend(1u32.to_le_bytes());
        b.extend(s("X-Name"));
        b.extend(s("value"));
        let (actions, problem) = task_actions(&b);
        assert_eq!(problem, None);
        assert_eq!(actions.context, None);
        let kinds: Vec<&str> = actions.actions.iter().map(TaskAction::kind).collect();
        assert_eq!(kinds, ["exec", "send_email"]);
        let TaskAction::SendEmail {
            fields,
            attachments,
            headers,
            ..
        } = &actions.actions[1]
        else {
            panic!("not an e-mail");
        };
        assert_eq!((fields[0].as_str(), fields[7].as_str()), ("a@x", "Body"));
        assert_eq!(attachments, &[r"C:\f.txt".to_owned()]);
        assert_eq!(headers, &[("X-Name".to_owned(), "value".to_owned())]);
    }

    #[test]
    fn version_2_actions_are_supported() {
        let mut b = 2u16.to_le_bytes().to_vec();
        b.extend(s("LocalSystem"));
        b.extend([0x66, 0x66]);
        b.extend(s(""));
        b.extend(s(r"C:\Windows\Temp\helper.exe"));
        b.extend(s("--run"));
        b.extend(s(r"C:\Windows\Temp"));
        let (actions, problem) = task_actions(&b);
        assert_eq!(problem, None);
        assert_eq!(actions.version, 2);
        assert_eq!(actions.context.as_deref(), Some("LocalSystem"));
        assert_eq!(actions.actions.len(), 1);
    }

    #[test]
    fn actions_that_dont_decode() {
        // what was read before the damage is kept
        let mut b = 3u16.to_le_bytes().to_vec();
        b.extend(s("Author"));
        b.extend([0x66, 0x66]);
        b.extend(s(""));
        b.extend(s("a.exe"));
        b.extend(s(""));
        b.extend(s(""));
        b.extend([0, 0]);
        b.extend([0x55, 0x55]);
        let (actions, problem) = task_actions(&b);
        assert_eq!(actions.actions.len(), 1);
        assert_eq!(
            problem.as_deref(),
            Some("Actions: an action of unknown type 0x5555 at 48")
        );
        let mut b = 3u16.to_le_bytes().to_vec();
        b.extend(100u32.to_le_bytes());
        b.extend([0x41, 0]);
        assert_eq!(
            task_actions(&b).1.as_deref(),
            Some("Actions: a string of 100 bytes at 2 is cut short (2 bytes left)")
        );
        assert_eq!(
            task_actions(&[3]).1.as_deref(),
            Some("Actions: a 2-byte field at 0 is cut short")
        );
        let (_, problem) = task_actions(&[7, 0, 0, 0, 0, 0]);
        assert_eq!(
            problem.as_deref(),
            Some("Actions: version 7 is not one seen")
        );
    }

    #[test]
    fn dynamic_infos() {
        let mut b = vec![0u8; 36];
        b[..4].copy_from_slice(&3u32.to_le_bytes());
        b[4..12].copy_from_slice(&11u64.to_le_bytes());
        b[12..20].copy_from_slice(&22u64.to_le_bytes());
        b[24..28].copy_from_slice(&0x8004_1315u32.to_le_bytes());
        b[28..36].copy_from_slice(&33u64.to_le_bytes());
        let info = dynamic_info(&b).unwrap_or_default();
        assert_eq!(
            (
                info.last_registered,
                info.last_run,
                info.last_result,
                info.last_successful_run
            ),
            (11, 22, 0x8004_1315, Some(33))
        );
        assert_eq!(
            dynamic_info(&b[..28]).map(|i| i.last_successful_run),
            Ok(None)
        );
        assert!(dynamic_info(&b[..20]).is_err());
        assert_eq!(guid(&CLSID), "{900BE39D-6BE8-461A-BC4D-B0FA71F5ECB1}");
    }
}
