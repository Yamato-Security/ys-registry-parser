# ys-registry-parser

[![CI](https://github.com/Yamato-Security/ys-registry-parser/actions/workflows/ci.yml/badge.svg)](https://github.com/Yamato-Security/ys-registry-parser/actions/workflows/ci.yml)

Windows registry hives for forensics, by [Yamato Security](https://github.com/Yamato-Security):
`SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `NTUSER.DAT`, `UsrClass.dat`, `Amcache.hve` and any
other hive, on any OS. Every key with its last-write time and every value with its type and data;
a dirty hive's transaction logs replayed; and where each key and value came from: in use, from the
logs, or deleted and left in a free cell. It is the parser of
[Juntei](https://github.com/Yamato-Security/juntei)'s `parse-registry` commands.

The crate is `ys-registry-parser` (library `ys_registry_parser`), version 1.0.0, on Rust's 2024
edition; it needs Rust 1.99, has no dependencies and is not published to crates.io.

## What it reads

- The base block (`Header`): sequence numbers, last-write time, version, the root's offset, the
  hive bins' size, the checksum, and the path Windows recorded for the hive.
- Keys (`Key`): name, last-write time, flags, parent, class name, subkey and value counts; their
  subkeys through every kind of list (`lf`, `lh`, `li`, `ri`) and their values. `Hive::walk` gives
  every key depth first with its path, each once.
- Values (`Value`): name (empty for the default value), type and data, kept in the value itself
  (up to 4 bytes), in a cell, or in the segments of a big data record. `decode` turns data into
  text (`REG_SZ`, `REG_EXPAND_SZ`, `REG_LINK`), a list (`REG_MULTI_SZ`), a number (`REG_DWORD`,
  `REG_DWORD_BIG_ENDIAN`, `REG_QWORD`) or bytes (`REG_BINARY` and the rest), and says when data
  isn't what its type says (a `REG_DWORD` of 3 bytes). Decoded text carries a `lossy` flag, so an
  odd trailing byte or invalid UTF-16 surrogate can be distinguished from a valid literal U+FFFD
  and the original bytes preserved when needed. `filetime` turns a FILETIME (a key's last-write
  time, or a `REG_QWORD` holding one) into Unix seconds and nanoseconds.
- Transaction logs (`Hive::open`, `find_logs`): a dirty hive's `.LOG1` and `.LOG2` (or `.LOG`),
  new format (`HvLE` entries, checked by their Marvin32 hashes and sequence numbers) and old
  format (`DIRT`), replayed as Windows replays them; `Recovery` says what was applied and why a
  log was not. `Key::status` and `Value::status` say whether the replay changed a key's or value's
  cells (`Status::Replayed`) or not (`Status::Allocated`).
- Deleted keys and values (`Hive::deleted`): records in free cells that look like ones Windows
  writes (`Status::Deleted`). A deleted key's path is rebuilt from its parents, in use or deleted
  too (`[unknown]` where a parent is lost), and its values are read through its value list; a
  cell that is in use again is reported, not taken for the deleted record's. Deleted values no
  deleted key lists are kept apart: their key is unknown. In a replayed hive, `replayed` says
  which deleted records the logs wrote.
- `SYSTEM` hives (`system`): the control sets `Select` names and those the hive has
  (`ControlSets`), the computer's name (`computer_name`), and a control set's services
  (`services`): display name, description, image path, service DLL (`Parameters\ServiceDll`),
  start, delayed start, type, error control, account, group, failure command and failure
  actions, each service with the problems its values have. `failure_actions` decodes a
  `FailureActions` value (`SERVICE_FAILURE_ACTIONS`: reset period, whether a reboot message and a
  command are set, then each action and its delay); `start_name`, `type_names` and
  `error_control_name` name the numbers.
- `NTUSER.DAT` hives (`ntuser`): Explorer's recent documents (`recent_docs`), from `RecentDocs`
  and each of its subkeys (one per extension, and `Folder`): every item in the order of the key's
  `MRUListEx` (`mru_list_ex`), its name, and the name of its shortcut in the `Recent` folder (the
  long name in the file entry shell item's `0xBEEF0004` block, else its short name); items the
  list names but the key hasn't, and values the list doesn't name, are reported. `profile_name`
  gives the profile folder's name (`alice` for `C:\Users\alice`) from the shell folders' paths.
- `SOFTWARE` hives (`software`): the Task Scheduler's cache (`task_cache`), each task from its
  `Tree` entry (name and folders, `Id`, `Index`, whether its `SD` is there: without it the Task
  Scheduler doesn't show the task) and its `Tasks\{GUID}` key (`Path`, `URI`, `Author`, …), the
  lists it is in (`Boot`, `Logon`, `Plain`, `Maintenance`), and tasks with only one of the two.
  `task_actions` decodes `Actions` by its structure, versions 1, 2 and 3 (including Windows
  Server 2016-era and current Windows 10+ layouts): the context, then each exec (program,
  arguments, working directory),
  COM handler (class id, data), e-mail and message box action, as far as the bytes go;
  `dynamic_info` decodes `DynamicInfo` (last registered, last run, state, last result, last
  successful run).
- `SAM` hives (`sam`): the local accounts (`accounts`), each from its key under
  `SAM\Domains\Account\Users`: `F` (`user_f`: last logon, password last set, account expiry,
  last failed logon, RID, account control flags, country code, code page, failed and total logon
  counts), `V`'s strings (`user_v`: user name, full name, comments, home directory and drive,
  logon script, profile path), the password hint, the Microsoft account it is linked to, and
  whether the sign-in screen hides it; its `Names` entry's RID and time (about when the account
  was made) are matched with it, and what disagrees is reported. `account_flag_names` names the
  flags. Password hashes are not read.

Damage is reported, never a panic: a list, key or value that can't be read is a problem
(`Key::subkeys`, `Key::values`, `Value::read_data`) and what is next to it is still read; a list
that leads back to a key already read is read once; a base block whose root is not a key gives way
to the key flagged as the root.

## Use

```rust
let (hive, recovery) = ys_registry_parser::open(std::path::Path::new("SOFTWARE"))?;
if recovery.dirty && !recovery.recovered {
    eprintln!("dirty, without usable logs: keys or values may be missing");
}
let run = hive.key(r"Microsoft\Windows\CurrentVersion\Run").expect("the Run key");
for value in run.values().0 {
    let data = ys_registry_parser::decode(value.data_type(), &value.data()?);
    println!("{} ({}) = {data:?}", value.name(), value.value_type().name());
}
for key in hive.deleted().keys {
    println!("deleted: {} ({} values)", key.path, key.values.len());
}

// SYSTEM: the services of the control set Windows used last
use ys_registry_parser::system::{ControlSets, services};
let (system, _) = ys_registry_parser::open(std::path::Path::new("SYSTEM"))?;
let current = ControlSets::read(&system).current_or_first().unwrap_or(1);
for service in services(&system, current).map(|s| s.0).unwrap_or_default() {
    let actions = service.failure_actions.map(|f| f.actions).unwrap_or_default();
    println!("{} {:?} {actions:?}", service.name, service.image_path);
}
```

From Cargo, by commit:

```toml
ys_registry_parser = { package = "ys-registry-parser", git = "https://github.com/Yamato-Security/ys-registry-parser", rev = "<commit>" }
```

## How it's checked

- [yarp](https://github.com/msuhanov/yarp) (GPL-3.0, run as a reference, not part of the crate)
  on 24 public hives (regipy's, python-registry's, notatin's and the DFIR Artifact
  Museum's: `SYSTEM`, `SOFTWARE` with 117,488 keys, `SAM`, `SECURITY`, `BCD`, `NTUSER.DAT`,
  `UsrClass.dat`, `Amcache.hve`): the same keys, values, types, data (byte for byte) and last-write
  times. The 10 dirty ones replayed with their logs give what yarp recovers from them.
- On regipy's damaged `SYSTEM`, 1,687 keys and 5,625 values are read and 261 problems reported,
  where yarp can't open the hive and regipy stops after 260 keys.
- Deleted keys and values on 7 hives: the same deleted keys as yarp's scanner finds in free cells,
  and the same values; their data differs where a value's data cell is in use again (reported
  here, its bytes not taken for the deleted value's).
- Services on regipy's Windows 7 `SYSTEM` (both control sets, 933 services) and on the DFIR
  Artifact Museum's dirty Windows 11 `SYSTEM` with its logs (718): every value read and every
  `FailureActions` decoded the same as by a reader built on yarp.
- Recent documents on 9 public `NTUSER.DAT` hives (regipy's, notatin's and the DFIR Artifact
  Museum's, the dirty ones with their logs; 593 items): the same order, names and shortcut names
  as a reader built on yarp and [libfwsi](https://github.com/libyal/libfwsi)'s shell item
  parser.
- The Task Scheduler's cache on 7 public `SOFTWARE` hives (regipy's Windows 7 and the DFIR
  Artifact Museum's Windows 10, 11, Server 2012 R2 and Server 2022 ones, the dirty ones with
  their logs; 1,233 tasks, 1,006 `Actions` with 441 exec and 566 COM handler actions): the same
  tasks, lists, actions and times as a separate decoder built on yarp, every `Actions` value
  decoded to its last byte.
- Local accounts on 7 public `SAM` hives (regipy's and the DFIR Artifact Museum's, Windows 7 to
  11, Server 2012 R2 and 2022; 30 accounts): every `F` and `V` field the same as
  [dissect](https://github.com/fox-it/dissect.target)'s `user_F` and `user_V` structures give,
  and the account expiry and logon counts as regipy's `samparse`.
- 2,000 damaged copies of hives and their logs read without a panic, in under 10 ms each.
- In the tests: regipy's `SAM`, `SECURITY`, `BCD`, `NTUSER.DAT` and its dirty `NTUSER.DAT` and
  `UsrClass.dat` with their logs (counts, values of each type, what the logs changed, deleted keys
  with their paths); hives built with every kind of list, big data, damage, a loop, a lost root,
  and deleted keys under keys in use, deleted or lost; the replay on built logs; regipy's `SYSTEM`
  (control sets, computer name, services) and `NTUSER.DAT` (recent documents, profile); recent
  documents whose list and values don't add up; a task cache built with real Windows 11 `Actions`
  and `DynamicInfo`, a task without its `SD`, a `Tree` entry without its `Tasks` key and the other
  way round, and `Actions` cut short; regipy's `SAM` (accounts, flags, times, `Names`); accounts
  whose `F`, `V` and `Names` disagree or are cut short, with a password hint, a Microsoft account
  and `UserDontShowInLogonUI`; random damage, and random `Actions`, `F` and `V`.
  Test data provenance: `tests/fixtures/README.md`.

Not yet: deleted records in the slack of cells in use, in the data past the hive bins, or in the
transaction logs' older versions of cells; security descriptors (`sk` cells).

## Licence

Apache-2.0 (`LICENSE`). The transaction log replay comes from Yamato Security's
[ys-shimcache-parser](https://github.com/Yamato-Security/ys-shimcache-parser) (Apache-2.0). The
format is Maxim Suhanov's [Windows registry file format specification](https://github.com/msuhanov/regf)
(CC BY 4.0). The test hives are regipy's, under the MIT licence (`tests/fixtures/regipy/LICENSE`).
