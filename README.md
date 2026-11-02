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
- Recovery (`Hive::recover`): the deleted records of the free cells, and also those in the slack
  of cells in use and in the data past the hive bins (at every even offset, as yarp's scanner
  reads them), and what only the transaction logs kept: the keys and values the hive held before
  their replay that it no longer holds, and those of each log entry, applied or older than the
  hive, read in its pages over the hive as it is (`Source`). Each record is given once with every
  place it was found and a status (`RecoveredStatus`): `deleted_complete` (its whole path and
  every value and data), `deleted_partial` (a path with `[unknown]` parts, or a value list,
  values or data lost to cells in use again), `residual_value_only` (a value no deleted key
  lists), `transaction_log_recovered` (only the logs hold it; with `in_use`, an earlier version
  of a key the hive has, with the values it held otherwise). A log entry's data is taken only
  where the entry wrote its cells, as they were then.
- `SYSTEM` hives (`system`): the control sets `Select` names and those the hive has
  (`ControlSets`), the computer's name (`computer_name`), and a control set's services
  (`services`): display name, description, image path, service DLL (`Parameters\ServiceDll`),
  start, delayed start, type, error control, account, group, failure command and failure
  actions, each service with the problems its values have. `failure_actions` decodes a
  `FailureActions` value (`SERVICE_FAILURE_ACTIONS`: reset period, whether a reboot message and a
  command are set, then each action and its delay); `start_name`, `type_names` and
  `error_control_name` name the numbers.
  `bam` gives when each user last ran each program as the Background and Desktop Activity
  Moderators recorded it: every value of each user's key (named after the user's SID) under
  `Services\bam` and `Services\dam`, in both layouts (`State\UserSettings`, Windows 10 1809 and
  later, and `UserSettings`, 1709 to 1803), without `Version` and `SequenceNumber`; the value's
  name is the program (a `\Device\HarddiskVolumeN\…` path, which `device_path` splits into the
  device and the path on it, or a packaged app's ID) and the first 8 bytes of its data are the
  time it last ran. Data that isn't `REG_BINARY` or holds fewer than 8 bytes keeps its bytes.
- `NTUSER.DAT` hives (`ntuser`): Explorer's recent documents (`recent_docs`), from `RecentDocs`
  and each of its subkeys (one per extension, and `Folder`): every item in the order of the key's
  `MRUListEx` (`mru_list_ex`), its name, and the name of its shortcut in the `Recent` folder (the
  long name in the file entry shell item's `0xBEEF0004` block, else its short name); items the
  list names but the key hasn't, and values the list doesn't name, are reported. `profile_name`
  gives the profile folder's name (`alice` for `C:\Users\alice`) from the shell folders' paths;
  `classes_sid` gives the SID a `UsrClass.dat` belongs to, from its root key's name.
  `user_assist` gives the programs and shortcuts a user started from Explorer (`UserAssist`):
  each `{GUID}` key's kind (`executable`, `shortcut`, …) and `Version`, each item's name decoded
  from ROT13 (`rot13`), its path with a known folder's GUID replaced by the folder's default path
  (`user_assist_path`, `known_folder_path`), and its data (`user_assist_data`: version 5's run
  count, focus count, focus time and last run; version 3's run count, stored plus 5, and last
  run), without the session entries. Data of another size, or a last run past 9999, keeps its
  bytes; with `NoEncrypt` set, each item says its name may not be ROT13.
  `user_assist_settings` reads what turns UserAssist off (`Start_TrackProgs`,
  `NoInstrumentation`, `NoLog`) or writes names without ROT13 (`NoEncrypt`).
  `mui_cache` gives the programs a user ran with the names Windows read from their version
  resources (`MuiCache`), from `UsrClass.dat` (`Local Settings\Software\Microsoft\Windows\Shell\MuiCache`,
  Windows Vista and later) and `NTUSER.DAT` (`Software\Microsoft\Windows\ShellNoRoam\MUICache`,
  Windows XP): one entry per program, its `<path>.FriendlyAppName` and `<path>.ApplicationCompany`
  values joined (Windows 8 and later), or its `<path>` value (Windows XP and 7), without `LangID`
  and the resource strings the shell cached (`@shell32.dll,-22019`, counted). A value that isn't
  text that decodes cleanly keeps its bytes. Case-insensitive joins do not expand characters:
  `straße.exe` and `STRASSE.EXE` remain separate programs, while `café.exe` and `CAFÉ.EXE` join.
- The Open and Save As dialogs' history in `NTUSER.DAT` (`comdlg32`): `dialogs` gives every
  entry of `ComDlg32`'s `OpenSavePidlMRU` (a subkey per extension, and `*`), `LastVisitedPidlMRU`,
  `LastVisitedPidlMRULegacy`, `CIDSizeMRU` and `FirstFolder`, and of Windows XP's `OpenSaveMRU`
  and `LastVisitedMRU`, in the order of its key's `MRUListEx` (numbered values) or `MRUList`
  (lettered values, a string of their letters), with the key's last-write time (which dates its
  most recent entry only): the program that showed the dialog, a path stored as text, or the
  shell item list (the file opened or saved, or the folder last used), kept as its bytes for a
  shell item parser; `item_list_problem` checks a list's layout. Values the list names but the key
  hasn't, values it doesn't name, and data that doesn't decode (kept as its bytes) are reported.
- ShellBags (`shellbags`): the folders a user opened in Explorer, from the `BagMRU` trees of
  `UsrClass.dat` (`Local Settings\Software\Microsoft\Windows\Shell\BagMRU`, and the 32-bit
  Explorer's under `Wow6432Node`) and `NTUSER.DAT` (`Software\Microsoft\Windows\Shell\BagMRU`,
  and Windows XP's `ShellNoRoam\BagMRU`). `shell_bags` gives every item from the top of each tree
  down, in `MRUListEx` order (an item, then the items under it): the item it is under, its place
  in its parent's list, its subkey's `NodeSlot` (its `Bags\N` key) and last-write time, the
  last-write time of the key its value is in (which dates the opening of the key's most recent
  item only), and its shell item list's bytes, for a shell item parser to decode (a link's
  target ID list has the same items). A listed value that isn't there, a value or subkey the
  list doesn't name, and a subkey without its value (the items under it are still read) are
  reported, and subkey lists that loop are read once.
- `SOFTWARE` hives (`software`): the Task Scheduler's cache (`task_cache`), each task from its
  `Tree` entry (name and folders, `Id`, `Index`, whether its `SD` is there: without it the Task
  Scheduler doesn't show the task) and its `Tasks\{GUID}` key (`Path`, `URI`, `Author`, …), the
  lists it is in (`Boot`, `Logon`, `Plain`, `Maintenance`), and tasks with only one of the two.
  `task_actions` decodes `Actions` by its structure, versions 1, 2 and 3 (including Windows
  Server 2016-era and current Windows 10+ layouts): the context, then each exec (program,
  arguments, working directory),
  COM handler (class id, data), e-mail and message box action, as far as the bytes go;
  `dynamic_info` decodes `DynamicInfo` (last registered, last run, state, last result, last
  successful run). `profile_list` gives each profile's SID and folder from `ProfileList`.
- `SAM` hives (`sam`): the local accounts (`accounts`), each from its key under
  `SAM\Domains\Account\Users`: `F` (`user_f`: last logon, password last set, account expiry,
  last failed logon, RID, account control flags, country code, code page, failed and total logon
  counts), `V`'s strings (`user_v`: user name, full name, comments, home directory and drive,
  logon script, profile path), the password hint, the Microsoft account it is linked to, and
  whether the sign-in screen hides it; its `Names` entry's RID and time (about when the account
  was made) are matched with it, and what disagrees is reported. `account_flag_names` names the
  flags. `machine_sid` gives the computer's SID (its local accounts' SIDs are it and their RIDs),
  from the end of `SAM\Domains\Account`'s `V`. Password hashes are not read.
- Autostart locations (`persistence`), one `Autostart` per program, DLL or package a value names
  (a list gives one each), with its `Mechanism` (`name`, and `attack_technique`: its MITRE
  ATT&CK technique, where one fits), key, value, data, program and arguments (`command_line`
  splits a command line where that can be told), whether it is enabled, and the problems its
  values have:
  - `software`: `Run`, `RunOnce` (and `Setup`), `RunOnceEx`, `RunServices(Once)` and
    `Policies\Explorer\Run`, with their `Wow6432Node` and Terminal Server install-mode copies;
    `Explorer\StartupApproved` (`startup_approved`: whether the Task Manager disabled an entry,
    and when), with the entries no `Run` value has and the Startup folder's files; `Winlogon`
    (`Shell`, `Userinit` and the rest, each comma-separated program, and `Notify`); `AppInit_DLLs`
    with `LoadAppInit_DLLs`; Image File Execution Options `Debugger` (with `UseFilter`'s
    `FilterFullPath`) and `VerifierDlls`, and `SilentProcessExit`'s `MonitorProcess`, enabled as
    `GlobalFlag` says (`MonitorProcess` also needs `ReportingMode`'s `0x1`); Active Setup `StubPath` (a `ShellComponent` DLL's argument on Windows
    10+); netsh helpers; `Command Processor` `AutoRun`.
  - `system`: `Session Manager`'s `BootExecute`, `SetupExecute` and the like,
    `PendingFileRenameOperations` (each file and where it goes), `KnownDLLs`, `AppCertDlls` and the
    .NET profiler's `Environment` variables; LSA authentication, security and notification
    packages and `SecurityProviders`; print monitors, providers and processors; time providers
    with `Enabled`.
  - `ntuser`: the user's `Run` keys and `StartupApproved`, `Windows` `Load` and `Run`,
    `Winlogon` `Shell`, `Environment` (`UserInitMprLogonScript`, the .NET profiler), the screen
    saver with `ScreenSaveActive`, `PackagedAppXDebug`, `Command Processor` `AutoRun`, and the
    classes under `Software\Classes` as in `UsrClass.dat`.
  - `usrclass`: COM servers (`CLSID\*\InprocServer32`, `LocalServer32`, and `Wow6432Node`'s),
    `shell\open\command` for program types (`exefile`, `batfile`, …) and for what auto-elevating
    programs start (`ms-settings`, `mscfile`, `Folder`, …), and app debuggers
    (`ActivatableClasses\…\DebugInformation`). With the machine's `MachineClasses` (read from
    `SOFTWARE`), each says whether it overrides the machine's registration of the same class or
    command.
- Installed software (`installed`), one `Program` per key, with its `ProgramSource`, `Scope`
  (`machine` or `user`), key and last-write time, and the problems its values have (their bytes
  kept): `software` reads `SOFTWARE`'s `Uninstall` entries (and `Wow6432Node`'s: name, version,
  publisher, install date written `YYYYMMDD` (`install_date`), folders, uninstall commands, size,
  `SystemComponent`, `WindowsInstaller`, the product code of an entry named after one, and its
  `DisplayIcon`, `ParentKeyName`, `ReleaseType` and `Inno Setup: User`), Windows Installer
  products (`Classes\Installer\Products`: the product code unpacked from the key's name
  (`unpack_guid`), `ProductName`, `Version` (`msi_version`), `PackageCode`, and the package's
  name and the folder it was last installed from, from `SourceList`), App Paths (the program and
  its `Path`, and `Wow6432Node`'s) and packaged apps (`Appx\AppxAllUserStore`'s `Applications`,
  `InboxApplications`, `Staged`, `Deprovisioned`, each user's `<SID>` and `EndOfLife\<SID>`, each
  package's name, version, architecture and publisher id from its full name (`package_name`), and
  its `Path`); `ntuser` reads a user's `Uninstall` entries, Windows Installer products
  (`Software\Microsoft\Installer\Products`), App Paths and WSL distributions (`Lxss\{GUID}`:
  `DistributionName`, `BasePath`, the WSL version its `Flags` say, `State`, `DefaultUid`, the file
  system's `Version`, `PackageFamilyName`, and whether it is the default).

- USB history (`usb`): from `SYSTEM`, a control set's USB storage devices (`Enum\USBSTOR`), USB
  devices (`Enum\USB`) and portable devices (`Enum\SWD\WPDBUSENUM`) (`devices`, `Device`): each
  with its type, vendor, product and revision, or vendor and product IDs (`storage_name`,
  `vid_pid`), its serial number (`serial`: without the logical unit, and none when Windows made
  the instance up), `FriendlyName`, `ContainerID`, driver, and the times its device properties
  keep (`{83da6326-97a6-4088-9453-a1923f573b29}`, in the Windows 8+ and the Windows 7 layout):
  driver last installed (`0064`), device first install (`0065`), last arrival (`0066`) and last
  removal (`0067`);
  `MountedDevices` (`mounted_devices`: each drive letter's and volume GUID's MBR disk signature
  and offset, GPT partition, or device path, and the device a path names, `device_ref`); from
  `SOFTWARE`, `Windows Portable Devices` (`portable_devices`: the name Explorer gave a device or
  volume) and ReadyBoost's `EMDMgmt` (`ready_boost`: a volume's label and serial number); from
  `NTUSER.DAT`, `MountPoints2` (`mount_points`: the volumes and shares a user had mounted, with
  `_LabelFromReg`). `history` joins them: one record per device and volume of its (letters,
  names, serial numbers, the users who had it), then the volumes no device key names (an internal
  disk's, or a removed device's whose `Enum` key is gone), drive letters without a volume GUID
  value, and the devices only `SOFTWARE` names.
  VID/PID joins require a matching usable container ID; serial fallback is used only without
  one. Conflicting matching IDs remain unknown and produce a problem. Contributing USB and
  portable-device keys retain their provenance and replay state, within the same control set.
  A property that isn't a FILETIME keeps its bytes in a problem.

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

// autostarts: SOFTWARE's, and a user's COM classes that override the machine's
use ys_registry_parser::persistence::{self, MachineClasses};
for autostart in persistence::software(&hive).0 {
    println!("{} {}\\{} = {:?}", autostart.mechanism.name(), autostart.key_path,
        autostart.value_name, autostart.data);
}
let (classes, _) = ys_registry_parser::open(std::path::Path::new("UsrClass.dat"))?;
let machine = MachineClasses::read(&hive);
for autostart in persistence::usrclass(&classes, Some(&machine)).0 {
    if autostart.overrides_machine == Some(true) {
        println!("overrides the machine's: {} = {:?}", autostart.key_path, autostart.image_path);
    }
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
- UserAssist on 12 public `NTUSER.DAT` hives (regipy's, Plaso's, notatin's and the DFIR Artifact
  Museum's, Windows XP to 11; 641 items): the same items, run counts, focus counts, focus times
  and last-run times as Plaso's `userassist`; the same as regipy's `user_assist` too, but for its
  duplicates and its rounding of times to the microsecond.
- The common dialogs' lists on the 9 public `NTUSER.DAT` hives with them (regipy's, Plaso's,
  notatin's and the DFIR Artifact Museum's, Windows XP to 10; 1,398 entries in all 7 lists): the
  same entries in the same order, with the same programs and paths, as Plaso's `mrulist` and
  `mrulistex` plugins. (regipy's `comdlg32` finds none on these hives: it reads the values' data
  as hex text.)
- MuiCache on 36 public `UsrClass.dat` and `NTUSER.DAT` hives (regipy's, Plaso's, notatin's,
  artemis' and the DFIR Artifact Museum's, Windows XP to 11; 16 with MuiCache, 827 values): the
  same programs, friendly names and companies as dissect.target's `muicache` and the same 197
  resource strings left out; the same values as regipy reads but for 2 paths whose one-byte names
  have a letter past ASCII (`Niðurhal`, `Startmenü`), which regipy decodes as `�`.
- ShellBags on 18 public `UsrClass.dat` and `NTUSER.DAT` hives (regipy's, Plaso's, notatin's,
  artemis' and the DFIR Artifact Museum's, Windows XP to 11; 252 items in 8 of them): the same
  keys and values as [libfwsi](https://github.com/libyal/libfwsi) with libregf, Plaso's
  `bagmru`, regipy's `shellbags_usrclass` and `shellbags_ntuser` (which don't read
  `ShellNoRoam`) and dissect.target's `shellbags` read, in the same `MRUListEx` order as the
  first three, with the same last-write times as regipy; regipy's `node_slot` is the `NodeSlot`
  of the key the value is in, not of the item's own key.
- The Task Scheduler's cache on 7 public `SOFTWARE` hives (regipy's Windows 7 and the DFIR
  Artifact Museum's Windows 10, 11, Server 2012 R2 and Server 2022 ones, the dirty ones with
  their logs; 1,233 tasks, 1,006 `Actions` with 441 exec and 566 COM handler actions): the same
  tasks, lists, actions and times as a separate decoder built on yarp, every `Actions` value
  decoded to its last byte.
- Local accounts on 7 public `SAM` hives (regipy's and the DFIR Artifact Museum's, Windows 7 to
  11, Server 2012 R2 and 2022; 30 accounts): every `F` and `V` field the same as
  [dissect](https://github.com/fox-it/dissect.target)'s `user_F` and `user_V` structures give,
  and the account expiry and logon counts as regipy's `samparse`.
- Recovery on regipy's `SAM`, `SECURITY`, `BCD`, `NTUSER.DAT` and its dirty `NTUSER.DAT` and
  `UsrClass.dat` with their logs: the same deleted keys (each once) as yarp's scanner finds in
  free cells, slack and the data past the hive bins, and the same value names and types but for
  one record whose type no Windows value has; on those two dirty hives and the DFIR Artifact
  Museum's Windows 11 `SYSTEM`, every key and value that yarp's replay removes or changes is
  recovered from the hive before the replay.
- BAM on 11 public `SYSTEM` hives (regipy's, Plaso's, notatin's, dissect's and the DFIR Artifact
  Museum's, Windows 7 to 11, Server 2012 R2 and 2022; 8 with BAM keys, both layouts, every
  control set; 199 entries): the same keys, SIDs, programs and times as regipy's `bam` plugin
  (which rounds times to the microsecond), and the same programs and times to the 100 ns as
  Plaso's `bam`. `machine_sid` on two of the Museum's Windows 10 systems: the SID of their local
  users' BAM keys and `ProfileList` entries, not their domain users'.
- Autostarts on 10 public `SOFTWARE` and `NTUSER.DAT` hives (regipy's, Plaso's, notatin's,
  artemis' and the DFIR Artifact Museum's Windows 10 ones): the same `Run`, `RunOnce`,
  `RunServices` and `Policies\Explorer\Run` values (27) as regipy's `software_plugin` and
  `ntuser_persistence`, and the same (none) `AppInit_DLLs` and IFEO debuggers as its
  `appinitdlls` and `image_file_execution_options`; on regipy's `SYSTEM`, the same LSA packages
  as its `lsa_packages`.
- Installed software on 10 public `SOFTWARE` and 19 public `NTUSER.DAT` hives (regipy's, Plaso's,
  notatin's, artemis' and the DFIR Artifact Museum's, Windows 7 to 11, Server 2012 R2 and 2022;
  1,731 records): the same 434 `Uninstall` entries (key, time and every value read) as regipy's
  `installed_programs_software` and `installed_programs_ntuser`, the same 112 Windows Installer
  products (key, time, `ProductName`) as its `software_classes_installer` and
  `ntuser_classes_installer`, the same 244 App Paths (program, `Path`, time) as its `app_paths`,
  and the same 7 WSL distributions as its `wsl` (which also lists `Lxss`'s `AppxInstallerCache`
  key as one); the same 913 packages (key, time, `Path`) as a reader built on yarp. regipy
  doesn't replay transaction logs: on the two dirty hives, with their logs not applied, the
  records are the same.
- USB history on 14 public `SYSTEM` hives (regipy's, Plaso's, dissect's, notatin's and the DFIR
  Artifact Museum's, Windows 7 to 11 and Server 2012 R2 and 2022): the same USB storage devices
  (16), USB devices (139) and `MountedDevices` values (138) as regipy's `usbstor_plugin`,
  `usb_devices` and `mounted_devices` (times to the microsecond regipy rounds to), but for
  regipy's Windows 7 hive, whose property times regipy doesn't read: there they are the ones
  Plaso's `windows_usbstor_devices` reads, as are the last-write times of 64 USB device keys
  (Plaso's `windows_usb_devices`). `MountPoints2` on 19 public `NTUSER.DAT` hives (118 keys): the
  same keys, servers, shares, labels and times as Plaso's `explorer_mountpoints2`. On the DFIR
  Artifact Museum's Windows 8.1 hives, `history` gives its 9 USB storage devices the same volume
  GUIDs, drive letters and users as dissect.target's `usb` plugin.
- 2,000 damaged copies of hives and their logs read without a panic, in under 10 ms each.
- In the tests: regipy's `SAM`, `SECURITY`, `BCD`, `NTUSER.DAT` and its dirty `NTUSER.DAT` and
  `UsrClass.dat` with their logs (counts, values of each type, what the logs changed, deleted keys
  with their paths); hives built with every kind of list, big data, damage, a loop, a lost root,
  and deleted keys under keys in use, deleted or lost; the replay on built logs; regipy's `SYSTEM`
  (control sets, computer name, services), its Windows 10 1709 `SYSTEM` (BAM in both layouts)
  and `NTUSER.DAT` (recent documents, profile, UserAssist, and its dirty `NTUSER.DAT` with the
  items its logs add), and its dirty `UsrClass.dat`'s MuiCache with the programs its logs add;
  MuiCache built in the Windows 8, 7 and XP forms, with both forms of one program, names in
  another case, resource strings, `LangID`, a value that isn't a string and one that isn't valid
  UTF-16; UserAssist built with both
  versions, a value of another size, a version that disagrees with the key's, an unknown GUID,
  session entries and `NoEncrypt`; recent
  documents whose list and values don't add up; a task cache built with real Windows 11 `Actions`
  and `DynamicInfo`, a task without its `SD`, a `Tree` entry without its `Tasks` key and the other
  way round, and `Actions` cut short; regipy's `SAM` (accounts, flags, times, `Names`); accounts
  whose `F`, `V` and `Names` disagree or are cut short, with a password hint, a Microsoft account
  and `UserDontShowInLogonUI`; regipy's `UsrClass.dat` ShellBags as it is and with its logs
  (order, parents, `NodeSlot`s, what the logs add), and `BagMRU` trees built with a missing,
  an unlisted and a non-binary value, a subkey without its value, a `NodeSlot` of the wrong type,
  `ShellNoRoam`, and subkey lists that loop; autostarts in regipy's `SYSTEM`, `NTUSER.DAT` and `UsrClass.dat`,
  and in built hives with one of each kind, `StartupApproved` entries enabled, disabled and
  without their `Run` value, IFEO `UseFilter` and `GlobalFlag` as a string, `SilentProcessExit`
  with each `ReportingMode` (0, 1, 2, 4, 7, none, unreadable), an Active Setup
  `ShellComponent`, and a user's COM classes and commands that do and don't override the
  machine's; BAM and DAM keys in both layouts with values that aren't `REG_BINARY` or are cut
  short; `SAM\Domains\Account` `V` with and without the computer's SID; regipy's `NTUSER-WSL.DAT`
  (a user's `Uninstall` entry, App Paths and WSL distributions); installed software built with
  each list, an `InstallDate` not written `YYYYMMDD`, a size written as text, a name that isn't
  valid UTF-16, a product whose key isn't a packed product code and whose `LastUsedSource` isn't
  `<type>;<index>;<source>`, deprovisioned and removed packages, a name that isn't a package's,
  and `Lxss` keys that aren't distributions; random damage, and random `Actions`, `F` and `V`.
  Common-dialog tests also cover Plaso's NTUSER.DAT, missing or unlisted values, truncated
  shell item lists and strings, incorrect registry types, and repeated MRUList entries.
  Test data provenance: `tests/fixtures/README.md`.

Not yet: security descriptors (`sk` cells); the data of a log entry's version of a value whose
data cells the entry didn't write.

## Licence

Apache-2.0 (`LICENSE`). The transaction log replay comes from Yamato Security's
[ys-shimcache-parser](https://github.com/Yamato-Security/ys-shimcache-parser) (Apache-2.0). The
format is Maxim Suhanov's [Windows registry file format specification](https://github.com/msuhanov/regf)
(CC BY 4.0). The test hives are regipy's, under the MIT licence (`tests/fixtures/regipy/LICENSE`),
and Plaso's, under the Apache License 2.0 (`tests/fixtures/plaso/LICENSE`).
