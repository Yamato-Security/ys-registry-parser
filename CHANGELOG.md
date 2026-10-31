# Changelog

## 1.0.0 (Unreleased)

First version. (@YamatoSecurity)

### Added
- `Hive`: a hive's base block (`Header`), its keys and values; `Hive::walk` (every key, depth
  first, each once, with its path) and `Hive::key` (a key by path, in any case).
- `Key`: name, last-write time, flags, parent, class name, counts, subkeys (`lf`, `lh`, `li`, `ri`
  lists) and values, with what keeps any from being read.
- `Value`: name, type, data in the value, in a cell or in big data segments; `decode` (`Data`,
  `ValueType`) and `filetime`.
- Transaction log replay (`Hive::open`, `find_logs`, `Recovery`), from ys-shimcache-parser, and
  where each key and value came from (`Status`: allocated, replayed, deleted).
- Deleted keys and values from free cells (`Hive::deleted`), with deleted keys' paths rebuilt
  from their parents.
- `open` and `open_with`: a hive file, with the logs next to it or given ones.
- `system`: a `SYSTEM` hive's control sets (`ControlSets`), computer name (`computer_name`) and
  services (`services`, `Service`), with `FailureActions` decoded (`failure_actions`) and names for
  start, type and error control values.
- `ntuser`: an `NTUSER.DAT` hive's recent documents (`recent_docs`, `RecentDocs`, `RecentDoc`) in
  their `MRUListEx` order (`mru_list_ex`), with each item's name and its shortcut's name
  (`recent_doc_data`), and the profile's name (`profile_name`).
- `software`: a `SOFTWARE` hive's Task Scheduler cache (`task_cache`, `ScheduledTask`): each task
  from its `Tree` entry and `Tasks` key, its lists, whether its security descriptor is there,
  `Actions` decoded by their structure (`task_actions`, `TaskActions`, `TaskAction`: exec, COM
  handler, e-mail, message box) and `DynamicInfo` (`dynamic_info`).
- `sam`: a `SAM` hive's local accounts (`accounts`, `Account`): `F` (`user_f`, `UserF`), `V`'s
  strings (`user_v`, `UserV`), the password hint, the linked Microsoft account, whether the
  sign-in screen hides the account, and its `Names` entry, matched with it; `account_flag_names`.
  Password hashes are not read.
- `persistence`: autostart locations in `SOFTWARE` (`software`), `SYSTEM` (`system`),
  `NTUSER.DAT` (`ntuser`) and `UsrClass.dat` (`usrclass`), one `Autostart` per program, DLL or
  package, with its `Mechanism` and MITRE ATT&CK technique: `Run` keys with `StartupApproved`
  (`startup_approved`), `Winlogon`, `AppInit_DLLs`, `AppCertDlls`, Image File Execution Options
  and `SilentProcessExit`, `Session Manager` (`BootExecute`, `KnownDLLs`,
  `PendingFileRenameOperations`), .NET profiler variables, LSA packages and security providers,
  print monitors, providers and processors, netsh helpers, time providers, Active Setup,
  `Command Processor` `AutoRun`, the screen saver, logon scripts, app debuggers, and a user's COM
  servers and `shell\open\command`s, with whether they override the machine's (`MachineClasses`).
  `command_line` splits a command line into its program and arguments. (@YamatoSecurity)
- `software::profile_list` (each profile's SID and folder) and `ntuser::classes_sid` (the SID a
  `UsrClass.dat` belongs to). (@YamatoSecurity)
- `Hive::recover` (`Recovered`, `RecoveredKey`, `RecoveredValue`, `RecoveredStatus`, `Source`):
  deleted keys and values from free cells, the slack of cells in use and the data past the hive
  bins, and what only the transaction logs kept (the hive before their replay, and each log
  entry's pages), each once with every place it was found and whether it is complete, partial, a
  value without its key, or only in the logs. The hive keeps its logs' entries from `Hive::open`.
