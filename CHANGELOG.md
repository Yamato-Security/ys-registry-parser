# Changelog

## 1.0.0 (Unreleased)

First version. (@YamatoSecurity)

### Fixed
- Office retains malformed trusted-location and multi-string bytes, diagnoses invalid timestamps,
  and leaves unknown trust flags unknown instead of claiming macros are disabled. (@YamatoSecurity)
- Security settings keep AMSI COM-value damage and replay provenance, reject invalid RDP ports
  and distinguish legacy Defender configuration from effective protection. (@YamatoSecurity)
- FeatureUsage preserves malformed RecentApps values, diagnoses a missing first ProgramsCache
  item, rejects truncated shortcut headers and invalid offsets, and joins local shortcut path
  components without inventing separators. (@YamatoSecurity)
- Application history retains zero-length malformed values and empty damaged multi-strings,
  validates 7-Zip history types, and avoids claiming first use for declined or damaged EULAs.
  (@YamatoSecurity)
- Preserve damaged WordWheelQuery bytes and report odd UTF-16 lengths or nonzero data after
  the terminator instead of silently discarding them. (@YamatoSecurity)
- Validate LSA string headers and Source OS calendar dates; report incomplete profile FILETIMEs
  instead of silently dropping them. Reuse the validated SAM machine-SID reader. (@YamatoSecurity)
- Preserve diagnostics and original bytes for malformed installed-program values, including
  zero-byte values and WSL's parent default-distribution value; retain replay provenance for
  that parent value and validate four-component, 16-bit package versions. (@YamatoSecurity)
- Keep distinct Unicode registry names and MuiCache paths separate when uppercasing would
  expand one character into several, while retaining ordinary case-insensitive joins. This
  prevents incorrect key/value lookups and metadata being joined to a different program.
  (@YamatoSecurity)

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
- `ntuser::user_assist` (`UserAssistEntry`): the programs and shortcuts a user started from
  Explorer, with each item's name decoded from ROT13 (`rot13`), its path with known folders
  resolved (`user_assist_path`, `known_folder_path`), and its run count, focus count and time and
  last run (`user_assist_data`, `UserAssistData`: versions 5 and 3); `user_assist_settings`
  (`UserAssistSettings`): what turns UserAssist off. (@YamatoSecurity)
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
- `comdlg32` (`dialogs`, `DialogEntry`, `DialogList`, `item_list_problem`): the Open and Save As
  dialogs' history in `NTUSER.DAT`: `OpenSavePidlMRU` by extension, `LastVisitedPidlMRU`,
  `LastVisitedPidlMRULegacy`, `CIDSizeMRU`, `FirstFolder`, and Windows XP's `OpenSaveMRU` and
  `LastVisitedMRU`, each entry in the order of its key's `MRUListEx` or `MRUList`, with its
  program, its path, or its shell item list's bytes. (@YamatoSecurity)
- MRUList value names use registry-style Unicode uppercase comparisons; malformed UTF-16 and
  missing string terminators are reported, and damaged or repeated entries do not shift later
  entries into position zero. (@YamatoSecurity)
- `installed` (`Program`, `ProgramSource`, `Scope`): installed software, in `SOFTWARE`
  (`software`: `Uninstall` and `Wow6432Node`'s, Windows Installer products, App Paths, packaged
  apps of `Appx\AppxAllUserStore`) and `NTUSER.DAT` (`ntuser`: a user's `Uninstall`, Windows
  Installer products, App Paths and WSL distributions), one record per key with its name,
  version, publisher, install date, folders, uninstall commands, size, product code and
  architecture; `unpack_guid` (a Windows Installer packed product code), `msi_version`,
  `package_name` (a package's full or family name) and `install_date` (`YYYYMMDD`).
  (@YamatoSecurity)
- `ntuser::mui_cache` (`MuiCache`, `MuiCacheEntry`, `MUI_CACHE`, `MUI_CACHE_XP`): the programs a
  user ran with the names and companies Windows read from their version resources, from
  `UsrClass.dat` (Vista and later) and `NTUSER.DAT` (XP), each program's values joined, without
  `LangID` and the cached resource strings. (@YamatoSecurity)
- `shellbags`: the `BagMRU` trees of `UsrClass.dat` and `NTUSER.DAT` (`shell_bags`, `ShellBag`,
  `LOCATIONS`: `Shell` and Windows XP's `ShellNoRoam`, and the 32-bit Explorer's under
  `Wow6432Node`): every item from the top of each tree down, in `MRUListEx` order, with its
  parent item, its place in the list, its subkey's `NodeSlot` and last-write time, the
  last-write time of the key its value is in, and its shell item list's bytes (decode them with
  a shell item parser). A listed value that isn't there, a value or subkey the list doesn't
  name, a subkey without its value (the items under it are still read), and subkey lists that
  loop are reported. (@YamatoSecurity)
- `system::bam` (`BamEntry`, `Moderator`): when each user last ran each program as the Background
  and Desktop Activity Moderators recorded it, from `Services\bam` and `Services\dam` in both
  layouts (`State\UserSettings` and `UserSettings`), and `device_path`, which splits a
  `\Device\HarddiskVolumeN\…` path into the device and the path on it; `sam::machine_sid`: the
  computer's SID. (@YamatoSecurity)
- `usb`: USB history. From `SYSTEM`, USB storage, USB and portable devices (`devices`, `Device`)
  with their names, IDs, serial numbers and device first install, driver last installed, last
  arrival and last removal times, and `MountedDevices` (`mounted_devices`, `MountTarget`, `device_ref`); from `SOFTWARE`,
  `Windows Portable Devices` (`portable_devices`) and ReadyBoost's `EMDMgmt` (`ready_boost`);
  from `NTUSER.DAT`, `MountPoints2` (`mount_points`); `history` joins them into one record per
  device and volume, with the users who had it. (@YamatoSecurity)
- `remote_access`: the remote connections a user made, from `NTUSER.DAT` (`connections`,
  `Connection`, `Kind`, `Client`): Remote Desktop's `Terminal Server Client` (`Default` MRU,
  `Servers` with `UsernameHint` and `CertHash`, `LocalDevices`), PuTTY's and WinSCP's saved
  sessions and accepted SSH host keys with their OpenSSH SHA-256 fingerprints
  (`host_key_fingerprint`, `host_key_blob`, `host_key_name`), whether a session stores a password
  (never decoded), PuTTY's recent sessions, mapped drives (`Network`, `Map Network Drive MRU` with
  `mru_list`) and `MountPoints2` shares (`mount_point_share`); `rdp_target` and `unescape`.
  (@YamatoSecurity)

- Remote-access MRU matching follows registry Unicode case comparisons, and stored password presence is checked without exposing malformed password bytes in diagnostic output. (@YamatoSecurity)
- `system_info`: what a timeline needs to know about a system. `system` (`SystemDetails`): a
  `SYSTEM` hive's computer name, host name and DNS domain, time zone (`TimeZone`, with
  `StandardStart` and `DaylightStart` decoded as the kernel's `TIME_FIELDS` by `TransitionDate`),
  last shutdown, processor architecture, code pages, and the versions it was upgraded from
  (`PreviousVersion`); `software` (`SoftwareDetails`): a `SOFTWARE` hive's Windows version
  (`WindowsVersion`), profiles (`Profile`, with load and unload times) and last signed-in user
  (`LastLoggedOn`); `machine_sid`: a `SAM` hive's computer SID; `domains` (`Domains`): the account
  and primary domains, DNS names, domain GUID and computer account SID in a `SECURITY` hive's LSA
  policy; `sid` and `utc_offset`. (@YamatoSecurity)
- `mru` (`mru_lists`, `MruEntry`, `MruList`, `acmru_search`): most-recently-used lists in
  `NTUSER.DAT`: `RunMRU`, `TypedPaths`, `WordWheelQuery`, `TypedURLs` with `TypedURLsTime`,
  Paint's and WordPad's recent files, and Windows XP's `ACMru`, each entry in its list's order.
  `ntuser::mru_items` and `ntuser::mru_list_items` order a key's values by its `MRUListEx` or
  `MRUList`. (@YamatoSecurity)
- `app_history` (`AppTrace`, `App`): traces third-party tools leave in `NTUSER.DAT`
  (`app_history::ntuser`): Sysinternals tools whose licence the user accepted (with when they
  first ran), WinRAR's, 7-Zip's and WinZip's archive and folder history, OneDrive accounts and
  their synced folders, Adobe Acrobat's and Reader's recent files and folders, and TeamViewer's and
  CCleaner's values; list entries with their positions. (@YamatoSecurity)
- `ntuser`: Explorer's use of applications (`AppUsage`): `feature_usage` (`FeatureUsage`
  counts per application and button) and `feature_usage_created`, `recent_apps` (`RecentApps`
  and their `RecentItems`), `taskband` (the taskbar's pins in `Favorites`, with their
  application IDs and pin types, and `FavoritesResolve`'s links) and `programs_cache` (the shell
  item lists of `ProgramsCache`, `ProgramsCacheSMP` and `ProgramsCacheTBP`). (@YamatoSecurity)
- `security_settings`: the security settings attackers change, in `SOFTWARE` (`software`), a
  `SYSTEM` control set (`system`) and `NTUSER.DAT` (`ntuser`): one `Setting` per value with its
  `Area`, value, meaning, whether it weakens the default and whether it comes from a `Policies`
  key; Microsoft Defender (with each exclusion), UAC, `WDigest`, LSA protection, Credential Guard,
  Restricted Admin, NTLM, Remote Desktop, the firewall, SMBv1, PowerShell (execution policy,
  logging, AMSI providers), last access times, System Restore and event log sizes and channels.
  (@YamatoSecurity)
- `office` (`office`, `OfficeEntry`, `OfficeList`, `mru_item`, `trust_record`, `setting_meaning`,
  `MACROS_ENABLED`): Microsoft Office in `NTUSER.DAT`: each version's and application's
  `File MRU` and `Place MRU` (with Microsoft 365 accounts' `User MRU`), each item's path and
  last-opened time; `Trusted Documents\TrustRecords`, with when each document was trusted and
  whether its macros were enabled; and the macro settings (`VBAWarnings`,
  `BlockContentExecutionFromInternet`, `AccessVBOM`) and `Trusted Locations` of the user and by
  policy. (@YamatoSecurity)
