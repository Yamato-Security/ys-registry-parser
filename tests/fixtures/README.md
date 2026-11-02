# Test hives

| Files | Source | Licence |
| --- | --- | --- |
| `regipy/SAM.gz`, `SECURITY.gz`, `BCD.gz`, `NTUSER.DAT.gz` | [regipy](https://github.com/mkorman90/regipy) `regipy_tests/data/` (c6de929): `SAM.xz`, `SECURITY.xz`, `BCD.xz`, `NTUSER.DAT.xz`, recompressed with gzip | MIT, `regipy/LICENSE` |
| `regipy/transactions_NTUSER.DAT.gz`, `transactions_ntuser.dat.log1.gz`, `transactions_ntuser.dat.log2.gz` | the same: a dirty `NTUSER.DAT` and its new-format logs | MIT, `regipy/LICENSE` |
| `regipy/UsrClass.dat.gz`, `UsrClass.dat.LOG1.gz`, `UsrClass.dat.LOG2.gz` | the same: a dirty `UsrClass.dat` and its new-format logs | MIT, `regipy/LICENSE` |
| `plaso/NTUSER-WIN7.DAT.gz` | [Plaso](https://github.com/log2timeline/plaso) `test_data/NTUSER-WIN7.DAT` (ee5a0ab), compressed with gzip: a Windows 7 `NTUSER.DAT` with Word 2010's `File MRU` and `Place MRU`, trust records and trusted locations | Apache-2.0, `plaso/LICENSE` |
| `regipy/NTUSER_BAGMRU.DAT.gz` | the same: `NTUSER_BAGMRU.DAT.xz`, a Windows 10 `NTUSER.DAT` with every kind of `FeatureUsage` count | MIT, `regipy/LICENSE` |
| `regipy/NTUSER-WSL.DAT.gz` | the same: `NTUSER-WSL.DAT.xz`, a Windows 10 `NTUSER.DAT` with three WSL distributions, App Paths and a user's `Uninstall` entry | MIT, `regipy/LICENSE` |
| `regipy/SYSTEM.gz` | the same: `SYSTEM.xz`, a 32-bit Windows 7 `SYSTEM` hive with two control sets (`Select\Current` 1, `LastKnownGood` 2) | MIT, `regipy/LICENSE` |
| `plaso/cit_system_88EDBB9D.bin` | [Plaso](https://github.com/log2timeline/plaso)'s `test_data/regf/SOFTWARE` (ee5a0ab), a Windows 10 hive: the data of its `Microsoft\Windows NT\CurrentVersion\AppCompatFlags\CIT\System\88EDBB9D08A39000000876E398222D10` value, a compressed CIT database (1,326 bytes) | Apache-2.0, `plaso/LICENSE` |
| `museum/w10_apt_NTUSER.DAT.gz`, `w10_apt_ntuser.dat.LOG1.gz`, `w10_apt_ntuser.dat.LOG2.gz` | the [DFIR Artifact Museum](https://github.com/AndrewRathbun/DFIRArtifactMuseum)'s `Windows/Registry/Win10/APTSimulatorVM/APTSimulatorVM_RegistryHives.7z`: `TestUser`'s dirty `NTUSER.DAT` and its new-format logs, gzipped (byte-identical to the archive's), with the Sysinternals keys PsExec and Sysmon left | MIT, `museum/LICENSE` |
| `notatin/win7_ntuser.dat.gz` | [notatin](https://github.com/strozfriedberg/notatin) `test_data/win7_ntuser.dat` (ae3a706), compressed with gzip: a clean Windows 7 `NTUSER.DAT` with Remote Desktop, PuTTY, WinSCP, mapped drive and `MountPoints2` keys | Apache-2.0, `notatin/LICENSE` |
| `host_keys.tsv` | Generated for these tests: SSH host keys of every type PuTTY keeps, in `SshHostKeys` form, with the fingerprints OpenSSH's `ssh-keygen -l` gives (DSA and Ed448: the SHA-256 of pycryptodome's encoding) | Test data of this repository |
| `plaso/NTUSER.DAT.gz` | [Plaso](https://github.com/log2timeline/plaso) `test_data/regf/NTUSER.DAT` (ee5a0ab), compressed with gzip: a clean `NTUSER.DAT` with the common dialogs' `OpenSavePidlMRU`, `LastVisitedPidlMRU`, `CIDSizeMRU` and `FirstFolder`, and `TypedURLs` with `TypedURLsTime` | Apache-2.0, `plaso/LICENSE` |
| `regipy/SYSTEM_WIN_10_1709.gz` | the same: `SYSTEM_WIN_10_1709.xz`, a Windows 10 `SYSTEM` hive whose BAM keys are in both layouts (`bam\UserSettings` and `bam\State\UserSettings`) | MIT, `regipy/LICENSE` |

`SECURITY` is dirty too, without logs. The other hives are clean.
