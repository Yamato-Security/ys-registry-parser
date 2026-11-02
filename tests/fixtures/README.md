# Test hives

| Files | Source | Licence |
| --- | --- | --- |
| `regipy/SAM.gz`, `SECURITY.gz`, `BCD.gz`, `NTUSER.DAT.gz` | [regipy](https://github.com/mkorman90/regipy) `regipy_tests/data/` (c6de929): `SAM.xz`, `SECURITY.xz`, `BCD.xz`, `NTUSER.DAT.xz`, recompressed with gzip | MIT, `regipy/LICENSE` |
| `regipy/transactions_NTUSER.DAT.gz`, `transactions_ntuser.dat.log1.gz`, `transactions_ntuser.dat.log2.gz` | the same: a dirty `NTUSER.DAT` and its new-format logs | MIT, `regipy/LICENSE` |
| `regipy/UsrClass.dat.gz`, `UsrClass.dat.LOG1.gz`, `UsrClass.dat.LOG2.gz` | the same: a dirty `UsrClass.dat` and its new-format logs | MIT, `regipy/LICENSE` |
| `regipy/SYSTEM.gz` | the same: `SYSTEM.xz`, a 32-bit Windows 7 `SYSTEM` hive with two control sets (`Select\Current` 1, `LastKnownGood` 2) | MIT, `regipy/LICENSE` |
| `notatin/win7_ntuser.dat.gz` | [notatin](https://github.com/strozfriedberg/notatin) `test_data/win7_ntuser.dat` (ae3a706), compressed with gzip: a clean Windows 7 `NTUSER.DAT` with Remote Desktop, PuTTY, WinSCP, mapped drive and `MountPoints2` keys | Apache-2.0, `notatin/LICENSE` |
| `host_keys.tsv` | Generated for these tests: SSH host keys of every type PuTTY keeps, in `SshHostKeys` form, with the fingerprints OpenSSH's `ssh-keygen -l` gives (DSA and Ed448: the SHA-256 of pycryptodome's encoding) | Test data of this repository |

`SECURITY` is dirty too, without logs. The other hives are clean.
