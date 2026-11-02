# Test hives

| Files | Source | Licence |
| --- | --- | --- |
| `regipy/SAM.gz`, `SECURITY.gz`, `BCD.gz`, `NTUSER.DAT.gz` | [regipy](https://github.com/mkorman90/regipy) `regipy_tests/data/` (c6de929): `SAM.xz`, `SECURITY.xz`, `BCD.xz`, `NTUSER.DAT.xz`, recompressed with gzip | MIT, `regipy/LICENSE` |
| `regipy/transactions_NTUSER.DAT.gz`, `transactions_ntuser.dat.log1.gz`, `transactions_ntuser.dat.log2.gz` | the same: a dirty `NTUSER.DAT` and its new-format logs | MIT, `regipy/LICENSE` |
| `regipy/UsrClass.dat.gz`, `UsrClass.dat.LOG1.gz`, `UsrClass.dat.LOG2.gz` | the same: a dirty `UsrClass.dat` and its new-format logs | MIT, `regipy/LICENSE` |
| `regipy/SYSTEM.gz` | the same: `SYSTEM.xz`, a 32-bit Windows 7 `SYSTEM` hive with two control sets (`Select\Current` 1, `LastKnownGood` 2) | MIT, `regipy/LICENSE` |
| `plaso/NTUSER.DAT.gz` | [Plaso](https://github.com/log2timeline/plaso) `test_data/regf/NTUSER.DAT` (ee5a0ab), compressed with gzip: a clean `NTUSER.DAT` with the common dialogs' `OpenSavePidlMRU`, `LastVisitedPidlMRU`, `CIDSizeMRU` and `FirstFolder`, and `TypedURLs` with `TypedURLsTime` | Apache-2.0, `plaso/LICENSE` |

`SECURITY` is dirty too, without logs. The other hives are clean.
