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
