//! Value types, value data decoded by type, and FILETIMEs.

use crate::bytes::utf16_units;

/// A value's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueType {
    /// `REG_NONE` (0).
    None,
    /// `REG_SZ` (1): a string.
    Sz,
    /// `REG_EXPAND_SZ` (2): a string with `%variables%`.
    ExpandSz,
    /// `REG_BINARY` (3).
    Binary,
    /// `REG_DWORD` (4): 32 bits, little-endian.
    Dword,
    /// `REG_DWORD_BIG_ENDIAN` (5).
    DwordBigEndian,
    /// `REG_LINK` (6): a symbolic link's target.
    Link,
    /// `REG_MULTI_SZ` (7): strings, each ended by a NUL.
    MultiSz,
    /// `REG_RESOURCE_LIST` (8).
    ResourceList,
    /// `REG_FULL_RESOURCE_DESCRIPTOR` (9).
    FullResourceDescriptor,
    /// `REG_RESOURCE_REQUIREMENTS_LIST` (10).
    ResourceRequirementsList,
    /// `REG_QWORD` (11): 64 bits, little-endian.
    Qword,
    /// Any other type (device properties are `0xFFFF0000` and a property type, ...).
    Other(u32),
}

impl ValueType {
    /// The type a value records.
    #[must_use]
    pub fn from_code(code: u32) -> Self {
        match code {
            0 => Self::None,
            1 => Self::Sz,
            2 => Self::ExpandSz,
            3 => Self::Binary,
            4 => Self::Dword,
            5 => Self::DwordBigEndian,
            6 => Self::Link,
            7 => Self::MultiSz,
            8 => Self::ResourceList,
            9 => Self::FullResourceDescriptor,
            10 => Self::ResourceRequirementsList,
            11 => Self::Qword,
            other => Self::Other(other),
        }
    }

    /// Its name (`REG_SZ`, ...), an other type's code in hex (`0xffff0012`).
    #[must_use]
    pub fn name(self) -> String {
        match self {
            Self::None => "REG_NONE",
            Self::Sz => "REG_SZ",
            Self::ExpandSz => "REG_EXPAND_SZ",
            Self::Binary => "REG_BINARY",
            Self::Dword => "REG_DWORD",
            Self::DwordBigEndian => "REG_DWORD_BIG_ENDIAN",
            Self::Link => "REG_LINK",
            Self::MultiSz => "REG_MULTI_SZ",
            Self::ResourceList => "REG_RESOURCE_LIST",
            Self::FullResourceDescriptor => "REG_FULL_RESOURCE_DESCRIPTOR",
            Self::ResourceRequirementsList => "REG_RESOURCE_REQUIREMENTS_LIST",
            Self::Qword => "REG_QWORD",
            Self::Other(code) => return format!("0x{code:x}"),
        }
        .to_owned()
    }
}

/// A value's data, decoded by its type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Data {
    /// `REG_SZ`, `REG_EXPAND_SZ`, `REG_LINK`: UTF-16 up to the first NUL. `lossy` says an odd
    /// byte was dropped or an invalid code unit was replaced.
    Text {
        /// The decoded text.
        value: String,
        /// Whether decoding dropped an odd byte or replaced an invalid UTF-16 code unit.
        lossy: bool,
    },
    /// `REG_MULTI_SZ`: the strings, without the empty ones the terminating NULs leave at the end.
    /// `lossy` has the same meaning as for [`Data::Text`].
    MultiText {
        /// The decoded strings.
        values: Vec<String>,
        /// Whether decoding dropped an odd byte or replaced an invalid UTF-16 code unit.
        lossy: bool,
    },
    /// `REG_DWORD`, `REG_DWORD_BIG_ENDIAN`, `REG_QWORD`.
    Number(u64),
    /// `REG_BINARY`, `REG_NONE` and the resource types: the bytes are the data.
    Bytes,
    /// Not what its type says (a `REG_DWORD` of 3 bytes): why.
    Malformed(String),
    /// A type with no decoding.
    Undecoded,
}

/// `bytes` decoded as a value of type `code`.
#[must_use]
pub fn decode(code: u32, bytes: &[u8]) -> Data {
    let kind = ValueType::from_code(code);
    let sized = |n: usize| -> Result<(), Data> {
        if bytes.len() == n {
            Ok(())
        } else {
            Err(Data::Malformed(format!(
                "{} of {} bytes",
                kind.name(),
                bytes.len()
            )))
        }
    };
    match kind {
        ValueType::Sz | ValueType::ExpandSz | ValueType::Link => {
            let units = utf16_units(bytes);
            let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
            Data::Text {
                value: String::from_utf16_lossy(&units[..end]),
                lossy: !bytes.len().is_multiple_of(2) || String::from_utf16(&units[..end]).is_err(),
            }
        }
        ValueType::MultiSz => {
            let units = utf16_units(bytes);
            let lossy = !bytes.len().is_multiple_of(2)
                || units
                    .split(|&u| u == 0)
                    .any(|item| String::from_utf16(item).is_err());
            let mut items: Vec<String> = units
                .split(|&u| u == 0)
                .map(String::from_utf16_lossy)
                .collect();
            while items.last().is_some_and(String::is_empty) {
                items.pop();
            }
            Data::MultiText {
                values: items,
                lossy,
            }
        }
        ValueType::Dword => match sized(4) {
            Ok(()) => Data::Number(u64::from(u32::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3],
            ]))),
            Err(e) => e,
        },
        ValueType::DwordBigEndian => match sized(4) {
            Ok(()) => Data::Number(u64::from(u32::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3],
            ]))),
            Err(e) => e,
        },
        ValueType::Qword => match sized(8) {
            Ok(()) => Data::Number(u64::from_le_bytes(bytes.try_into().unwrap_or_default())),
            Err(e) => e,
        },
        ValueType::None
        | ValueType::Binary
        | ValueType::ResourceList
        | ValueType::FullResourceDescriptor
        | ValueType::ResourceRequirementsList => Data::Bytes,
        ValueType::Other(_) => Data::Undecoded,
    }
}

/// FILETIMEs between 1601 and 9999 (the times .NET and Windows' tools show).
const MAX_FILETIME: u64 = 2_650_467_743_999_999_999;
/// FILETIME ticks from 1601 to 1970.
const UNIX_EPOCH: u64 = 116_444_736_000_000_000;

/// A FILETIME (100 ns ticks since 1601, UTC) as Unix seconds and nanoseconds; `None` for 0 and
/// times past 9999.
#[must_use]
pub fn filetime(ft: u64) -> Option<(i64, u32)> {
    if ft == 0 || ft > MAX_FILETIME {
        return None;
    }
    // in range, so it fits an i64
    let ticks = ft.cast_signed() - UNIX_EPOCH.cast_signed();
    let nanos = u32::try_from(ticks.rem_euclid(10_000_000) * 100).ok()?;
    Some((ticks.div_euclid(10_000_000), nanos))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn values_decode_by_type() {
        assert_eq!(
            decode(1, &utf16("abc\0junk")),
            Data::Text {
                value: "abc".into(),
                lossy: false
            }
        );
        assert_eq!(
            decode(2, &utf16("%x%\0")),
            Data::Text {
                value: "%x%".into(),
                lossy: false
            }
        );
        assert_eq!(
            decode(7, &utf16("a\0\0b c\0\0")),
            Data::MultiText {
                values: vec!["a".into(), String::new(), "b c".into()],
                lossy: false
            }
        );
        assert_eq!(
            decode(7, &utf16("\0")),
            Data::MultiText {
                values: Vec::new(),
                lossy: false
            }
        );
        assert_eq!(
            decode(1, &utf16("\u{fffd}")),
            Data::Text {
                value: "\u{fffd}".into(),
                lossy: false
            }
        );
        assert_eq!(
            decode(1, &[0x00, 0xd8]),
            Data::Text {
                value: "\u{fffd}".into(),
                lossy: true
            }
        );
        assert_eq!(
            decode(1, b"a"),
            Data::Text {
                value: String::new(),
                lossy: true
            }
        );
        assert_eq!(decode(4, &[1, 0, 0, 0]), Data::Number(1));
        assert_eq!(decode(5, &[0, 0, 0, 1]), Data::Number(1));
        assert_eq!(decode(11, &u64::MAX.to_le_bytes()), Data::Number(u64::MAX));
        assert_eq!(decode(3, &[1]), Data::Bytes);
        assert_eq!(
            decode(4, &[1, 2, 3]),
            Data::Malformed("REG_DWORD of 3 bytes".into())
        );
        assert_eq!(
            decode(11, &[0; 4]),
            Data::Malformed("REG_QWORD of 4 bytes".into())
        );
        assert_eq!(decode(0xffff_0012, &[1]), Data::Undecoded);
        assert_eq!(ValueType::from_code(7).name(), "REG_MULTI_SZ");
        assert_eq!(ValueType::from_code(0xffff_0012).name(), "0xffff0012");
    }

    #[test]
    fn filetimes() {
        // 2022-02-08T21:03:52.5205720Z
        assert_eq!(
            filetime(132_888_278_325_205_720),
            Some((1_644_354_232, 520_572_000))
        );
        assert_eq!(filetime(UNIX_EPOCH), Some((0, 0)));
        assert_eq!(filetime(1), Some((-11_644_473_600, 100)));
        assert_eq!(filetime(0), None);
        assert_eq!(filetime(MAX_FILETIME + 1), None);
        assert_eq!(filetime(u64::MAX), None);
    }
}
