//! Little-endian reads that are `None` past the end.

pub(crate) fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        b.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

pub(crate) fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        b.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

pub(crate) fn i32_at(b: &[u8], at: usize) -> Option<i32> {
    Some(i32::from_le_bytes(
        b.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

pub(crate) fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        b.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}

/// UTF-16LE code units (an odd last byte is left out).
pub(crate) fn utf16_units(b: &[u8]) -> Vec<u16> {
    b.as_chunks::<2>()
        .0
        .iter()
        .map(|u| u16::from_le_bytes(*u))
        .collect()
}

/// A key or value name: one byte per character (Latin-1, as Windows widens it) or UTF-16.
pub(crate) fn name(raw: &[u8], one_byte: bool) -> String {
    if one_byte {
        raw.iter().map(|&b| char::from(b)).collect()
    } else {
        String::from_utf16_lossy(&utf16_units(raw))
    }
}
