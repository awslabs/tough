use std::fmt::Write;

pub fn oid_to_string(oid: &[u8]) -> String {
    if oid.is_empty() {
        return String::new();
    }

    let mut result = String::new();

    // First byte encodes the first two arcs: value = arc1 * 40 + arc2
    let first = oid[0] as u32;
    let arc1 = first / 40;
    let arc2 = first % 40;
    let _ = write!(result, "{arc1}.{arc2}");

    // Remaining arcs are base-128 encoded, 7 bits per byte,
    // high bit set means "more bytes follow".
    let mut value: u64 = 0;
    for &byte in &oid[1..] {
        value = (value << 7) | (byte & 0x7F) as u64;
        if byte & 0x80 == 0 {
            // end of this arc's encoding
            result.push('.');
            result.push_str(&value.to_string());
            value = 0;
        }
    }

    result
}
