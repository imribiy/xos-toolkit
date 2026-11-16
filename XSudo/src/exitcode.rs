pub const ERR_USAGE: u32 = 0x5853_0001;
pub const ERR_ELEVATION: u32 = 0x5853_0002;
pub const ERR_IDENTITY: u32 = 0x5853_0003;
pub const ERR_CHILD: u32 = 0x5853_0004;
pub const ERR_WORKDIR: u32 = 0x5853_0005;

pub fn as_process_code(code: u32) -> i32 {
    code as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_codes_are_distinct_and_outside_common_range() {
        let codes = [ERR_USAGE, ERR_ELEVATION, ERR_IDENTITY, ERR_CHILD, ERR_WORKDIR];
        for c in codes {
            assert!(c > 0x0001_0000);
            assert_ne!(c, 3010);
        }
        let mut seen = codes.to_vec();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), codes.len());
    }

    #[test]
    fn child_codes_round_trip_through_i32() {
        for raw in [0u32, 1, 5, 259, 3010, 42, 0xFFFF_FFFF, 0x7FFF_FFFF] {
            assert_eq!(as_process_code(raw) as u32, raw);
        }
    }
}
