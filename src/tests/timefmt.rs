use super::*;

#[test]
fn epoch() {
    assert_eq!(format_utc(0), "1970-01-01 00:00");
}

#[test]
fn known_timestamp() {
    // 1_700_000_000 s == 2023-11-14 22:13:20 UTC
    assert_eq!(format_utc(1_700_000_000_000), "2023-11-14 22:13");
}

#[test]
fn leap_day() {
    // 2020-02-29 00:00 UTC == 18321 days after the epoch
    assert_eq!(format_utc(18_321 * 86_400 * 1000), "2020-02-29 00:00");
}

#[test]
fn end_of_day() {
    assert_eq!(format_utc(86_399_000), "1970-01-01 23:59");
    assert_eq!(format_utc(86_400_000), "1970-01-02 00:00");
}
