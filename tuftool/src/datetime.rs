// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::{self, Result};

use jiff::{SignedDuration, Timestamp};
use snafu::{ensure, ResultExt};

/// Parses a user-specified datetime, either in full RFC 3339 format, or a shorthand like "in 7
/// days".
///
/// The TUF specification requires metadata `expires` timestamps in whole seconds, UTC, with no
/// sub-second component (`YYYY-MM-DDTHH:MM:SSZ`). RFC 3339 input can carry fractional seconds (for
/// example `2030-01-01T00:00:00.5Z`), and `Timestamp::now()` always has a sub-second component, so
/// the returned value is truncated to whole seconds.
pub(crate) fn parse_datetime(input: &str) -> Result<Timestamp> {
    // If the user gave an absolute date in a standard format, accept it.
    if let Ok(ts) = input.parse::<Timestamp>() {
        return Ok(truncate_to_seconds(ts));
    }

    // Otherwise, pull apart a request like "in 5 days" to get an exact datetime.
    let mut parts: Vec<&str> = input.split_whitespace().collect();
    ensure!(
        parts.len() == 3,
        error::DateArgInvalidSnafu {
            input,
            msg: "expected RFC 3339, or 3 space-separated values like 'in 7 days'",
        }
    );
    let unit_str = parts.pop().unwrap();
    let count_str = parts.pop().unwrap();
    let prefix = parts.pop().unwrap();
    ensure!(
        prefix == "in",
        error::DateArgInvalidSnafu {
            input,
            msg: "expected RFC 3339, or prefix 'in', something like 'in 7 days'",
        }
    );

    let count: u32 = count_str
        .parse()
        .context(error::DateArgCountSnafu { input })?;

    let duration = match unit_str {
        "hour" | "hours" => SignedDuration::from_hours(i64::from(count)),
        "day" | "days" => i64::from(count)
            .checked_mul(24)
            .map(SignedDuration::from_hours)
            .ok_or_else(|| {
                error::DateArgInvalidSnafu {
                    input: count.to_string(),
                    msg: format!("unable to convert {count} to a number of days"),
                }
                .build()
            })?,
        "week" | "weeks" => i64::from(count)
            .checked_mul(24 * 7)
            .map(SignedDuration::from_hours)
            .ok_or_else(|| {
                error::DateArgInvalidSnafu {
                    input: count.to_string(),
                    msg: format!("unable to convert {count} to a number of weeks"),
                }
                .build()
            })?,
        _ => {
            return error::DateArgInvalidSnafu {
                input,
                msg: "date argument's unit must be hours/days/weeks",
            }
            .fail();
        }
    };

    let now = Timestamp::now();
    let then = now + duration;
    Ok(truncate_to_seconds(then))
}

/// Truncates a timestamp to whole seconds, dropping any sub-second component, so it can be rendered
/// in the whole-second RFC 3339 form the TUF spec requires for `expires`.
fn truncate_to_seconds(ts: Timestamp) -> Timestamp {
    // The whole-second value of an in-range timestamp is itself in range, so this cannot fail; fall
    // back to the original on the theoretical error rather than panicking.
    Timestamp::from_second(ts.as_second()).unwrap_or(ts)
}

#[cfg(test)]
mod tests {
    use super::parse_datetime;

    #[test]
    fn rfc3339_fractional_seconds_are_truncated() {
        let ts = parse_datetime("2030-01-01T00:00:00.5Z").unwrap();
        assert_eq!(ts.subsec_nanosecond(), 0);
        assert_eq!(ts.to_string(), "2030-01-01T00:00:00Z");
    }

    #[test]
    fn rfc3339_whole_seconds_unchanged() {
        let ts = parse_datetime("2030-01-01T00:00:00Z").unwrap();
        assert_eq!(ts.to_string(), "2030-01-01T00:00:00Z");
    }

    #[test]
    fn relative_datetime_has_no_subsecond() {
        let ts = parse_datetime("in 7 days").unwrap();
        assert_eq!(ts.subsec_nanosecond(), 0);
    }
}
