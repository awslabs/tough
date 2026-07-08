// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::{self, Result};

use jiff::{SignedDuration, Timestamp};
use snafu::{ensure, ResultExt};

/// Parses a user-specified datetime, either in full RFC 3339 format, or a shorthand like "in 7
/// days"
pub(crate) fn parse_datetime(input: &str) -> Result<Timestamp> {
    // If the user gave an absolute date in a standard format, accept it.
    if let Ok(ts) = input.parse::<Timestamp>() {
        return Ok(ts);
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
    Ok(then)
}
