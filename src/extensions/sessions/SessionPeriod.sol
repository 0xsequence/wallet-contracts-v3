// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { SessionErrors } from "./SessionErrors.sol";

/// @notice Fixed-interval and UTC calendar-month renewal schedules
library SessionPeriod {

  /// @dev Reserved period value for renewal on the first of each month at 00:00 UTC.
  uint64 internal constant CALENDAR_MONTH = type(uint64).max;

  function periodAt(
    uint64 start,
    uint64 period,
    uint256 timestamp
  ) internal pure returns (uint256) {
    if (timestamp < start) {
      revert SessionErrors.SessionNotStarted(start);
    }
    if (period == 0) {
      revert SessionErrors.InvalidRenewalPeriod();
    }
    if (period == CALENDAR_MONTH) {
      return _calendarMonth(timestamp) - _calendarMonth(start) + 1;
    }
    return (timestamp - start) / period + 1;
  }

  /// @dev Gregorian civil-from-days arithmetic, also used by the monthly subscription prototype.
  ///      https://howardhinnant.github.io/date_algorithms.html#civil_from_days
  function _calendarMonth(
    uint256 timestamp
  ) private pure returns (uint256) {
    uint256 daysSinceMarch = timestamp / 1 days + 719468;
    uint256 era = daysSinceMarch / 146097;
    uint256 dayOfEra = daysSinceMarch % 146097;
    uint256 yearOfEra = (dayOfEra - dayOfEra / 1460 + dayOfEra / 36524 - dayOfEra / 146096) / 365;
    uint256 year = yearOfEra + era * 400;
    uint256 dayOfYear = dayOfEra - (365 * yearOfEra + yearOfEra / 4 - yearOfEra / 100);
    uint256 marchMonth = (5 * dayOfYear + 2) / 153;
    uint256 month = marchMonth < 10 ? marchMonth + 3 : marchMonth - 9;
    if (month <= 2) {
      year++;
    }
    return year * 12 + month - 1;
  }

}
