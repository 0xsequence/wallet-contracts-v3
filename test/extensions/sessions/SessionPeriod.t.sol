// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Test } from "forge-std/Test.sol";
import { SessionPeriod } from "src/extensions/sessions/SessionPeriod.sol";

contract SessionPeriodTest is Test {

  function test_calendarMatchesGregorianReference(
    uint256 year,
    uint256 month,
    uint256 day,
    uint256 secondsInDay
  ) public pure {
    year = bound(year, 1971, 2400);
    month = bound(month, 1, 12);
    day = bound(day, 1, _daysInMonth(year, month));
    secondsInDay = bound(secondsInDay, 0, 1 days - 1);
    uint256 boundary = _timestamp(year, month);
    uint64 start = uint64(_timestamp(year - 1, 11) + 14 days);
    uint256 index = SessionPeriod.periodAt(start, type(uint64).max, boundary + (day - 1) * 1 days + secondsInDay);
    assertEq(index, month + 2);
    uint256 previousIndex = SessionPeriod.periodAt(start, type(uint64).max, boundary - 1);
    assertEq(previousIndex, index - 1);
  }

  function test_calendarEpoch(
    uint256 timestamp
  ) public pure {
    timestamp = bound(timestamp, 0, 31 days - 1);
    uint256 index = SessionPeriod.periodAt(0, type(uint64).max, timestamp);
    assertEq(index, 1);
  }

  function test_calendarCenturyLeapRules() public pure {
    uint256[3] memory sampleYears = [uint256(2000), 2100, 2400];
    for (uint256 i = 0; i < sampleYears.length; i++) {
      uint64 start = uint64(_timestamp(sampleYears[i], 1));
      uint256 february = _timestamp(sampleYears[i], 2);
      uint256 index = SessionPeriod.periodAt(start, type(uint64).max, february + 28 days);
      assertEq(index, i == 1 ? 3 : 2);
    }
  }

  // Independent Gregorian reference: count whole years and months from the Unix epoch.
  function _timestamp(
    uint256 year,
    uint256 month
  ) internal pure returns (uint256) {
    uint256 daysSinceEpoch;
    for (uint256 y = 1970; y < year; y++) {
      daysSinceEpoch += _leapYear(y) ? 366 : 365;
    }
    for (uint256 m = 1; m < month; m++) {
      daysSinceEpoch += _daysInMonth(year, m);
    }
    return daysSinceEpoch * 1 days;
  }

  function _daysInMonth(
    uint256 year,
    uint256 month
  ) internal pure returns (uint256) {
    uint256[12] memory daysPerMonth = [uint256(31), 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    return daysPerMonth[month - 1] + (month == 2 && _leapYear(year) ? 1 : 0);
  }

  function _leapYear(
    uint256 year
  ) internal pure returns (bool) {
    return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
  }

}
