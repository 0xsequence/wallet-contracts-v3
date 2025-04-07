// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Base64 } from "../../src/utils/Base64.sol";
import { Test, Vm } from "forge-std/Test.sol";

contract Base64Test is Test {

  function test_encode(
    bytes calldata data
  ) external pure {
    // Test standard encoding
    string memory result = Base64.encode(data);
    string memory expected = vm.toBase64(data);
    assertEq(result, expected);

    // Test file-safe encoding
    string memory fileSafeResult = Base64.encode(data, true);
    string memory fileSafeExpected = vm.toBase64URL(data);
    assertEq(fileSafeResult, fileSafeExpected);

    // Test encoding without padding
    string memory noPaddingResult = Base64.encode(data, false, true);
    string memory noPaddingExpected = removePadding(vm.toBase64(data));
    assertEq(noPaddingResult, noPaddingExpected);

    // Test file-safe encoding without padding
    string memory fileSafeNoPaddingResult = Base64.encode(data, true, true);
    string memory fileSafeNoPaddingExpected = removePadding(vm.toBase64URL(data));
    assertEq(fileSafeNoPaddingResult, fileSafeNoPaddingExpected);
  }

  function test_decode(
    bytes calldata data
  ) external pure {
    // Test standard base64
    string memory encoded = Base64.encode(data);
    bytes memory decoded = Base64.decode(encoded);
    assertEq(decoded, data);

    // Test file-safe base64
    string memory fileSafeEncoded = Base64.encode(data, true);
    bytes memory fileSafeDecoded = Base64.decode(fileSafeEncoded);
    assertEq(fileSafeDecoded, data);

    // Test without padding
    string memory noPaddingEncoded = Base64.encode(data, false, true);
    bytes memory noPaddingDecoded = Base64.decode(noPaddingEncoded);
    assertEq(noPaddingDecoded, data);

    // Test file-safe without padding
    string memory fileSafeNoPaddingEncoded = Base64.encode(data, true, true);
    bytes memory fileSafeNoPaddingDecoded = Base64.decode(fileSafeNoPaddingEncoded);
    assertEq(fileSafeNoPaddingDecoded, data);
  }

  function test_encode_empty() external pure {
    bytes memory empty;
    string memory result = Base64.encode(empty);
    assertEq(result, "");
  }

  function test_decode_empty() external pure {
    string memory empty = "";
    bytes memory result = Base64.decode(empty);
    assertEq(result.length, 0);
  }

  // Manual test cases for specific scenarios
  function test_manual_cases() external pure {
    // Test single byte
    bytes memory singleByte = hex"01";
    string memory encoded = Base64.encode(singleByte);
    assertEq(encoded, "AQ==");
    bytes memory decoded = Base64.decode(encoded);
    assertEq(decoded, singleByte);

    // Test two bytes
    bytes memory twoBytes = hex"0102";
    encoded = Base64.encode(twoBytes);
    assertEq(encoded, "AQI=");
    decoded = Base64.decode(encoded);
    assertEq(decoded, twoBytes);

    // Test three bytes
    bytes memory threeBytes = hex"010203";
    encoded = Base64.encode(threeBytes);
    assertEq(encoded, "AQID");
    decoded = Base64.decode(encoded);
    assertEq(decoded, threeBytes);

    // Test four bytes
    bytes memory fourBytes = hex"01020304";
    encoded = Base64.encode(fourBytes);
    assertEq(encoded, "AQIDBA==");
    decoded = Base64.decode(encoded);
    assertEq(decoded, fourBytes);

    // Test file-safe encoding
    encoded = Base64.encode(fourBytes, true);
    assertEq(encoded, "AQIDBA==");
    decoded = Base64.decode(encoded);
    assertEq(decoded, fourBytes);

    // Test without padding
    encoded = Base64.encode(fourBytes, false, true);
    assertEq(encoded, "AQIDBA");
    decoded = Base64.decode(encoded);
    assertEq(decoded, fourBytes);

    // Test file-safe without padding
    encoded = Base64.encode(fourBytes, true, true);
    assertEq(encoded, "AQIDBA");
    decoded = Base64.decode(encoded);
    assertEq(decoded, fourBytes);

    // Test all zeros
    bytes memory allZeros = hex"00000000";
    encoded = Base64.encode(allZeros);
    assertEq(encoded, "AAAAAA==");
    decoded = Base64.decode(encoded);
    assertEq(decoded, allZeros);

    // Test all ones
    bytes memory allOnes = hex"FFFFFFFF";
    encoded = Base64.encode(allOnes);
    assertEq(encoded, "/////w==");
    decoded = Base64.decode(encoded);
    assertEq(decoded, allOnes);

    // Test non-padded base64 string with length not divisible by 4
    // This will hit the break statement in the decode function
    bytes memory nonPaddedData = hex"010203";
    string memory nonPaddedEncoded = "AQID";
    bytes memory nonPaddedDecoded = Base64.decode(nonPaddedEncoded);
    assertEq(nonPaddedDecoded, nonPaddedData);

    // "AQI" is 3 characters (mod 4 = 3), so it goes down the "non-padded" path in decode
    string memory nonPadded = "AQI";
    bytes memory expected = hex"0102"; // This is what "AQI=" would normally decode to
    decoded = Base64.decode(nonPadded);
    assertEq(decoded, expected);
  }

  // Helper function to remove padding from base64 string
  function removePadding(
    string memory data
  ) internal pure returns (string memory) {
    bytes memory dataBytes = bytes(data);
    uint256 length = dataBytes.length;
    while (length > 0 && dataBytes[length - 1] == "=") {
      length--;
    }
    bytes memory result = new bytes(length);
    for (uint256 i = 0; i < length; i++) {
      result[i] = dataBytes[i];
    }
    return string(result);
  }

}
