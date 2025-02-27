// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { LibBytes } from "../../src/utils/LibBytes.sol";
import { AdvTest } from "./TestUtils.sol";
import { Test, Vm } from "forge-std/Test.sol";

contract LibBytesImp {

  function readBytes32(bytes calldata data, uint256 index) external pure returns (bytes32) {
    return LibBytes.readBytes32(data, index);
  }

  function readUint8(bytes calldata data, uint256 index) external pure returns (uint8) {
    return LibBytes.readUint8(data, index);
  }

  function readFirstUint16(
    bytes calldata data
  ) external pure returns (uint16) {
    return LibBytes.readFirstUint16(data);
  }

  function readUint32(bytes calldata data, uint256 index) external pure returns (uint32) {
    return LibBytes.readUint32(data, index);
  }

  function readRSVCompact(bytes calldata data, uint256 index) external pure returns (bytes32 r, bytes32 s, uint8 v) {
    return LibBytes.readRSVCompact(data, index);
  }

  function readMBytes4(bytes memory data, uint256 index) external pure returns (bytes4) {
    return LibBytes.readMBytes4(data, index);
  }

  function readMBytes32(bytes memory data, uint256 index) external pure returns (bytes32) {
    return LibBytes.readMBytes32(data, index);
  }

  function readMRSVCompact(bytes memory data, uint256 index) external pure returns (bytes32 r, bytes32 s, uint8 v) {
    return LibBytes.readMRSVCompact(data, index);
  }

}

contract LibBytesTest is AdvTest {

  LibBytesImp public bytesImp;

  function setUp() public {
    bytesImp = new LibBytesImp();
  }

  function test_readBytes32(bytes calldata prefix, bytes32 value, bytes calldata suffix) external view {
    bytes memory fullData = bytes.concat(prefix, abi.encodePacked(value), suffix);
    uint256 index = prefix.length;
    bytes32 result = bytesImp.readBytes32(fullData, index);
    assertEq(result, value);
  }

  function test_readUint8(bytes calldata prefix, uint8 value, bytes calldata suffix) external view {
    bytes memory fullData = bytes.concat(prefix, abi.encodePacked(value), suffix);
    uint256 index = prefix.length;
    uint8 result = bytesImp.readUint8(fullData, index);
    assertEq(result, value);
  }

  function test_readFirstUint16(uint16 value, bytes calldata suffix) external view {
    bytes memory fullData = bytes.concat(abi.encodePacked(value), suffix);
    uint16 result = bytesImp.readFirstUint16(fullData);
    assertEq(result, value);
  }

  function test_readUint32(bytes calldata prefix, uint32 value, bytes calldata suffix) external view {
    bytes memory fullData = bytes.concat(prefix, abi.encodePacked(value), suffix);
    uint256 index = prefix.length;
    uint32 result = bytesImp.readUint32(fullData, index);
    assertEq(result, value);
  }

  function test_readRSVCompact(
    bytes calldata prefix,
    bytes32 r,
    uint256 sWithParity,
    bytes calldata suffix
  ) external view {
    bool parityBit = (sWithParity & (1 << 255)) > 0;
    bytes32 s = bytes32(sWithParity & ((1 << 255) - 1));
    uint8 expectedV = parityBit ? 28 : 27;

    bytes memory fullData = bytes.concat(prefix, abi.encodePacked(r), abi.encodePacked(bytes32(sWithParity)), suffix);

    uint256 index = prefix.length;
    (bytes32 resultR, bytes32 resultS, uint8 resultV) = bytesImp.readRSVCompact(fullData, index);

    assertEq(resultR, r);
    assertEq(resultS, s);
    assertEq(resultV, expectedV);
  }

  function test_readMBytes4(bytes calldata prefix, bytes4 value, bytes calldata suffix) external view {
    bytes memory fullData = bytes.concat(prefix, abi.encodePacked(value), suffix);
    uint256 index = prefix.length;
    bytes4 result = bytesImp.readMBytes4(fullData, index);
    assertEq(result, value);
  }

  function test_readMBytes32(bytes calldata prefix, bytes32 value, bytes calldata suffix) external view {
    bytes memory fullData = bytes.concat(prefix, abi.encodePacked(value), suffix);
    uint256 index = prefix.length;
    bytes32 result = bytesImp.readMBytes32(fullData, index);
    assertEq(result, value);
  }

  function test_readMRSVCompact(
    bytes calldata prefix,
    bytes32 r,
    uint256 sWithParity,
    bytes calldata suffix
  ) external view {
    bool parityBit = (sWithParity & (1 << 255)) > 0;
    bytes32 s = bytes32(sWithParity & ((1 << 255) - 1));
    uint8 expectedV = parityBit ? 28 : 27;

    bytes memory fullData = bytes.concat(prefix, abi.encodePacked(r), abi.encodePacked(bytes32(sWithParity)), suffix);

    uint256 index = prefix.length;
    (bytes32 resultR, bytes32 resultS, uint8 resultV) = bytesImp.readMRSVCompact(fullData, index);

    assertEq(resultR, r);
    assertEq(resultS, s);
    assertEq(resultV, expectedV);
  }

  function test_readBytes32_emptyPrefix(bytes32 value, bytes calldata suffix) external view {
    bytes memory fullData = bytes.concat(abi.encodePacked(value), suffix);
    uint256 index = 0;
    bytes32 result = bytesImp.readBytes32(fullData, index);
    assertEq(result, value);
  }

  function test_readUint8_emptyPrefix(uint8 value, bytes calldata suffix) external view {
    bytes memory fullData = bytes.concat(abi.encodePacked(value), suffix);
    uint256 index = 0;
    uint8 result = bytesImp.readUint8(fullData, index);
    assertEq(result, value);
  }

  function test_readBytes32_outOfBounds(
    bytes calldata prefix
  ) external view {
    vm.assume(prefix.length < 32);
    bytesImp.readBytes32(prefix, prefix.length);
    assertTrue(true); // Just ensure it doesn't revert
  }

  function test_readUint8_outOfBounds(
    bytes calldata data
  ) external view {
    vm.assume(data.length > 0);
    bytesImp.readUint8(data, data.length);
    assertTrue(true); // Just ensure it doesn't revert
  }

  function test_readFirstUint16_emptyData() external view {
    bytes memory emptyData = new bytes(0);
    bytesImp.readFirstUint16(emptyData);
    assertTrue(true); // Just ensure it doesn't revert
  }

  function test_readRSVCompact_withHighBit(
    bytes calldata prefix,
    bytes32 r,
    uint256 s,
    bytes calldata suffix
  ) external view {
    uint256 sWithHighBit = s | (1 << 255);
    bytes memory fullData = bytes.concat(prefix, abi.encodePacked(r), abi.encodePacked(bytes32(sWithHighBit)), suffix);

    uint256 index = prefix.length;
    (bytes32 resultR, bytes32 resultS, uint8 resultV) = bytesImp.readRSVCompact(fullData, index);

    assertEq(resultR, r);
    assertEq(resultS, bytes32(s & ((1 << 255) - 1)));
    assertEq(resultV, 28);
  }

  function test_readRSVCompact_withoutHighBit(
    bytes calldata prefix,
    bytes32 r,
    uint256 s,
    bytes calldata suffix
  ) external view {
    uint256 sWithoutHighBit = s & ((1 << 255) - 1);
    bytes memory fullData =
      bytes.concat(prefix, abi.encodePacked(r), abi.encodePacked(bytes32(sWithoutHighBit)), suffix);

    uint256 index = prefix.length;
    (bytes32 resultR, bytes32 resultS, uint8 resultV) = bytesImp.readRSVCompact(fullData, index);

    assertEq(resultR, r);
    assertEq(resultS, bytes32(sWithoutHighBit));
    assertEq(resultV, 27);
  }

  function test_readMBytes32_withOffset(bytes calldata prefix, bytes32 value) external view {
    vm.assume(prefix.length > 0);
    bytes memory fullData = bytes.concat(prefix, abi.encodePacked(value));
    uint256 index = prefix.length;
    bytes32 result = bytesImp.readMBytes32(fullData, index);
    assertEq(result, value);
  }

}
