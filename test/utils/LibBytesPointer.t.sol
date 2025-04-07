// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { LibBytesPointer } from "../../src/utils/LibBytesPointer.sol";
import { AdvTest } from "./TestUtils.sol";
import { Test, Vm } from "forge-std/Test.sol";

contract LibBytesPointerImp {

  function readFirstUint8(
    bytes calldata data
  ) external pure returns (uint8 a, uint256 newPointer) {
    return LibBytesPointer.readFirstUint8(data);
  }

  function readFirstUint16(
    bytes calldata data
  ) external pure returns (uint16 a, uint256 newPointer) {
    return LibBytesPointer.readFirstUint16(data);
  }

  function readFirstUint24(
    bytes calldata data
  ) external pure returns (uint24 a, uint256 newPointer) {
    return LibBytesPointer.readFirstUint24(data);
  }

  function readUint8(bytes calldata data, uint256 index) external pure returns (uint8 a, uint256 newPointer) {
    return LibBytesPointer.readUint8(data, index);
  }

  function readAddress(bytes calldata data, uint256 index) external pure returns (address a, uint256 newPointer) {
    return LibBytesPointer.readAddress(data, index);
  }

  function readUint8Address(
    bytes calldata data,
    uint256 index
  ) external pure returns (uint8 a, address b, uint256 newPointer) {
    return LibBytesPointer.readUint8Address(data, index);
  }

  function readUint16(bytes calldata data, uint256 index) external pure returns (uint16 a, uint256 newPointer) {
    return LibBytesPointer.readUint16(data, index);
  }

  function readUintX(
    bytes calldata data,
    uint256 index,
    uint256 length
  ) external pure returns (uint256 a, uint256 newPointer) {
    return LibBytesPointer.readUintX(data, index, length);
  }

  function readUint24(bytes calldata data, uint256 index) external pure returns (uint24 a, uint256 newPointer) {
    return LibBytesPointer.readUint24(data, index);
  }

  function readUint64(bytes calldata data, uint256 index) external pure returns (uint64 a, uint256 newPointer) {
    return LibBytesPointer.readUint64(data, index);
  }

  function readBytes4(bytes calldata data, uint256 pointer) external pure returns (bytes4 a, uint256 newPointer) {
    return LibBytesPointer.readBytes4(data, pointer);
  }

  function readBytes32(bytes calldata data, uint256 pointer) external pure returns (bytes32 a, uint256 newPointer) {
    return LibBytesPointer.readBytes32(data, pointer);
  }

  function readUint256(bytes calldata data, uint256 index) external pure returns (uint256 a, uint256 newPointer) {
    return LibBytesPointer.readUint256(data, index);
  }

  function readUint160(bytes calldata data, uint256 index) external pure returns (uint160 a, uint256 newPointer) {
    return LibBytesPointer.readUint160(data, index);
  }

  function readRSVCompact(
    bytes calldata data,
    uint256 index
  ) external pure returns (bytes32 r, bytes32 s, uint8 v, uint256 newPointer) {
    return LibBytesPointer.readRSVCompact(data, index);
  }

}

contract LibBytesPointerTest is AdvTest {

  LibBytesPointerImp public bytesImp;

  function setUp() public {
    bytesImp = new LibBytesPointerImp();
  }

  function test_readFirstUint8(
    bytes calldata suffix
  ) external view {
    uint8 value = 0x12;
    bytes memory fullData = bytes.concat(abi.encodePacked(value), suffix);
    (uint8 result, uint256 newPointer) = bytesImp.readFirstUint8(fullData);
    assertEq(result, value);
    assertEq(newPointer, 1);
  }

  function test_readFirstUint16(
    bytes calldata suffix
  ) external view {
    uint16 value = 0x1234;
    bytes memory fullData = bytes.concat(abi.encodePacked(value), suffix);
    (uint16 result, uint256 newPointer) = bytesImp.readFirstUint16(fullData);
    assertEq(result, value);
    assertEq(newPointer, 2);
  }

  function test_readFirstUint24(
    bytes calldata suffix
  ) external view {
    uint24 value = 0x123456;
    bytes memory fullData = bytes.concat(abi.encodePacked(value), suffix);
    (uint24 result, uint256 newPointer) = bytesImp.readFirstUint24(fullData);
    assertEq(result, value);
    assertEq(newPointer, 3);
  }

  function test_readUint8(bytes calldata prefix, uint8 value, bytes calldata suffix) external view {
    bytes memory fullData = bytes.concat(prefix, abi.encodePacked(value), suffix);
    uint256 index = prefix.length;
    (uint8 result, uint256 newPointer) = bytesImp.readUint8(fullData, index);
    assertEq(result, value);
    assertEq(newPointer, index + 1);
  }

  function test_readAddress(bytes calldata prefix, address value, bytes calldata suffix) external view {
    bytes memory fullData = bytes.concat(prefix, abi.encodePacked(value), suffix);
    uint256 index = prefix.length;
    (address result, uint256 newPointer) = bytesImp.readAddress(fullData, index);
    assertEq(result, value);
    assertEq(newPointer, index + 20);
  }

  function test_readUint8Address(bytes calldata prefix, uint8 a, address b, bytes calldata suffix) external view {
    bytes memory fullData = bytes.concat(prefix, abi.encodePacked(a), abi.encodePacked(b), suffix);
    uint256 index = prefix.length;
    (uint8 resultA, address resultB, uint256 newPointer) = bytesImp.readUint8Address(fullData, index);
    assertEq(resultA, a);
    assertEq(resultB, b);
    assertEq(newPointer, index + 21);
  }

  function test_readUint16(bytes calldata prefix, uint16 value, bytes calldata suffix) external view {
    bytes memory fullData = bytes.concat(prefix, abi.encodePacked(value), suffix);
    uint256 index = prefix.length;
    (uint16 result, uint256 newPointer) = bytesImp.readUint16(fullData, index);
    assertEq(result, value);
    assertEq(newPointer, index + 2);
  }

  function test_readUintX(bytes calldata prefix, uint256 value, uint256 length, bytes calldata suffix) external view {
    length = bound(length, 0, 32);

    uint256 mask = length == 32 ? type(uint256).max : ((1 << (length * 8)) - 1);
    uint256 maskedValue = value & mask;

    bytes memory encodedValue;
    if (length == 1) {
      encodedValue = abi.encodePacked(uint8(maskedValue));
    } else if (length == 2) {
      encodedValue = abi.encodePacked(uint16(maskedValue));
    } else if (length == 3) {
      encodedValue = abi.encodePacked(uint24(maskedValue));
    } else if (length == 4) {
      encodedValue = abi.encodePacked(uint32(maskedValue));
    } else if (length == 5) {
      encodedValue = abi.encodePacked(uint40(maskedValue));
    } else if (length == 6) {
      encodedValue = abi.encodePacked(uint48(maskedValue));
    } else if (length == 7) {
      encodedValue = abi.encodePacked(uint56(maskedValue));
    } else if (length == 8) {
      encodedValue = abi.encodePacked(uint64(maskedValue));
    } else if (length == 9) {
      encodedValue = abi.encodePacked(uint72(maskedValue));
    } else if (length == 10) {
      encodedValue = abi.encodePacked(uint80(maskedValue));
    } else if (length == 11) {
      encodedValue = abi.encodePacked(uint88(maskedValue));
    } else if (length == 12) {
      encodedValue = abi.encodePacked(uint96(maskedValue));
    } else if (length == 13) {
      encodedValue = abi.encodePacked(uint104(maskedValue));
    } else if (length == 14) {
      encodedValue = abi.encodePacked(uint112(maskedValue));
    } else if (length == 15) {
      encodedValue = abi.encodePacked(uint120(maskedValue));
    } else if (length == 16) {
      encodedValue = abi.encodePacked(uint128(maskedValue));
    } else if (length == 17) {
      encodedValue = abi.encodePacked(uint136(maskedValue));
    } else if (length == 18) {
      encodedValue = abi.encodePacked(uint144(maskedValue));
    } else if (length == 19) {
      encodedValue = abi.encodePacked(uint152(maskedValue));
    } else if (length == 20) {
      encodedValue = abi.encodePacked(uint160(maskedValue));
    } else if (length == 21) {
      encodedValue = abi.encodePacked(uint168(maskedValue));
    } else if (length == 22) {
      encodedValue = abi.encodePacked(uint176(maskedValue));
    } else if (length == 23) {
      encodedValue = abi.encodePacked(uint184(maskedValue));
    } else if (length == 24) {
      encodedValue = abi.encodePacked(uint192(maskedValue));
    } else if (length == 25) {
      encodedValue = abi.encodePacked(uint200(maskedValue));
    } else if (length == 26) {
      encodedValue = abi.encodePacked(uint208(maskedValue));
    } else if (length == 27) {
      encodedValue = abi.encodePacked(uint216(maskedValue));
    } else if (length == 28) {
      encodedValue = abi.encodePacked(uint224(maskedValue));
    } else if (length == 29) {
      encodedValue = abi.encodePacked(uint232(maskedValue));
    } else if (length == 30) {
      encodedValue = abi.encodePacked(uint240(maskedValue));
    } else if (length == 31) {
      encodedValue = abi.encodePacked(uint248(maskedValue));
    } else {
      encodedValue = abi.encodePacked(uint256(maskedValue));
    }

    bytes memory fullData = bytes.concat(prefix, encodedValue, suffix);
    uint256 index = prefix.length;
    (uint256 result, uint256 newPointer) = bytesImp.readUintX(fullData, index, length);

    assertEq(result, maskedValue);
    assertEq(newPointer, index + length);
  }

  function test_readUint24(bytes calldata prefix, uint24 value, bytes calldata suffix) external view {
    bytes memory fullData = bytes.concat(prefix, abi.encodePacked(value), suffix);
    uint256 index = prefix.length;
    (uint24 result, uint256 newPointer) = bytesImp.readUint24(fullData, index);
    assertEq(result, value);
    assertEq(newPointer, index + 3);
  }

  function test_readUint64(bytes calldata prefix, uint64 value, bytes calldata suffix) external view {
    bytes memory fullData = bytes.concat(prefix, abi.encodePacked(value), suffix);
    uint256 index = prefix.length;
    (uint64 result, uint256 newPointer) = bytesImp.readUint64(fullData, index);
    assertEq(result, value);
    assertEq(newPointer, index + 8);
  }

  function test_readBytes4(bytes calldata prefix, bytes4 value, bytes calldata suffix) external view {
    bytes memory fullData = bytes.concat(prefix, abi.encodePacked(value), suffix);
    uint256 pointer = prefix.length;
    (bytes4 result, uint256 newPointer) = bytesImp.readBytes4(fullData, pointer);
    assertEq(result, value);
    assertEq(newPointer, pointer + 4);
  }

  function test_readBytes32(bytes calldata prefix, bytes32 value, bytes calldata suffix) external view {
    bytes memory fullData = bytes.concat(prefix, abi.encodePacked(value), suffix);
    uint256 pointer = prefix.length;
    (bytes32 result, uint256 newPointer) = bytesImp.readBytes32(fullData, pointer);
    assertEq(result, value);
    assertEq(newPointer, pointer + 32);
  }

  function test_readUint256(bytes calldata prefix, uint256 value, bytes calldata suffix) external view {
    bytes memory fullData = bytes.concat(prefix, abi.encodePacked(value), suffix);
    uint256 index = prefix.length;
    (uint256 result, uint256 newPointer) = bytesImp.readUint256(fullData, index);
    assertEq(result, value);
    assertEq(newPointer, index + 32);
  }

  function test_readUint160(bytes calldata prefix, uint160 value, bytes calldata suffix) external view {
    bytes memory fullData = bytes.concat(prefix, abi.encodePacked(value), suffix);
    uint256 index = prefix.length;
    (uint160 result, uint256 newPointer) = bytesImp.readUint160(fullData, index);
    assertEq(result, value);
    assertEq(newPointer, index + 20);
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
    (bytes32 resultR, bytes32 resultS, uint8 resultV, uint256 newPointer) = bytesImp.readRSVCompact(fullData, index);

    assertEq(resultR, r);
    assertEq(resultS, s);
    assertEq(resultV, expectedV);
    assertEq(newPointer, index + 64);
  }

  function test_readFirstUint8_emptyData() external view {
    bytes memory emptyData = new bytes(0);
    bytesImp.readFirstUint8(emptyData);
  }

  function test_readFirstUint16_emptyData() external view {
    bytes memory emptyData = new bytes(0);
    bytesImp.readFirstUint16(emptyData);
  }

  function test_readFirstUint24_emptyData() external view {
    bytes memory emptyData = new bytes(0);
    bytesImp.readFirstUint24(emptyData);
  }

  function test_readUint8_outOfBounds(
    bytes calldata data
  ) external view {
    vm.assume(data.length > 0);
    bytesImp.readUint8(data, data.length);
  }

  function test_readAddress_outOfBounds(
    bytes calldata data
  ) external view {
    vm.assume(data.length < 20);
    bytesImp.readAddress(data, 0);
  }

  function test_readUint8Address_outOfBounds(
    bytes calldata data
  ) external view {
    vm.assume(data.length < 21);
    bytesImp.readUint8Address(data, 0);
  }

  function test_readUint16_outOfBounds(
    bytes calldata data
  ) external view {
    vm.assume(data.length < 2);
    bytesImp.readUint16(data, 0);
  }

  function test_readUint24_outOfBounds(
    bytes calldata data
  ) external view {
    vm.assume(data.length < 3);
    bytesImp.readUint24(data, 0);
  }

  function test_readUint64_outOfBounds(
    bytes calldata data
  ) external view {
    vm.assume(data.length < 8);
    bytesImp.readUint64(data, 0);
  }

  function test_readBytes4_outOfBounds(
    bytes calldata data
  ) external view {
    vm.assume(data.length < 4);
    bytesImp.readBytes4(data, 0);
  }

  function test_readBytes32_outOfBounds(
    bytes calldata data
  ) external view {
    vm.assume(data.length < 32);
    bytesImp.readBytes32(data, 0);
  }

  function test_readUint256_outOfBounds(
    bytes calldata data
  ) external view {
    vm.assume(data.length < 32);
    bytesImp.readUint256(data, 0);
  }

  function test_readUint160_outOfBounds(
    bytes calldata data
  ) external view {
    vm.assume(data.length < 20);
    bytesImp.readUint160(data, 0);
  }

  function test_readRSVCompact_outOfBounds(
    bytes calldata data
  ) external view {
    vm.assume(data.length < 64);
    bytesImp.readRSVCompact(data, 0);
  }

}
