// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

/**
 * @title Library for reading data from bytes arrays
 * @author Agustin Aguilar (aa@horizon.io), Michael Standen (mstan@horizon.io)
 * @notice This library contains functions for reading data from bytes arrays.
 *
 * @dev These functions do not check if the input index is within the bounds of the data array.
 *         Reading out of bounds may return dirty values.
 */
library LibBytesPointer {

  function readFirstUint8(
    bytes calldata _data
  ) internal pure returns (uint8 a, uint256 newPointer) {
    assembly {
      let word := calldataload(_data.offset)
      a := shr(248, word)
      newPointer := 1
    }
  }

  function readFirstUint16(
    bytes calldata _data
  ) internal pure returns (uint16 a, uint256 newPointer) {
    assembly {
      let word := calldataload(_data.offset)
      a := shr(240, word)
      newPointer := 2
    }
  }

  function readFirstUint24(
    bytes calldata _data
  ) internal pure returns (uint24 a, uint256 newPointer) {
    assembly {
      let word := calldataload(_data.offset)
      a := shr(232, word)
      newPointer := 3
    }
  }

  function readUint8(bytes calldata _data, uint256 _index) internal pure returns (uint8 a, uint256 newPointer) {
    assembly {
      let word := calldataload(add(_index, _data.offset))
      a := shr(248, word)
      newPointer := add(_index, 1)
    }
  }

  function readAddress(bytes calldata _data, uint256 _index) internal pure returns (address a, uint256 newPointer) {
    assembly {
      let word := calldataload(add(_index, _data.offset))
      a := and(shr(96, word), 0xffffffffffffffffffffffffffffffffffffffff)
      newPointer := add(_index, 20)
    }
  }

  function readUint8Address(
    bytes calldata _data,
    uint256 _index
  ) internal pure returns (uint8 a, address b, uint256 newPointer) {
    assembly {
      let word := calldataload(add(_index, _data.offset))
      a := shr(248, word)
      b := and(shr(88, word), 0xffffffffffffffffffffffffffffffffffffffff)
      newPointer := add(_index, 21)
    }
  }

  function readUint16(bytes calldata _data, uint256 _index) internal pure returns (uint16 a, uint256 newPointer) {
    assembly {
      let word := calldataload(add(_index, _data.offset))
      a := and(shr(240, word), 0xffff)
      newPointer := add(_index, 2)
    }
  }

  function readUintX(
    bytes calldata _data,
    uint256 _index,
    uint256 _length
  ) internal pure returns (uint256 a, uint256 newPointer) {
    assembly {
      let word := calldataload(add(_index, _data.offset))
      let shift := sub(256, mul(_length, 8))
      a := and(shr(shift, word), sub(shl(mul(8, _length), 1), 1))
      newPointer := add(_index, _length)
    }
  }

  function readUint24(bytes calldata _data, uint256 _index) internal pure returns (uint24 a, uint256 newPointer) {
    assembly {
      let word := calldataload(add(_index, _data.offset))
      a := and(shr(232, word), 0xffffff)
      newPointer := add(_index, 3)
    }
  }

  function readUint48(bytes calldata _data, uint256 _index) internal pure returns (uint48 a, uint256 newPointer) {
    assembly {
      let word := calldataload(add(_index, _data.offset))
      a := and(shr(208, word), 0xFFFFFFFFFFFF)
      newPointer := add(_index, 6)
    }
  }

  function readUint64(bytes calldata _data, uint256 _index) internal pure returns (uint64 a, uint256 newPointer) {
    assembly {
      let word := calldataload(add(_index, _data.offset))
      a := and(shr(192, word), 0xffffffffffffffff)
      newPointer := add(_index, 8)
    }
  }

  function readBytes4(bytes calldata _data, uint256 _pointer) internal pure returns (bytes4 a, uint256 newPointer) {
    assembly {
      a := calldataload(add(_pointer, _data.offset))
      newPointer := add(_pointer, 4)
    }
  }

  function readBytes32(bytes calldata _data, uint256 _pointer) internal pure returns (bytes32 a, uint256 newPointer) {
    assembly {
      a := calldataload(add(_pointer, _data.offset))
      newPointer := add(_pointer, 32)
    }
  }

  function readUint256(bytes calldata _data, uint256 _index) internal pure returns (uint256 a, uint256 newPointer) {
    assembly {
      a := calldataload(add(_index, _data.offset))
      newPointer := add(_index, 32)
    }
  }

  function readUint160(bytes calldata _data, uint256 _index) internal pure returns (uint160 a, uint256 newPointer) {
    assembly {
      let word := calldataload(add(_index, _data.offset))
      a := and(shr(96, word), 0xffffffffffffffffffffffffffffffffffffffff)
      newPointer := add(_index, 20)
    }
  }

  // ERC-2098 Compact Signature
  function readRSVCompact(
    bytes calldata _data,
    uint256 _index
  ) internal pure returns (bytes32 r, bytes32 s, uint8 v, uint256 newPointer) {
    uint256 yParityAndS;
    assembly {
      r := calldataload(add(_index, _data.offset))
      yParityAndS := calldataload(add(_index, add(_data.offset, 32)))
      newPointer := add(_index, 64)
    }
    uint256 yParity = uint256(yParityAndS >> 255);
    s = bytes32(uint256(yParityAndS) & ((1 << 255) - 1));
    v = uint8(yParity) + 27;
  }

}
