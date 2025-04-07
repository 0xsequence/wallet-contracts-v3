// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../../src/modules/Payload.sol";
import "forge-std/Test.sol";
import "forge-std/console.sol";

contract AdvTest is Test {

  function boundPk(
    uint256 _a
  ) internal pure returns (uint256) {
    _a = bound(_a, 1, 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364139);
    return _a;
  }

  function boundToLegalPayload(
    Payload.Decoded memory _payload
  ) internal pure {
    _payload.kind = uint8(bound(_payload.kind, uint8(0), uint8(Payload.KIND_DIGEST)));

    if (_payload.kind == Payload.KIND_TRANSACTIONS) {
      _payload.space = bound(_payload.space, 0, type(uint160).max);
      _payload.nonce = bound(_payload.nonce, 0, type(uint56).max);

      for (uint256 i = 0; i < _payload.calls.length; i++) {
        _payload.calls[i].behaviorOnError = bound(
          _payload.calls[i].behaviorOnError,
          uint256(Payload.BEHAVIOR_IGNORE_ERROR),
          uint256(Payload.BEHAVIOR_ABORT_ON_ERROR)
        );
      }
    }
  }

  function assumeNotPrecompile2(
    address _addr
  ) internal view {
    assumeNotPrecompile(_addr);
    vm.assume(_addr.code.length == 0);
    vm.assume(_addr != address(0x000000000000000000636F6e736F6c652e6c6f67));
    vm.assume(_addr != address(0x4e59b44847b379578588920cA78FbF26c0B4956C));
  }

  function useSeed(
    uint256 seed
  ) internal pure returns (bytes32 value, uint256 newSeed) {
    value = keccak256(abi.encode(seed));
    newSeed = uint256(value);
  }

  function boundNoPrecompile(
    address _addr
  ) internal view returns (address) {
    address candidate = _addr;
    address invalid1 = address(0x000000000000000000636F6e736F6c652e6c6f67);
    address invalid2 = address(0x4e59b44847b379578588920cA78FbF26c0B4956C);

    while (
      (uint160(candidate) >= 1 && uint160(candidate) <= 0xff) || candidate == invalid1 || candidate == invalid2
        || candidate.code.length > 0
    ) {
      candidate = address(uint160(uint256(keccak256(abi.encode(candidate)))));
    }

    return candidate;
  }

  // ERC-2098 Compact Signature
  function signRSVCompact(bytes32 hash, Vm.Wallet memory wallet) internal pure returns (bytes memory) {
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(wallet.privateKey, hash);
    uint256 yParity = v == 28 ? 1 << 255 : 0;
    bytes32 yParityAndS = bytes32(uint256(s) | yParity);
    return abi.encodePacked(r, yParityAndS);
  }

  function generateRandomString(
    uint256 seed
  ) internal pure returns (string memory) {
    uint256 size;

    (seed, size) = useSeed(seed, 0, 300);
    bytes memory _bytes = new bytes(size);

    // For every byte, select a UTF-8 random char (a-z, A-Z, 0-9, _, -, !, or ?)
    for (uint256 i = 0; i < size; i++) {
      uint256 charType;
      (seed, charType) = useSeed(seed, 0, 4);

      if (charType == 0) {
        // lowercase a-z (ASCII 97-122)
        uint256 char;
        (seed, char) = useSeed(seed, 97, 122);
        _bytes[i] = bytes1(uint8(char));
      } else if (charType == 1) {
        // uppercase A-Z (ASCII 65-90)
        uint256 char;
        (seed, char) = useSeed(seed, 65, 90);
        _bytes[i] = bytes1(uint8(char));
      } else if (charType == 2) {
        // numbers 0-9 (ASCII 48-57)
        uint256 char;
        (seed, char) = useSeed(seed, 48, 57);
        _bytes[i] = bytes1(uint8(char));
      } else {
        // special characters: _, -, !, ?
        uint256 specialChar;
        (seed, specialChar) = useSeed(seed, 0, 3);
        if (specialChar == 0) {
          _bytes[i] = bytes1(uint8(95)); // _ (underscore)
        } else if (specialChar == 1) {
          _bytes[i] = bytes1(uint8(45)); // - (hyphen)
        } else if (specialChar == 2) {
          _bytes[i] = bytes1(uint8(33)); // ! (exclamation mark)
        } else {
          _bytes[i] = bytes1(uint8(63)); // ? (question mark)
        }
      }
    }
    return string(_bytes);
  }

  function useSeed(uint256 _seed, uint256 _min, uint256 _max) internal pure returns (uint256 seed, uint256 val) {
    val = uint256(keccak256(abi.encode(_seed)));
    seed = val;
    val = val % (_max - _min + 1) + _min;
  }

}
