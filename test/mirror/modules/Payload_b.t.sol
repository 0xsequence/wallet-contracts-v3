// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "src/modules/Payload.sol";
import { SequenceLib } from "../utils/SequenceLib.sol";
import { AdvTest } from "../../utils/TestUtils.sol";

contract ExternalPayload {
  function fromPackedCalls(
    bytes calldata packed
  ) external view returns (Payload.Decoded memory _decoded) {
    return Payload.fromPackedCalls(packed);
  }

  function hash(
    Payload.Decoded memory _decoded
  ) external view returns (bytes32) {
    return Payload.hash(_decoded);
  }

  function hashFor(
    Payload.Decoded memory _decoded,
    address _wallet
  ) external view returns (bytes32) {
    return Payload.hashFor(_decoded, _wallet);
  }
}

contract PayloadTest is AdvTest {
  function test_unpackPackedCalls(Payload.Decoded memory _decoded) external {
    _decoded.kind = Payload.KIND_TRANSACTIONS;
    _decoded.noChainId = false; // this is ignored at this level
    boundToLegalPayload(_decoded);

    ExternalPayload externalPayload = new ExternalPayload();
    bytes memory packed = SequenceLib.toPackedCalls(_decoded, address(externalPayload));
    Payload.Decoded memory unpacked = externalPayload.fromPackedCalls(packed);
    assertEq(unpacked.kind, _decoded.kind, "kind");
    assertEq(unpacked.noChainId, _decoded.noChainId, "noChainId");
    assertEq(unpacked.calls.length, _decoded.calls.length, "calls.length");
    assertEq(unpacked.space, _decoded.space, "space");
    assertEq(unpacked.nonce, _decoded.nonce, "nonce");
    for (uint256 i = 0; i < _decoded.calls.length; i++) {
      assertEq(unpacked.calls[i].to, _decoded.calls[i].to, "calls[i].to");
      assertEq(unpacked.calls[i].value, _decoded.calls[i].value, "calls[i].value");
      assertEq(unpacked.calls[i].data, _decoded.calls[i].data, "calls[i].data");
      assertEq(unpacked.calls[i].gasLimit, _decoded.calls[i].gasLimit, "calls[i].gasLimit");
      assertEq(unpacked.calls[i].delegateCall, _decoded.calls[i].delegateCall, "calls[i].delegateCall");
      assertEq(unpacked.calls[i].onlyFallback, _decoded.calls[i].onlyFallback, "calls[i].onlyFallback");
      assertEq(unpacked.calls[i].behaviorOnError, _decoded.calls[i].behaviorOnError, "calls[i].behaviorOnError");
    }
  }

  function test_noCallHashCollision(Payload.Call memory _call, Payload.Call memory _call2) external pure {
    // If calls are identical, their hash should be identical
    if (isEqualCall(_call, _call2)) {
      assertEq(Payload.hashCall(_call), Payload.hashCall(_call2), "hash collision");
    } else {
      assertNotEq(Payload.hashCall(_call), Payload.hashCall(_call2), "no hash collision");
    }
  }

  function test_noCallsHashCollision(Payload.Call[] memory _calls, Payload.Call[] memory _calls2) external pure {
    // If calls are identical, their hash should be identical
    bool allEqual = false;
    if (_calls.length == _calls2.length) {
      for (uint256 i = 0; i < _calls.length; i++) {
        if (!isEqualCall(_calls[i], _calls2[i])) {
          allEqual = false;
          break;
        }
      }
    }

    if (allEqual) {
      assertEq(Payload.hashCalls(_calls), Payload.hashCalls(_calls2), "hash collision");
    } else {
      assertNotEq(Payload.hashCalls(_calls), Payload.hashCalls(_calls2), "no hash collision");
    }
  }

  function test_noPayloadHashCollision(Payload.Decoded memory _decoded, Payload.Decoded memory _decoded2) external {
    bool isEqual = isEqualPayload(_decoded, _decoded2);

    ExternalPayload externalPayload = new ExternalPayload();

    // If any kind is invalid, then there should revert
    if (!isValidKind(_decoded)) {
      vm.expectRevert(abi.encodeWithSelector(Payload.InvalidKind.selector, _decoded.kind));
      externalPayload.hash(_decoded);
      return;
    } else if (!isValidKind(_decoded2)) {
      vm.expectRevert(abi.encodeWithSelector(Payload.InvalidKind.selector, _decoded2.kind));
      externalPayload.hash(_decoded2);
      return;
    }

    if (isEqual) {
      assertEq(externalPayload.hash(_decoded), externalPayload.hash(_decoded2), "hash collision");
    } else {
      assertNotEq(externalPayload.hash(_decoded), externalPayload.hash(_decoded2), "no hash collision");
    }
  }

  function test_noPayloadHashForCollision(Payload.Decoded memory _decoded, Payload.Decoded memory _decoded2, address _wallet1, address _wallet2) external {
    bool isEqual = isEqualPayload(_decoded, _decoded2);

    ExternalPayload externalPayload = new ExternalPayload();

    // If any kind is invalid, then there should revert
    if (!isValidKind(_decoded)) {
      vm.expectRevert(abi.encodeWithSelector(Payload.InvalidKind.selector, _decoded.kind));
      externalPayload.hash(_decoded);
      return;
    } else if (!isValidKind(_decoded2)) {
      vm.expectRevert(abi.encodeWithSelector(Payload.InvalidKind.selector, _decoded2.kind));
      externalPayload.hash(_decoded2);
      return;
    }

    if (isEqual && _wallet1 == _wallet2) {
      assertEq(externalPayload.hashFor(_decoded, _wallet1), externalPayload.hashFor(_decoded2, _wallet2), "hash collision");
    } else {
      assertNotEq(externalPayload.hashFor(_decoded, _wallet1), externalPayload.hashFor(_decoded2, _wallet2), "no hash collision");
    }
  }

  function isValidKind(Payload.Decoded memory _decoded) internal pure returns (bool) {
    return
      _decoded.kind == Payload.KIND_TRANSACTIONS ||
      _decoded.kind == Payload.KIND_MESSAGE ||
      _decoded.kind == Payload.KIND_CONFIG_UPDATE ||
      _decoded.kind == Payload.KIND_DIGEST;
  }

  function isEqualPayload(Payload.Decoded memory _decoded, Payload.Decoded memory _decoded2) internal pure returns (bool) {
    if (
      _decoded.kind != _decoded2.kind ||
      _decoded.noChainId != _decoded2.noChainId ||
      _decoded.parentWallets.length != _decoded2.parentWallets.length
    ) {
      return false;
    }

    for (uint256 i = 0; i < _decoded.parentWallets.length; i++) {
      if (_decoded.parentWallets[i] != _decoded2.parentWallets[i]) {
        return false;
      }
    }

    if (_decoded.kind == Payload.KIND_TRANSACTIONS) {
      if (_decoded.calls.length != _decoded2.calls.length) {
        return false;
      }

      for (uint256 i = 0; i < _decoded.calls.length; i++) {
        if (!isEqualCall(_decoded.calls[i], _decoded2.calls[i])) {
          return false;
        }
      }
    } else if (_decoded.kind == Payload.KIND_MESSAGE) {
      return keccak256(_decoded.message) == keccak256(_decoded2.message);
    } else if (_decoded.kind == Payload.KIND_CONFIG_UPDATE) {
      return _decoded.imageHash == _decoded2.imageHash;
    } else if (_decoded.kind == Payload.KIND_DIGEST) {
      return _decoded.digest == _decoded2.digest;
    } else {
      return false;
    }

    return true;
  }

  function isEqualCall(Payload.Call memory _call, Payload.Call memory _call2) internal pure returns (bool) {
    return
      _call.to == _call2.to &&
      _call.value == _call2.value &&
      keccak256(_call.data) == keccak256(_call2.data) &&
      _call.gasLimit == _call2.gasLimit &&
      _call.delegateCall == _call2.delegateCall &&
      _call.onlyFallback == _call2.onlyFallback &&
      _call.behaviorOnError == _call2.behaviorOnError;
  }
}