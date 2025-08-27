// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { AdvTest } from "../../utils/TestUtils.sol";
import { SequencePayloadsLib } from "../utils/SequencePayloadsLib.sol";
import { Payload } from "src/modules/Payload.sol";

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

  function hashFor(Payload.Decoded memory _decoded, address _wallet) external view returns (bytes32) {
    return Payload.hashFor(_decoded, _wallet);
  }

}

contract PayloadTest is AdvTest {

  function test_unpackPackedCalls(
    Payload.Decoded memory _decoded
  ) external {
    vm.assume(_decoded.calls.length < 100);

    _decoded.kind = Payload.KIND_TRANSACTIONS;
    _decoded.noChainId = false; // this is ignored at this level
    boundToLegalPayload(_decoded);

    ExternalPayload externalPayload = new ExternalPayload();
    bytes memory packed = SequencePayloadsLib.toPackedCalls(_decoded, address(externalPayload));
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

  function test_noCallHashCollision(Payload.Call memory _a, Payload.Call memory _b) external pure {
    // If calls are identical, their hash should be identical
    if (isEqualCall(_a, _b)) {
      assertEq(Payload.hashCall(_a), Payload.hashCall(_b), "hash collision");
    } else {
      assertNotEq(Payload.hashCall(_a), Payload.hashCall(_b), "no hash collision");
    }
  }

  function test_noCallsHashCollision(Payload.Call[] memory _a, Payload.Call[] memory _b) external pure {
    // If calls are identical, their hash should be identical
    bool allEqual = _a.length == _b.length;
    if (allEqual) {
      for (uint256 i = 0; i < _a.length; i++) {
        if (!isEqualCall(_a[i], _b[i])) {
          allEqual = false;
          break;
        }
      }
    }

    if (allEqual) {
      assertEq(Payload.hashCalls(_a), Payload.hashCalls(_b), "hash collision");
    } else {
      assertNotEq(Payload.hashCalls(_a), Payload.hashCalls(_b), "no hash collision");
    }
  }

  function test_noPayloadHashCollision(Payload.Decoded memory _a, Payload.Decoded memory _b) external {
    bool isEqual = isEqualPayload(_a, _b);

    ExternalPayload externalPayload = new ExternalPayload();

    // If any kind is invalid, then there should revert
    if (!isValidKind(_a)) {
      vm.expectRevert(abi.encodeWithSelector(Payload.InvalidKind.selector, _a.kind));
      externalPayload.hash(_a);
      return;
    } else if (!isValidKind(_b)) {
      vm.expectRevert(abi.encodeWithSelector(Payload.InvalidKind.selector, _b.kind));
      externalPayload.hash(_b);
      return;
    }

    if (isEqual) {
      assertEq(externalPayload.hash(_a), externalPayload.hash(_b), "hash collision");
    } else {
      assertNotEq(externalPayload.hash(_a), externalPayload.hash(_b), "no hash collision");
    }
  }

  function test_noPayloadHashForCollision(
    Payload.Decoded memory _a,
    Payload.Decoded memory _b,
    address _wallet1,
    address _wallet2
  ) external {
    bool isEqual = isEqualPayload(_a, _b);

    ExternalPayload externalPayload = new ExternalPayload();

    // If any kind is invalid, then there should revert
    if (!isValidKind(_a)) {
      vm.expectRevert(abi.encodeWithSelector(Payload.InvalidKind.selector, _a.kind));
      externalPayload.hash(_a);
      return;
    } else if (!isValidKind(_b)) {
      vm.expectRevert(abi.encodeWithSelector(Payload.InvalidKind.selector, _b.kind));
      externalPayload.hash(_b);
      return;
    }

    if (isEqual && _wallet1 == _wallet2) {
      assertEq(externalPayload.hashFor(_a, _wallet1), externalPayload.hashFor(_b, _wallet2), "hash collision");
    } else {
      assertNotEq(externalPayload.hashFor(_a, _wallet1), externalPayload.hashFor(_b, _wallet2), "no hash collision");
    }
  }

  function test_EIP712_walletParamAndSelf(address _w1, address _w2) external {
    vm.assume(_w1 != _w2);

    ExternalPayload ep = new ExternalPayload();
    Payload.Decoded memory m;
    m.kind = Payload.KIND_MESSAGE;
    m.message = bytes("hello");

    bytes32 a = ep.hashFor(m, _w1);
    bytes32 b = ep.hashFor(m, _w2);
    assertNotEq(a, b, "hashFor must change with wallet");

    bytes32 c = ep.hash(m);
    bytes32 d = ep.hashFor(m, address(ep));
    assertEq(c, d, "hash should equal hashFor(self)");
  }

  function test_EIP712_noChainIdToggle(address _wallet, uint64 _chainId1, uint64 _chainId2) external {
    vm.assume(_chainId1 != _chainId2);
    ExternalPayload ep = new ExternalPayload();

    Payload.Decoded memory m;
    m.kind = Payload.KIND_MESSAGE;
    m.message = bytes("x");

    // noChainId = false => chain id affects hash
    m.noChainId = false;
    vm.chainId(_chainId1);
    bytes32 h1 = ep.hashFor(m, _wallet);
    vm.chainId(_chainId2);
    bytes32 h2 = ep.hashFor(m, _wallet);
    assertNotEq(h1, h2, "chainId must change EIP712 hash");

    // noChainId = true => chain id ignored
    m.noChainId = true;
    bytes32 h3 = ep.hashFor(m, _wallet);
    vm.chainId(_chainId1);
    bytes32 h4 = ep.hashFor(m, _wallet);
    assertEq(h3, h4, "noChainId=true must ignore chainId");
  }

  function test_walletsOrderMatters(address _a, address _b) external {
    vm.assume(_a != _b);
    ExternalPayload ep = new ExternalPayload();

    Payload.Decoded memory m;
    m.kind = Payload.KIND_MESSAGE;
    m.message = "x";
    m.parentWallets = new address[](2);
    m.parentWallets[0] = _a;
    m.parentWallets[1] = _b;
    bytes32 h1 = ep.hash(m);

    m.parentWallets[0] = _b;
    m.parentWallets[1] = _a;
    bytes32 h2 = ep.hash(m);

    assertNotEq(h1, h2, "wallet order must affect hash");
  }

  function test_digestEqualsMessageHash(
    bytes memory _msgData
  ) external {
    ExternalPayload ep = new ExternalPayload();

    Payload.Decoded memory m;
    m.kind = Payload.KIND_MESSAGE;
    m.message = _msgData;

    Payload.Decoded memory d;
    d.kind = Payload.KIND_DIGEST;
    d.digest = keccak256(_msgData);

    assertEq(ep.hash(m), ep.hash(d), "digest should match message hash path");
  }

  function isValidKind(
    Payload.Decoded memory _a
  ) internal pure returns (bool) {
    return _a.kind == Payload.KIND_TRANSACTIONS || _a.kind == Payload.KIND_MESSAGE
      || _a.kind == Payload.KIND_CONFIG_UPDATE || _a.kind == Payload.KIND_DIGEST;
  }

  function isEqualPayload(Payload.Decoded memory _a, Payload.Decoded memory _b) internal pure returns (bool) {
    if (_a.kind != _b.kind || _a.noChainId != _b.noChainId || _a.parentWallets.length != _b.parentWallets.length) {
      return false;
    }

    for (uint256 i = 0; i < _a.parentWallets.length; i++) {
      if (_a.parentWallets[i] != _b.parentWallets[i]) {
        return false;
      }
    }

    if (_a.kind == Payload.KIND_TRANSACTIONS) {
      if (_a.calls.length != _b.calls.length) {
        return false;
      }
      if (_a.space != _b.space || _a.nonce != _b.nonce || _a.calls.length != _b.calls.length) {
        return false;
      }

      for (uint256 i = 0; i < _a.calls.length; i++) {
        if (!isEqualCall(_a.calls[i], _b.calls[i])) {
          return false;
        }
      }
    } else if (_a.kind == Payload.KIND_MESSAGE) {
      return keccak256(_a.message) == keccak256(_b.message);
    } else if (_a.kind == Payload.KIND_CONFIG_UPDATE) {
      return _a.imageHash == _b.imageHash;
    } else if (_a.kind == Payload.KIND_DIGEST) {
      return _a.digest == _b.digest;
    } else {
      return false;
    }

    return true;
  }

  function isEqualCall(Payload.Call memory _a, Payload.Call memory _b) internal pure returns (bool) {
    return _a.to == _b.to && _a.value == _b.value && keccak256(_a.data) == keccak256(_b.data)
      && _a.gasLimit == _b.gasLimit && _a.delegateCall == _b.delegateCall && _a.onlyFallback == _b.onlyFallback
      && _a.behaviorOnError == _b.behaviorOnError;
  }

}
