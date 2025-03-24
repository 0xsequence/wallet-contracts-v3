// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Calls } from "../../src/modules/Calls.sol";

import { Payload } from "../../src/modules/Payload.sol";
import { AdvTest } from "../utils/TestUtils.sol";

import { Payload } from "../../src/modules/Payload.sol";

import { IDelegatedExtension } from "../../src/modules/interfaces/IDelegatedExtension.sol";
import { PrimitivesRPC } from "../utils/PrimitivesRPC.sol";

import "forge-std/console.sol";

contract CallsImp is Calls {

  bytes public expectedSignature;
  bytes32 public expectedOpHash;

  function setExpectedSignature(
    bytes calldata _signature
  ) external {
    expectedSignature = _signature;
  }

  function setExpectedOpHash(
    bytes32 _opHash
  ) external {
    expectedOpHash = _opHash;
  }

  function writeNonce(uint256 _space, uint256 _nonce) external {
    _writeNonce(_space, _nonce);
  }

  function signatureValidation(
    Payload.Decoded memory,
    bytes calldata _signature
  ) internal view override returns (bool isValid, bytes32 opHash) {
    return (keccak256(_signature) == keccak256(expectedSignature), expectedOpHash);
  }

  function _isValidImage(
    bytes32
  ) internal pure override returns (bool) {
    revert("Not used");
  }

  function _updateImageHash(
    bytes32
  ) internal pure override {
    revert("Not used");
  }

}

contract MockDelegatecall is IDelegatedExtension {

  event OpHash(bytes32 _opHash);
  event StartingGas(uint256 _startingGas);
  event Index(uint256 _index);
  event NumCalls(uint256 _numCalls);
  event Space(uint256 _space);
  event Data(bytes _data);

  function handleSequenceDelegateCall(
    bytes32 _opHash,
    uint256 _startingGas,
    uint256 _index,
    uint256 _numCalls,
    uint256 _space,
    bytes calldata _data
  ) external {
    emit OpHash(_opHash);
    emit StartingGas(_startingGas);
    emit Index(_index);
    emit NumCalls(_numCalls);
    emit Space(_space);
    emit Data(_data);
  }

}

struct CallsPayload {
  bool noChainId;
  Payload.Call[] calls;
  uint160 space;
  uint56 nonce;
}

function toDecodedPayload(
  CallsPayload memory _payload
) pure returns (Payload.Decoded memory _decoded) {
  _decoded.kind = Payload.KIND_TRANSACTIONS;
  _decoded.calls = _payload.calls;
  _decoded.space = _payload.space;
  _decoded.nonce = _payload.nonce;
}

contract CallsTest is AdvTest {

  CallsImp public calls = new CallsImp();

  event CallSucceeded(bytes32 _opHash, uint256 _index);
  event CallSkipped(bytes32 _opHash, uint256 _index);

  function test_execute(bytes32 _opHash, CallsPayload memory _payload, bytes calldata _signature) external {
    vm.assume(_payload.calls.length < 3);
    address mockDelegatecall = address(new MockDelegatecall());
    Payload.Decoded memory decoded = toDecodedPayload(_payload);

    uint256 totalEther;

    for (uint256 i = 0; i < decoded.calls.length; i++) {
      decoded.calls[i].to = boundNoPrecompile(decoded.calls[i].to);
      decoded.calls[i].value = bound(decoded.calls[i].value, 0, 100_000_000_000_000 ether);
      decoded.calls[i].gasLimit = bound(decoded.calls[i].gasLimit, 0, 1_000_000_000);

      if (!decoded.calls[i].delegateCall && !decoded.calls[i].onlyFallback) {
        totalEther += decoded.calls[i].value;
      }

      if (decoded.calls[i].delegateCall && decoded.calls[i].gasLimit != 0) {
        decoded.calls[i].gasLimit = bound(decoded.calls[i].gasLimit, 100_000, 1_000_000_000);
      }

      vm.assume(decoded.calls[i].to != address(calls));
    }

    vm.deal(address(calls), totalEther);

    boundToLegalPayload(decoded);

    bytes memory packed = PrimitivesRPC.toPackedPayload(vm, decoded);
    calls.setExpectedSignature(_signature);
    calls.setExpectedOpHash(_opHash);
    calls.writeNonce(decoded.space, decoded.nonce);

    for (uint256 i = 0; i < decoded.calls.length; i++) {
      if (decoded.calls[i].onlyFallback) {
        vm.expectEmit(true, true, true, true, address(calls));
        emit CallSkipped(_opHash, i);
      } else {
        vm.deal(decoded.calls[i].to, 0);

        if (decoded.calls[i].delegateCall) {
          vm.etch(decoded.calls[i].to, mockDelegatecall.code);
          vm.expectEmit(true, true, true, true, address(calls));
          emit MockDelegatecall.OpHash(_opHash);
          // Can't test gasleft() because memory expansion makes it not so reliable
          // emit MockDelegatecall.StartingGas(gasleft());
          vm.expectEmit(true, true, true, true, address(calls));
          emit MockDelegatecall.Index(i);
          vm.expectEmit(true, true, true, true, address(calls));
          emit MockDelegatecall.NumCalls(decoded.calls.length);
          vm.expectEmit(true, true, true, true, address(calls));
          emit MockDelegatecall.Space(decoded.space);
          vm.expectEmit(true, true, true, true, address(calls));
          emit MockDelegatecall.Data(decoded.calls[i].data);
        } else {
          vm.expectCall(decoded.calls[i].to, decoded.calls[i].data);
        }

        emit CallSucceeded(_opHash, i);
      }
    }

    calls.execute(packed, _signature);

    assertEq(address(calls).balance, 0);

    // Assert balance of each destination contract
    for (uint256 i = 0; i < decoded.calls.length; i++) {
      if (
        !decoded.calls[i].delegateCall && decoded.calls[i].to.balance != decoded.calls[i].value
          && !decoded.calls[i].onlyFallback
      ) {
        // We need to do a full recount because maybe the contract is duplicated so multiple transfers are done
        uint256 totalTransferred = 0;
        for (uint256 j = 0; j < decoded.calls.length; j++) {
          if (
            !decoded.calls[j].delegateCall && decoded.calls[j].to == decoded.calls[i].to
              && !decoded.calls[j].onlyFallback
          ) {
            totalTransferred += decoded.calls[j].value;
          }
        }
        assertEq(totalTransferred, decoded.calls[i].to.balance);
      }
    }
  }

  function test_self_execute(
    CallsPayload memory _payload
  ) external {
    vm.assume(_payload.calls.length < 3);
    address mockDelegatecall = address(new MockDelegatecall());

    Payload.Decoded memory decoded = toDecodedPayload(_payload);

    uint256 totalEther;

    for (uint256 i = 0; i < decoded.calls.length; i++) {
      decoded.calls[i].to = boundNoPrecompile(decoded.calls[i].to);
      decoded.calls[i].value = bound(decoded.calls[i].value, 0, 100_000_000_000_000 ether);
      decoded.calls[i].gasLimit = bound(decoded.calls[i].gasLimit, 0, 1_000_000_000);

      if (decoded.calls[i].delegateCall && decoded.calls[i].gasLimit != 0) {
        decoded.calls[i].gasLimit = bound(decoded.calls[i].gasLimit, 100_000, 1_000_000_000);
      }

      if (!decoded.calls[i].delegateCall && !decoded.calls[i].onlyFallback) {
        totalEther += decoded.calls[i].value;
      }

      vm.assume(decoded.calls[i].to != address(calls));
    }

    vm.deal(address(calls), totalEther);

    boundToLegalPayload(decoded);

    bytes32 opHash = Payload.hashFor(decoded, address(calls));
    bytes memory packed = PrimitivesRPC.toPackedPayload(vm, decoded);

    for (uint256 i = 0; i < decoded.calls.length; i++) {
      if (decoded.calls[i].onlyFallback) {
        vm.expectEmit(true, true, true, true, address(calls));
        emit CallSkipped(opHash, i);
      } else {
        vm.deal(decoded.calls[i].to, 0);
        if (decoded.calls[i].delegateCall) {
          vm.etch(decoded.calls[i].to, mockDelegatecall.code);
          vm.expectEmit(true, true, true, true, address(calls));
          emit MockDelegatecall.OpHash(opHash);
          // Can't reliably test gasleft() due to memory expansion changes
          vm.expectEmit(true, true, true, true, address(calls));
          emit MockDelegatecall.Index(i);
          vm.expectEmit(true, true, true, true, address(calls));
          emit MockDelegatecall.NumCalls(decoded.calls.length);
          vm.expectEmit(true, true, true, true, address(calls));
          emit MockDelegatecall.Space(decoded.space);
          vm.expectEmit(true, true, true, true, address(calls));
          emit MockDelegatecall.Data(decoded.calls[i].data);
        } else {
          vm.expectCall(decoded.calls[i].to, decoded.calls[i].data);
        }
        vm.expectEmit(true, true, true, true, address(calls));
        emit CallSucceeded(opHash, i);
      }
    }

    vm.prank(address(calls));
    calls.selfExecute(packed);

    assertEq(address(calls).balance, 0);

    for (uint256 i = 0; i < decoded.calls.length; i++) {
      if (
        !decoded.calls[i].delegateCall && decoded.calls[i].to.balance != decoded.calls[i].value
          && !decoded.calls[i].onlyFallback
      ) {
        uint256 totalTransferred = 0;
        for (uint256 j = 0; j < decoded.calls.length; j++) {
          if (
            !decoded.calls[j].delegateCall && decoded.calls[j].to == decoded.calls[i].to
              && !decoded.calls[j].onlyFallback
          ) {
            totalTransferred += decoded.calls[j].value;
          }
        }
        assertEq(totalTransferred, decoded.calls[i].to.balance);
      }
    }
  }

}
