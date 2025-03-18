// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../../src/modules/Payload.sol";
import { PrimitivesRPC } from "../utils/PrimitivesRPC.sol";

import { AdvTest } from "../utils/TestUtils.sol";
import { Test, Vm } from "forge-std/Test.sol";
import { console } from "forge-std/console.sol";

contract PayloadImp {

  function fromPackedCalls(
    bytes calldata packed
  ) external view returns (Payload.Decoded memory) {
    return Payload.fromPackedCalls(packed);
  }

}

contract PayloadTest is AdvTest {

  PayloadImp public payloadImp;

  function setUp() public {
    payloadImp = new PayloadImp();
  }

  function test_fromPackedCalls(Payload.Call[] memory _calls, uint256 _space, uint256 _nonce) external {
    // Convert nonce into legal range
    _nonce = bound(_nonce, 0, type(uint56).max);
    _space = bound(_space, 0, type(uint160).max);

    for (uint256 i = 0; i < _calls.length; i++) {
      // Convert behaviors into legal ones
      _calls[i].behaviorOnError = bound(
        _calls[i].behaviorOnError, uint256(Payload.BEHAVIOR_IGNORE_ERROR), uint256(Payload.BEHAVIOR_ABORT_ON_ERROR)
      );
    }

    Payload.Decoded memory input;
    input.kind = Payload.KIND_TRANSACTIONS;
    input.calls = _calls;
    input.space = _space;
    input.nonce = _nonce;

    bytes memory packed = PrimitivesRPC.toPackedPayload(vm, input);
    console.logBytes(packed);

    Payload.Decoded memory output = payloadImp.fromPackedCalls(packed);
    console.logBytes(abi.encode(output));

    // Input should equal output
    assertEq(abi.encode(input), abi.encode(output));
  }

  function test_hashFor_kindDigest(
    bytes32 _digest
  ) external {
    Payload.Decoded memory _payload;
    _payload.kind = Payload.KIND_DIGEST;
    _payload.digest = _digest;
    bytes32 contractHash = Payload.hashFor(_payload, address(this));
    bytes32 payloadHash = PrimitivesRPC.hashForPayload(vm, address(this), uint64(block.chainid), _payload);
    assertEq(contractHash, payloadHash);
  }

  function test_hashFor_kindMessage(
    bytes calldata _message
  ) external {
    Payload.Decoded memory _payload;
    _payload.kind = Payload.KIND_MESSAGE;
    _payload.message = _message;
    bytes32 contractHash = Payload.hashFor(_payload, address(this));
    bytes32 payloadHash = PrimitivesRPC.hashForPayload(vm, address(this), uint64(block.chainid), _payload);
  }

  function test_hashFor_kindConfigUpdate(
    bytes32 _imageHash
  ) external {
    Payload.Decoded memory _payload;
    _payload.kind = Payload.KIND_CONFIG_UPDATE;
    _payload.imageHash = _imageHash;
    bytes32 contractHash = Payload.hashFor(_payload, address(this));
    bytes32 payloadHash = PrimitivesRPC.hashForPayload(vm, address(this), uint64(block.chainid), _payload);
  }

  function test_hashFor_kindTransactions(
    address _to,
    uint256 _value,
    bytes memory _data,
    uint256 _gasLimit,
    bool _delegateCall,
    bool _onlyFallback,
    uint256 _behaviorOnError,
    uint256 _space,
    uint256 _nonce
  ) external {
    Payload.Decoded memory _payload;
    _payload.kind = Payload.KIND_TRANSACTIONS;
    _payload.calls = new Payload.Call[](2);
    _payload.calls[0] = Payload.Call({
      to: _to,
      value: _value,
      data: _data,
      gasLimit: _gasLimit,
      delegateCall: _delegateCall,
      onlyFallback: _onlyFallback,
      behaviorOnError: bound(_behaviorOnError, 0, 0x02)
    });
    _payload.calls[1] = Payload.Call({
      to: address(this),
      value: 0,
      data: hex"001122",
      gasLimit: 1000000,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_IGNORE_ERROR
    });

    _payload.space = _space;
    _payload.nonce = _nonce;

    bytes32 contractHash = Payload.hashFor(_payload, address(this));
    bytes32 payloadHash = PrimitivesRPC.hashForPayload(vm, address(this), uint64(block.chainid), _payload);
  }

  function test_hashFor_kindTransactions(Payload.Call[] memory _calls, uint256 _space, uint256 _nonce) external {
    Payload.Decoded memory _payload;
    _payload.kind = Payload.KIND_TRANSACTIONS;
    _payload.calls = _calls;

    _payload.space = _space;
    _payload.nonce = _nonce;

    boundToLegalPayload(_payload);

    bytes32 contractHash = Payload.hashFor(_payload, address(this));
    bytes32 payloadHash = PrimitivesRPC.hashForPayload(vm, address(this), uint64(block.chainid), _payload);
  }

  function test_hashFor_payload(
    Payload.Decoded memory _payload
  ) external {
    boundToLegalPayload(_payload);

    bytes32 contractHash = Payload.hashFor(_payload, address(this));
    bytes32 payloadHash = PrimitivesRPC.hashForPayload(vm, address(this), uint64(block.chainid), _payload);
  }

  function test_hashFor_empty_calls(uint256 _space, uint256 _nonce) external {
    Payload.Decoded memory _payload;
    _payload.kind = Payload.KIND_TRANSACTIONS;
    _payload.calls = new Payload.Call[](0);
    _payload.space = bound(_space, 0, type(uint160).max);
    _payload.nonce = bound(_nonce, 0, type(uint56).max);

    bytes32 contractHash = Payload.hashFor(_payload, address(this));
    bytes32 payloadHash = PrimitivesRPC.hashForPayload(vm, address(this), uint64(block.chainid), _payload);
    assertEq(contractHash, payloadHash);
  }

}
