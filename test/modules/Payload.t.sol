// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../../src/modules/Payload.sol";
import { PrimitivesRPC } from "../utils/PrimitivesRPC.sol";

import { AdvTest } from "../utils/TestUtils.sol";
import { Test, Vm } from "forge-std/Test.sol";
import { console } from "forge-std/console.sol";

contract PayloadImp {

  function fromMessage(
    bytes calldata message
  ) external pure returns (Payload.Decoded memory) {
    return Payload.fromMessage(message);
  }

  function fromDigest(
    bytes32 digest
  ) external pure returns (Payload.Decoded memory) {
    return Payload.fromDigest(digest);
  }

  function fromConfigUpdate(
    bytes32 imageHash
  ) external pure returns (Payload.Decoded memory) {
    return Payload.fromConfigUpdate(imageHash);
  }

  function fromPackedCalls(
    bytes calldata packed
  ) external view returns (Payload.Decoded memory) {
    return Payload.fromPackedCalls(packed);
  }

  // Expose this otherwise forge won't catch the revert due to depth
  function toEIP712(
    Payload.Decoded memory payload
  ) external pure returns (bytes32) {
    return Payload.toEIP712(payload);
  }

  function hash(
    Payload.Decoded memory payload
  ) external view returns (bytes32) {
    return Payload.hash(payload);
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

  function test_fromPackedCalls_2bytes(
    Payload.Call memory _call
  ) external {
    // Convert behaviors into legal ones
    _call.behaviorOnError =
      bound(_call.behaviorOnError, uint256(Payload.BEHAVIOR_IGNORE_ERROR), uint256(Payload.BEHAVIOR_ABORT_ON_ERROR));

    Payload.Call[] memory _calls = new Payload.Call[](257);
    for (uint256 i = 0; i < 257; i++) {
      // Force > 1 byte of calls
      _calls[i] = _call;
    }

    Payload.Decoded memory input;
    input.kind = Payload.KIND_TRANSACTIONS;
    input.calls = _calls;

    bytes memory packed = PrimitivesRPC.toPackedPayload(vm, input);
    Payload.Decoded memory output = payloadImp.fromPackedCalls(packed);
    assertEq(abi.encode(input), abi.encode(output));
  }

  function test_fromPackedCalls_self(
    Payload.Call memory _call
  ) external {
    // Convert behaviors into legal ones
    _call.behaviorOnError =
      bound(_call.behaviorOnError, uint256(Payload.BEHAVIOR_IGNORE_ERROR), uint256(Payload.BEHAVIOR_ABORT_ON_ERROR));
    _call.to = address(payloadImp);

    Payload.Call[] memory _calls = new Payload.Call[](1);
    _calls[0] = _call;

    Payload.Decoded memory input;
    input.kind = Payload.KIND_TRANSACTIONS;
    input.calls = _calls;

    bytes memory packed = PrimitivesRPC.toPackedPayloadForWallet(vm, input, address(payloadImp));
    Payload.Decoded memory output = payloadImp.fromPackedCalls(packed);
    assertEq(abi.encode(input), abi.encode(output));
  }

  function test_fromMessage(
    bytes calldata _message
  ) external view {
    Payload.Decoded memory _expected;
    _expected.kind = Payload.KIND_MESSAGE;
    _expected.message = _message;

    Payload.Decoded memory _actual = payloadImp.fromMessage(_message);
    assertEq(abi.encode(_expected), abi.encode(_actual));
  }

  function test_fromDigest(
    bytes32 _digest
  ) external view {
    Payload.Decoded memory _expected;
    _expected.kind = Payload.KIND_DIGEST;
    _expected.digest = _digest;

    Payload.Decoded memory _actual = payloadImp.fromDigest(_digest);
    assertEq(abi.encode(_expected), abi.encode(_actual));
  }

  function test_fromConfigUpdate(
    bytes32 _imageHash
  ) external view {
    Payload.Decoded memory _expected;
    _expected.kind = Payload.KIND_CONFIG_UPDATE;
    _expected.imageHash = _imageHash;

    Payload.Decoded memory _actual = payloadImp.fromConfigUpdate(_imageHash);
    assertEq(abi.encode(_expected), abi.encode(_actual));
  }

  // TODO: Re-enable this after the SDK gains support for the digest kind
  // function test_hashFor_kindDigest(
  //   bytes32 _digest
  // ) external {
  //   Payload.Decoded memory _payload;
  //   _payload.kind = Payload.KIND_DIGEST;
  //   _payload.digest = _digest;
  //   bytes32 contractHash = Payload.hashFor(_payload, address(this));
  //   bytes32 payloadHash = PrimitivesRPC.hashForPayload(vm, address(this), uint64(block.chainid), _payload);
  //   assertEq(contractHash, payloadHash);
  // }

  function test_hash_kindMessage(bytes calldata _message, address[] memory _parents) external {
    Payload.Decoded memory _payload;
    _payload.kind = Payload.KIND_MESSAGE;
    _payload.message = _message;
    _payload.parentWallets = _parents;
    bytes32 contractHash = payloadImp.hash(_payload);
    bytes32 payloadHash = PrimitivesRPC.hashForPayload(vm, address(payloadImp), uint64(block.chainid), _payload);
    assertEq(contractHash, payloadHash);
  }

  function test_hashFor_kindMessage(bytes calldata _message, address[] memory _parents, address _wallet) external {
    Payload.Decoded memory _payload;
    _payload.kind = Payload.KIND_MESSAGE;
    _payload.message = _message;
    _payload.parentWallets = _parents;
    bytes32 contractHash = Payload.hashFor(_payload, _wallet);
    bytes32 payloadHash = PrimitivesRPC.hashForPayload(vm, _wallet, uint64(block.chainid), _payload);
    assertEq(contractHash, payloadHash);
  }

  function test_hash_kindMessage_as_digest(bytes calldata _message, address[] memory _parents) external {
    bytes32 digest = keccak256(_message);
    Payload.Decoded memory _payloadDigest;
    _payloadDigest.kind = Payload.KIND_DIGEST;
    _payloadDigest.digest = digest;
    _payloadDigest.parentWallets = _parents;
    Payload.Decoded memory _payloadMessage;
    _payloadMessage.kind = Payload.KIND_MESSAGE;
    _payloadMessage.message = _message;
    _payloadMessage.parentWallets = _parents;
    bytes32 contractHashDigest = payloadImp.hash(_payloadDigest);
    bytes32 payloadHashMessage =
      PrimitivesRPC.hashForPayload(vm, address(payloadImp), uint64(block.chainid), _payloadMessage);
    assertEq(contractHashDigest, payloadHashMessage);
  }

  function test_hashFor_kindMessage_as_digest(
    bytes calldata _message,
    address[] memory _parents,
    address _wallet
  ) external {
    bytes32 digest = keccak256(_message);
    Payload.Decoded memory _payloadDigest;
    _payloadDigest.kind = Payload.KIND_DIGEST;
    _payloadDigest.digest = digest;
    _payloadDigest.parentWallets = _parents;
    Payload.Decoded memory _payloadMessage;
    _payloadMessage.kind = Payload.KIND_MESSAGE;
    _payloadMessage.message = _message;
    _payloadMessage.parentWallets = _parents;
    bytes32 contractHashDigest = Payload.hashFor(_payloadDigest, _wallet);
    bytes32 payloadHashMessage = PrimitivesRPC.hashForPayload(vm, _wallet, uint64(block.chainid), _payloadMessage);
    assertEq(contractHashDigest, payloadHashMessage);
  }

  function test_hash_kindConfigUpdate(bytes32 _imageHash, address[] memory _parents) external {
    Payload.Decoded memory _payload;
    _payload.kind = Payload.KIND_CONFIG_UPDATE;
    _payload.imageHash = _imageHash;
    _payload.parentWallets = _parents;
    bytes32 contractHash = payloadImp.hash(_payload);
    bytes32 payloadHash = PrimitivesRPC.hashForPayload(vm, address(payloadImp), uint64(block.chainid), _payload);
    assertEq(contractHash, payloadHash);
  }

  function test_hashFor_kindConfigUpdate(bytes32 _imageHash, address[] memory _parents, address _wallet) external {
    Payload.Decoded memory _payload;
    _payload.kind = Payload.KIND_CONFIG_UPDATE;
    _payload.imageHash = _imageHash;
    _payload.parentWallets = _parents;
    bytes32 contractHash = Payload.hashFor(_payload, _wallet);
    bytes32 payloadHash = PrimitivesRPC.hashForPayload(vm, _wallet, uint64(block.chainid), _payload);
    assertEq(contractHash, payloadHash);
  }

  function test_hash_kindTransactions(
    address _to,
    uint256 _value,
    bytes memory _data,
    uint256 _gasLimit,
    bool _delegateCall,
    bool _onlyFallback,
    uint256 _behaviorOnError,
    uint256 _space,
    uint256 _nonce,
    address[] memory _parents
  ) external {
    // Convert nonce into legal range
    _nonce = bound(_nonce, 0, type(uint56).max);
    _space = bound(_space, 0, type(uint160).max);

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
    _payload.parentWallets = _parents;

    bytes32 contractHash = payloadImp.hash(_payload);
    bytes32 payloadHash = PrimitivesRPC.hashForPayload(vm, address(payloadImp), uint64(block.chainid), _payload);
    assertEq(contractHash, payloadHash);
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
    uint256 _nonce,
    address[] memory _parents,
    address _wallet
  ) external {
    // Convert nonce into legal range
    _nonce = bound(_nonce, 0, type(uint56).max);
    _space = bound(_space, 0, type(uint160).max);

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
    _payload.parentWallets = _parents;

    bytes32 contractHash = Payload.hashFor(_payload, _wallet);
    bytes32 payloadHash = PrimitivesRPC.hashForPayload(vm, _wallet, uint64(block.chainid), _payload);
    assertEq(contractHash, payloadHash);
  }

  function test_hashFor_kindTransactions(
    Payload.Call[] memory _calls,
    uint256 _space,
    uint256 _nonce,
    address[] memory _parents,
    address _wallet
  ) external {
    // Convert nonce into legal range
    _nonce = bound(_nonce, 0, type(uint56).max);
    _space = bound(_space, 0, type(uint160).max);

    Payload.Decoded memory _payload;
    _payload.kind = Payload.KIND_TRANSACTIONS;
    _payload.calls = _calls;

    _payload.space = _space;
    _payload.nonce = _nonce;
    _payload.parentWallets = _parents;

    boundToLegalPayload(_payload);

    bytes32 contractHash = Payload.hashFor(_payload, _wallet);
    bytes32 payloadHash = PrimitivesRPC.hashForPayload(vm, _wallet, uint64(block.chainid), _payload);
    assertEq(contractHash, payloadHash);
  }

  function test_hashFor_invalidPayload(
    uint8 _kind
  ) external {
    _kind = uint8(bound(_kind, 0x04, 0xff));
    Payload.Decoded memory _payload;
    _payload.kind = _kind;

    vm.expectRevert(abi.encodeWithSelector(Payload.InvalidKind.selector, _kind));
    payloadImp.toEIP712(_payload);
  }

}
