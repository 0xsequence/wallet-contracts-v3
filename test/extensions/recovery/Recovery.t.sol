// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Recovery } from "../../../src/extensions/recovery/Recovery.sol";

import { Payload } from "../../../src/modules/Payload.sol";
import { IERC1271 } from "../../../src/modules/interfaces/IERC1271.sol";
import { PrimitivesRPC } from "../../utils/PrimitivesRPC.sol";
import { AdvTest } from "../../utils/TestUtils.sol";
import { console } from "forge-std/console.sol";

contract RecoveryImp is Recovery {

  function recoverBranch(
    address _wallet,
    bytes32 _payloadHash,
    bytes calldata _signature
  ) external view returns (bool verified, bytes32 root) {
    return _recoverBranch(_wallet, _payloadHash, _signature);
  }

}

contract RecoveryTest is AdvTest {

  RecoveryImp public recovery;

  function setUp() public {
    recovery = new RecoveryImp();
  }

  struct Signer {
    address signer;
    uint24 requiredDeltaTime;
    uint64 minTimestamp;
  }

  function test_recoverBranch(Signer[] calldata signers, address wallet, bytes32 payloadHash) public {
    vm.assume(signers.length > 0);

    string memory leaves;

    for (uint256 i = 0; i < signers.length; i++) {
      if (i > 0) {
        leaves = string.concat(leaves, " ");
      }
      leaves = string.concat(
        leaves,
        "signer:",
        vm.toString(signers[i].signer),
        ":",
        vm.toString(signers[i].requiredDeltaTime),
        ":",
        vm.toString(signers[i].minTimestamp)
      );
    }

    bytes32 rpcRoot = PrimitivesRPC.recoveryHashFromLeaves(vm, leaves);
    vm.assume(rpcRoot != bytes32(0));

    bytes memory encoded = PrimitivesRPC.recoveryEncode(vm, leaves);
    bytes32 rpcRootEncoded = PrimitivesRPC.recoveryHashEncoded(vm, encoded);
    assertEq(rpcRoot, rpcRootEncoded);

    (bool verified, bytes32 root) = recovery.recoverBranch(wallet, payloadHash, encoded);
    assertEq(verified, false);
    assertEq(root, rpcRoot);
  }

  function test_queue_payload(
    uint256 _signerPk,
    address _wallet,
    Payload.Decoded memory _payload,
    uint64 _randomTime
  ) external {
    boundToLegalPayload(_payload);

    vm.warp(_randomTime);

    _signerPk = boundPk(_signerPk);
    bytes32 recoveryPayloadHash = recovery.recoveryPayloadHash(_wallet, _payload);
    bytes32 payloadHash = Payload.hashFor(_payload, _wallet);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(_signerPk, recoveryPayloadHash);

    bytes32 yParityAndS = bytes32((uint256(v - 27) << 255) | uint256(s));
    bytes memory signature = abi.encodePacked(r, yParityAndS);

    address signerAddr = vm.addr(_signerPk);

    vm.expectEmit(true, true, true, true, address(recovery));
    emit Recovery.NewQueuedPayload(_wallet, signerAddr, payloadHash, block.timestamp);
    recovery.queuePayload(_wallet, signerAddr, _payload, signature);

    assertEq(recovery.totalQueuedPayloads(_wallet, signerAddr), 1);
    assertEq(recovery.queuedPayloadHashes(_wallet, signerAddr, 0), payloadHash);
    assertEq(recovery.timestampForQueuedPayload(_wallet, signerAddr, payloadHash), block.timestamp);
  }

  function test_queue_payload_ecdsa_with_code(
    uint256 _signerPk,
    address _wallet,
    Payload.Decoded memory _payload,
    uint64 _randomTime,
    bytes memory _randomCode
  ) external {
    _randomCode = abi.encodePacked(bytes1(0x00), _randomCode);
    boundToLegalPayload(_payload);

    vm.warp(_randomTime);

    _signerPk = boundPk(_signerPk);
    bytes32 recoveryPayloadHash = recovery.recoveryPayloadHash(_wallet, _payload);
    bytes32 payloadHash = Payload.hashFor(_payload, _wallet);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(_signerPk, recoveryPayloadHash);

    bytes32 yParityAndS = bytes32((uint256(v - 27) << 255) | uint256(s));
    bytes memory signature = abi.encodePacked(r, yParityAndS);

    address signerAddr = vm.addr(_signerPk);
    vm.etch(signerAddr, _randomCode);

    vm.expectEmit(true, true, true, true, address(recovery));
    emit Recovery.NewQueuedPayload(_wallet, signerAddr, payloadHash, block.timestamp);
    recovery.queuePayload(_wallet, signerAddr, _payload, signature);

    assertEq(recovery.totalQueuedPayloads(_wallet, signerAddr), 1);
    assertEq(recovery.queuedPayloadHashes(_wallet, signerAddr, 0), payloadHash);
    assertEq(recovery.timestampForQueuedPayload(_wallet, signerAddr, payloadHash), block.timestamp);
  }

  function test_queue_payload_invalid_signature_fail_no_code(
    uint256 _signerPk,
    address _wallet,
    Payload.Decoded memory _payload,
    uint64 _randomTime,
    address _wrongSigner
  ) external {
    assumeNotPrecompile(_wrongSigner);
    vm.assume(_wrongSigner.code.length == 0);

    boundToLegalPayload(_payload);
    _signerPk = boundPk(_signerPk);

    address signerAddr = vm.addr(_signerPk);
    vm.assume(signerAddr != _wrongSigner);
    vm.label(signerAddr, "signer");
    vm.label(_wrongSigner, "wrongSigner");

    vm.warp(_randomTime);

    bytes32 recoveryPayloadHash = recovery.recoveryPayloadHash(_wallet, _payload);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(_signerPk, recoveryPayloadHash);

    bytes32 yParityAndS = bytes32((uint256(v - 27) << 255) | uint256(s));
    bytes memory signature = abi.encodePacked(r, yParityAndS);

    vm.expectRevert(
      abi.encodeWithSelector(Recovery.InvalidSignature.selector, _wallet, _wrongSigner, _payload, signature)
    );
    recovery.queuePayload(_wallet, _wrongSigner, _payload, signature);
  }

  function test_queue_payload_invalid_signature_fail_has_code(
    uint256 _signerPk,
    address _wallet,
    Payload.Decoded memory _payload,
    uint64 _randomTime,
    address _wrongSigner,
    bytes memory _randomCode
  ) external {
    _wrongSigner = boundNoPrecompile(_wrongSigner);
    assumeNotPrecompile2(_wrongSigner);
    // Ensure there is code without 0xef prefix
    _randomCode = abi.encodePacked(bytes1(0x00), _randomCode);

    vm.etch(_wrongSigner, _randomCode);

    boundToLegalPayload(_payload);
    _signerPk = boundPk(_signerPk);

    {
      address signerAddr = vm.addr(_signerPk);
      vm.assume(signerAddr != _wrongSigner);
      vm.label(signerAddr, "signer");
      vm.label(_wrongSigner, "wrongSigner");
    }

    vm.warp(_randomTime);

    bytes memory signature;
    {
      bytes32 recoveryPayloadHash = recovery.recoveryPayloadHash(_wallet, _payload);
      (uint8 v, bytes32 r, bytes32 s) = vm.sign(_signerPk, recoveryPayloadHash);

      bytes32 yParityAndS = bytes32((uint256(v - 27) << 255) | uint256(s));
      signature = abi.encodePacked(r, yParityAndS);

      vm.mockCall(
        _wrongSigner,
        abi.encodeWithSelector(IERC1271.isValidSignature.selector, recoveryPayloadHash, signature),
        abi.encode(bytes4(0x00000000))
      );
    }

    vm.expectRevert(
      abi.encodeWithSelector(Recovery.InvalidSignature.selector, _wallet, _wrongSigner, _payload, signature)
    );
    recovery.queuePayload(_wallet, _wrongSigner, _payload, signature);
  }

  function test_queue_payload_already_queued_fail(
    uint256 _signerPk,
    address _wallet,
    Payload.Decoded memory _payload,
    uint256 _randomTime,
    uint256 _waitBetweenQueues
  ) external {
    boundToLegalPayload(_payload);
    _signerPk = boundPk(_signerPk);

    _randomTime = bound(_randomTime, 1, type(uint64).max);
    _waitBetweenQueues = bound(_waitBetweenQueues, 0, type(uint64).max - _randomTime);

    address signerAddr = vm.addr(_signerPk);
    vm.warp(_randomTime);

    _signerPk = boundPk(_signerPk);
    bytes32 recoveryPayloadHash = recovery.recoveryPayloadHash(_wallet, _payload);
    bytes32 payloadHash = Payload.hashFor(_payload, _wallet);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(_signerPk, recoveryPayloadHash);

    bytes32 yParityAndS = bytes32((uint256(v - 27) << 255) | uint256(s));
    bytes memory signature = abi.encodePacked(r, yParityAndS);

    recovery.queuePayload(_wallet, signerAddr, _payload, signature);
    vm.warp(block.timestamp + _waitBetweenQueues);

    vm.expectRevert(abi.encodeWithSelector(Recovery.AlreadyQueued.selector, _wallet, signerAddr, payloadHash));
    recovery.queuePayload(_wallet, signerAddr, _payload, signature);
  }

  function test_queue_payload_erc1271(
    address _signer,
    bytes calldata _signature,
    address _wallet,
    Payload.Decoded memory _payload,
    uint64 _randomTime,
    bytes memory _signerCode
  ) external {
    boundToLegalPayload(_payload);
    _signer = boundNoPrecompile(_signer);
    assumeNotPrecompile2(_signer);

    _signerCode = abi.encodePacked(bytes1(0x00), _signerCode);
    vm.warp(_randomTime);

    bytes32 payloadHash = Payload.hashFor(_payload, _wallet);
    bytes32 recoveryPayloadHash = recovery.recoveryPayloadHash(_wallet, _payload);

    vm.mockCall(
      _signer,
      abi.encodeWithSelector(IERC1271.isValidSignature.selector, recoveryPayloadHash, _signature),
      abi.encode(bytes4(0x1626ba7e))
    );
    vm.etch(_signer, _signerCode);

    vm.expectEmit(true, true, true, true, address(recovery));
    emit Recovery.NewQueuedPayload(_wallet, _signer, payloadHash, block.timestamp);
    recovery.queuePayload(_wallet, _signer, _payload, _signature);

    assertEq(recovery.totalQueuedPayloads(_wallet, _signer), 1);
    assertEq(recovery.queuedPayloadHashes(_wallet, _signer, 0), payloadHash);
    assertEq(recovery.timestampForQueuedPayload(_wallet, _signer, payloadHash), block.timestamp);
  }

  function test_queue_payload_erc1271_invalid_signature_fail(
    address _signer,
    bytes calldata _signature,
    address _wallet,
    Payload.Decoded memory _payload,
    uint64 _randomTime,
    bytes memory _signerCode,
    bytes4 _badMagicValue
  ) external {
    boundToLegalPayload(_payload);
    _signer = boundNoPrecompile(_signer);
    assumeNotPrecompile2(_signer);

    _signerCode = abi.encodePacked(bytes1(0x00), _signerCode);
    vm.warp(_randomTime);
    if (_badMagicValue == bytes4(0x1626ba7e)) {
      _badMagicValue = bytes4(0);
    }

    bytes32 recoveryPayloadHash = recovery.recoveryPayloadHash(_wallet, _payload);

    vm.mockCall(
      _signer,
      abi.encodeWithSelector(IERC1271.isValidSignature.selector, recoveryPayloadHash, _signature),
      abi.encode(_badMagicValue)
    );
    vm.etch(_signer, _signerCode);

    vm.expectRevert(abi.encodeWithSelector(Recovery.InvalidSignature.selector, _wallet, _signer, _payload, _signature));
    recovery.queuePayload(_wallet, _signer, _payload, _signature);
  }

  function test_queue_payload_erc1271_revert_fail(
    address _signer,
    bytes calldata _signature,
    address _wallet,
    Payload.Decoded memory _payload,
    uint64 _randomTime,
    bytes memory _signerCode,
    bytes calldata _revertData
  ) external {
    boundToLegalPayload(_payload);
    _signer = boundNoPrecompile(_signer);
    assumeNotPrecompile2(_signer);

    _signerCode = abi.encodePacked(bytes1(0x00), _signerCode);
    vm.warp(_randomTime);

    bytes32 recoveryPayloadHash = recovery.recoveryPayloadHash(_wallet, _payload);

    vm.mockCallRevert(
      _signer, abi.encodeWithSelector(IERC1271.isValidSignature.selector, recoveryPayloadHash, _signature), _revertData
    );
    vm.etch(_signer, _signerCode);

    vm.expectRevert(_revertData);
    recovery.queuePayload(_wallet, _signer, _payload, _signature);
  }

  struct other_leaf {
    address signer;
    uint24 requiredDeltaTime;
    uint64 minTimestamp;
  }

  struct test_recover_sapient_signature_compact_params {
    uint256 signerPk;
    address wallet;
    Payload.Decoded payload;
    uint256 startTime;
    uint256 passedTime;
    uint256 minTimestamp;
    uint256 requiredDeltaTime;
    other_leaf[] suffixes;
    other_leaf[] prefixes;
  }

  struct test_recover_sapient_signature_compact_vars {
    bytes32 recoveryPayloadHash;
    bytes32 payloadHash;
    uint8 v;
    bytes32 r;
    bytes32 s;
    bytes32 yParityAndS;
    bytes signature;
    address signerAddr;
    string parts;
    bytes32 rpcRoot;
    bytes encoded;
    bytes32 recoveredRoot;
  }

  function test_recover_sapient_signature_compact(
    test_recover_sapient_signature_compact_params memory params
  ) external {
    boundToLegalPayload(params.payload);
    params.startTime = bound(params.startTime, 1, type(uint64).max / 2); // Safer upper bound perhaps
    params.requiredDeltaTime = bound(params.requiredDeltaTime, 0, type(uint24).max);
    params.minTimestamp = bound(params.minTimestamp, 0, params.startTime);
    uint256 minPassedTime = params.requiredDeltaTime == type(uint64).max ? type(uint64).max : params.requiredDeltaTime;

    params.passedTime = bound(params.passedTime, minPassedTime, type(uint64).max);
    vm.warp(params.startTime);

    params.signerPk = boundPk(params.signerPk);

    test_recover_sapient_signature_compact_vars memory vars;
    vars.recoveryPayloadHash = recovery.recoveryPayloadHash(params.wallet, params.payload);
    vars.payloadHash = Payload.hashFor(params.payload, params.wallet);
    (vars.v, vars.r, vars.s) = vm.sign(params.signerPk, vars.recoveryPayloadHash);

    vars.yParityAndS = bytes32((uint256(vars.v - 27) << 255) | uint256(vars.s));
    vars.signature = abi.encodePacked(vars.r, vars.yParityAndS);

    vars.signerAddr = vm.addr(params.signerPk);

    recovery.queuePayload(params.wallet, vars.signerAddr, params.payload, vars.signature);

    vm.warp(block.timestamp + params.passedTime);

    vars.parts = "";
    for (uint256 i = 0; i < params.suffixes.length; i++) {
      vars.parts = string.concat(
        vars.parts,
        "signer:",
        vm.toString(params.suffixes[i].signer),
        ":",
        vm.toString(params.suffixes[i].requiredDeltaTime),
        ":",
        vm.toString(params.suffixes[i].minTimestamp),
        " "
      );
    }

    vars.parts = string.concat(
      vars.parts,
      "signer:",
      vm.toString(vars.signerAddr),
      ":",
      vm.toString(params.requiredDeltaTime),
      ":",
      vm.toString(params.minTimestamp)
    );

    for (uint256 i = 0; i < params.prefixes.length; i++) {
      vars.parts = string.concat(
        vars.parts,
        " signer:",
        vm.toString(params.prefixes[i].signer),
        ":",
        vm.toString(params.prefixes[i].requiredDeltaTime),
        ":",
        vm.toString(params.prefixes[i].minTimestamp)
      );
    }

    vars.rpcRoot = PrimitivesRPC.recoveryHashFromLeaves(vm, vars.parts);

    vars.encoded = PrimitivesRPC.recoveryTrim(vm, vars.parts, vars.signerAddr);
    vm.prank(params.wallet);
    vars.recoveredRoot = recovery.recoverSapientSignatureCompact(vars.payloadHash, vars.encoded);
    assertEq(vars.recoveredRoot, vars.rpcRoot);
  }

  function test_recover_sapient_signature_compact_fail_minTimestamp(
    test_recover_sapient_signature_compact_params memory params
  ) external {
    boundToLegalPayload(params.payload);
    params.startTime = uint64(bound(params.startTime, 1, type(uint64).max - 1000));
    params.minTimestamp = uint64(bound(params.minTimestamp, params.startTime + 1, type(uint64).max));
    params.requiredDeltaTime = uint24(bound(params.requiredDeltaTime, 0, type(uint24).max));
    params.passedTime = uint64(bound(params.passedTime, 0, type(uint64).max - params.startTime));

    vm.warp(params.startTime);

    params.signerPk = boundPk(params.signerPk);

    test_recover_sapient_signature_compact_vars memory vars;
    vars.recoveryPayloadHash = recovery.recoveryPayloadHash(params.wallet, params.payload);
    vars.payloadHash = Payload.hashFor(params.payload, params.wallet);
    (vars.v, vars.r, vars.s) = vm.sign(params.signerPk, vars.recoveryPayloadHash);

    vars.yParityAndS = bytes32((uint256(vars.v - 27) << 255) | uint256(vars.s));
    vars.signature = abi.encodePacked(vars.r, vars.yParityAndS);

    vars.signerAddr = vm.addr(params.signerPk);

    recovery.queuePayload(params.wallet, vars.signerAddr, params.payload, vars.signature);
    assertEq(recovery.timestampForQueuedPayload(params.wallet, vars.signerAddr, vars.payloadHash), params.startTime);

    vm.warp(params.startTime + params.passedTime);

    vars.parts = "";
    for (uint256 i = 0; i < params.suffixes.length; i++) {
      vars.parts = string.concat(
        vars.parts,
        "signer:",
        vm.toString(params.suffixes[i].signer),
        ":",
        vm.toString(params.suffixes[i].requiredDeltaTime),
        ":",
        vm.toString(params.suffixes[i].minTimestamp),
        " "
      );
    }
    vars.parts = string.concat(
      vars.parts,
      "signer:",
      vm.toString(vars.signerAddr),
      ":",
      vm.toString(params.requiredDeltaTime),
      ":",
      vm.toString(params.minTimestamp)
    );
    for (uint256 i = 0; i < params.prefixes.length; i++) {
      vars.parts = string.concat(
        vars.parts,
        " signer:",
        vm.toString(params.prefixes[i].signer),
        ":",
        vm.toString(params.prefixes[i].requiredDeltaTime),
        ":",
        vm.toString(params.prefixes[i].minTimestamp)
      );
    }
    vars.encoded = PrimitivesRPC.recoveryTrim(vm, vars.parts, vars.signerAddr);

    vm.prank(params.wallet);
    vm.expectRevert(abi.encodeWithSelector(Recovery.QueueNotReady.selector, params.wallet, vars.payloadHash));
    recovery.recoverSapientSignatureCompact(vars.payloadHash, vars.encoded);
  }

  function test_recover_sapient_signature_compact_fail_deltaTime(
    test_recover_sapient_signature_compact_params memory params
  ) external {
    boundToLegalPayload(params.payload);
    params.startTime = uint64(bound(params.startTime, 1, type(uint64).max - type(uint24).max - 1));
    params.minTimestamp = uint64(bound(params.minTimestamp, 0, params.startTime));
    params.requiredDeltaTime = uint24(bound(params.requiredDeltaTime, 1, type(uint24).max));
    params.passedTime = uint64(bound(params.passedTime, 0, params.requiredDeltaTime - 1));

    vm.warp(params.startTime);

    params.signerPk = boundPk(params.signerPk);

    test_recover_sapient_signature_compact_vars memory vars;
    vars.recoveryPayloadHash = recovery.recoveryPayloadHash(params.wallet, params.payload);
    vars.payloadHash = Payload.hashFor(params.payload, params.wallet);
    (vars.v, vars.r, vars.s) = vm.sign(params.signerPk, vars.recoveryPayloadHash);

    vars.yParityAndS = bytes32((uint256(vars.v - 27) << 255) | uint256(vars.s));
    vars.signature = abi.encodePacked(vars.r, vars.yParityAndS);

    vars.signerAddr = vm.addr(params.signerPk);

    recovery.queuePayload(params.wallet, vars.signerAddr, params.payload, vars.signature);
    assertEq(recovery.timestampForQueuedPayload(params.wallet, vars.signerAddr, vars.payloadHash), params.startTime);

    vm.warp(params.startTime + params.passedTime);

    vars.parts = "";
    for (uint256 i = 0; i < params.suffixes.length; i++) {
      vars.parts = string.concat(
        vars.parts,
        "signer:",
        vm.toString(params.suffixes[i].signer),
        ":",
        vm.toString(params.suffixes[i].requiredDeltaTime),
        ":",
        vm.toString(params.suffixes[i].minTimestamp),
        " "
      );
    }
    vars.parts = string.concat(
      vars.parts,
      "signer:",
      vm.toString(vars.signerAddr),
      ":",
      vm.toString(params.requiredDeltaTime),
      ":",
      vm.toString(params.minTimestamp)
    );
    for (uint256 i = 0; i < params.prefixes.length; i++) {
      vars.parts = string.concat(
        vars.parts,
        " signer:",
        vm.toString(params.prefixes[i].signer),
        ":",
        vm.toString(params.prefixes[i].requiredDeltaTime),
        ":",
        vm.toString(params.prefixes[i].minTimestamp)
      );
    }
    vars.encoded = PrimitivesRPC.recoveryTrim(vm, vars.parts, vars.signerAddr);

    vm.prank(params.wallet);
    vm.expectRevert(abi.encodeWithSelector(Recovery.QueueNotReady.selector, params.wallet, vars.payloadHash));
    recovery.recoverSapientSignatureCompact(vars.payloadHash, vars.encoded);
  }

  function test_recover_fail_invalid_signature_flag(
    address _wallet,
    bytes32 _payloadHash,
    uint8 _invalidSignatureFlag,
    bytes calldata _suffix
  ) external {
    if (
      _invalidSignatureFlag == 1 // Recovery.FLAG_RECOVERY_LEAF
        || _invalidSignatureFlag == 3 // Recovery.FLAG_NODE
        || _invalidSignatureFlag == 4 // Recovery.FLAG_BRANCH
    ) {
      _invalidSignatureFlag = uint8(0);
    }

    vm.prank(_wallet);
    vm.expectRevert(abi.encodeWithSelector(Recovery.InvalidSignatureFlag.selector, _invalidSignatureFlag));
    recovery.recoverSapientSignatureCompact(_payloadHash, abi.encodePacked(_invalidSignatureFlag, _suffix));
  }

}
