// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Stage7702Module } from "../src/Stage7702Module.sol";

import { Calls } from "../src/modules/Calls.sol";
import { ERC4337v07 } from "../src/modules/ERC4337v07.sol";
import { Payload } from "../src/modules/Payload.sol";
import { PackedUserOperation } from "../src/modules/interfaces/IAccount.sol";

import { BaseAuth } from "../src/modules/auth/BaseAuth.sol";
import { BaseSig } from "../src/modules/auth/BaseSig.sol";
import { SelfAuth } from "../src/modules/auth/SelfAuth.sol";
import { Stage7702Auth } from "../src/modules/auth/Stage7702Auth.sol";

import { ICheckpointer, Snapshot } from "../src/modules/interfaces/ICheckpointer.sol";
import { IERC1271_MAGIC_VALUE_HASH } from "../src/modules/interfaces/IERC1271.sol";
import { IPartialAuth } from "../src/modules/interfaces/IPartialAuth.sol";

import { EntryPoint, IStakeManager } from "account-abstraction/core/EntryPoint.sol";

import { Emitter } from "./mocks/Emitter.sol";
import { PrimitivesRPC } from "./utils/PrimitivesRPC.sol";
import { AdvTest } from "./utils/TestUtils.sol";
import { Vm } from "forge-std/Test.sol";

contract CheckpointerMock is ICheckpointer {

  function snapshotFor(
    address,
    bytes calldata
  ) external pure returns (Snapshot memory snapshot) {
    return snapshot;
  }

}

contract TestStage7702Module is AdvTest {

  event ImageHashUpdated(bytes32 newImageHash);

  EntryPoint public entryPoint;
  Stage7702Module public stage7702Module;
  CheckpointerMock public checkpointer;

  struct ConfigContext {
    address signer;
    uint256 signerPk;
    string config;
    bytes32 imageHash;
  }

  function setUp() public {
    entryPoint = new EntryPoint();
    checkpointer = new CheckpointerMock();
    stage7702Module = new Stage7702Module(address(entryPoint), address(checkpointer));
  }

  function test_imageHash_matches_initial_7702_config(
    uint256 authorityPk
  ) external {
    authorityPk = boundPk(authorityPk);

    address payable authority = payable(vm.addr(authorityPk));
    ConfigContext memory initial = _initialConfig(authority, authorityPk);

    assertEq(stage7702Module.DEFAULT_CHECKPOINTER(), address(checkpointer));
    assertEq(_imageHash(authority, authorityPk), initial.imageHash);
  }

  function test_getImplementation_reads_current_7702_delegate(
    uint256 authorityPk
  ) external {
    authorityPk = boundPk(authorityPk);

    address authority = vm.addr(authorityPk);
    Stage7702Module alternateModule = new Stage7702Module(address(entryPoint), address(checkpointer));

    assertEq(_getImplementation(authority, authorityPk), address(stage7702Module));
    assertEq(_getImplementation(authority, authorityPk, address(alternateModule)), address(alternateModule));
  }

  function test_getImplementation_returns_zero_without_7702_delegation() external view {
    assertEq(stage7702Module.getImplementation(), address(0));
  }

  function test_execute_updates_image_hash_and_switches_signature_validation(
    uint256 authorityPk,
    uint256 nextSignerPk,
    bytes32 digest
  ) external {
    authorityPk = boundPk(authorityPk);
    nextSignerPk = boundPk(nextSignerPk);
    vm.assume(authorityPk != nextSignerPk);

    address payable authority = payable(vm.addr(authorityPk));
    ConfigContext memory initial = _initialConfig(authority, authorityPk);
    ConfigContext memory next = _singleSignerConfig(vm.addr(nextSignerPk), nextSignerPk, 1);

    Payload.Decoded memory updatePayload = _updateImageHashPayload(authority, next.imageHash, 0);
    bytes memory updateSignature = _signPayload(initial, updatePayload, authority);
    bytes memory packedUpdatePayload = PrimitivesRPC.toPackedPayload(vm, updatePayload);

    vm.recordLogs();
    _attachDelegation(authorityPk);
    Stage7702Module(authority).execute(packedUpdatePayload, updateSignature);

    Vm.Log[] memory logs = vm.getRecordedLogs();
    assertTrue(_hasImageHashUpdated(logs, authority, next.imageHash));

    assertEq(_imageHash(authority, authorityPk), next.imageHash);

    Payload.Decoded memory digestPayload = Payload.fromDigest(digest);
    bytes memory oldSignature = _signPayload(initial, digestPayload, authority);
    bytes memory newSignature = _signPayload(next, digestPayload, authority);

    assertEq(_isValidSignature(authority, authorityPk, digest, oldSignature), bytes4(0));
    assertEq(_isValidSignature(authority, authorityPk, digest, newSignature), IERC1271_MAGIC_VALUE_HASH);
  }

  function test_recover_partial_signature_tracks_counterfactual_and_stored_image(
    uint256 authorityPk,
    uint256 nextSignerPk,
    bytes32 digest
  ) external {
    authorityPk = boundPk(authorityPk);
    nextSignerPk = boundPk(nextSignerPk);
    vm.assume(authorityPk != nextSignerPk);

    address payable authority = payable(vm.addr(authorityPk));
    ConfigContext memory initial = _initialConfig(authority, authorityPk);
    ConfigContext memory next = _singleSignerConfig(vm.addr(nextSignerPk), nextSignerPk, 1);

    Payload.Decoded memory payload = Payload.fromDigest(digest);
    bytes memory initialSignature = _signPayload(initial, payload, authority);

    (
      uint256 initialThreshold,
      uint256 initialWeight,
      bool initialIsValidImage,
      bytes32 initialImageHash,
      uint256 initialCheckpoint,
      bytes32 initialOpHash
    ) = _recoverPartialSignature(authority, authorityPk, payload, initialSignature);

    assertEq(initialThreshold, 1);
    assertEq(initialWeight, 1);
    assertTrue(initialIsValidImage);
    assertEq(initialImageHash, initial.imageHash);
    assertEq(initialCheckpoint, 0);
    assertEq(initialOpHash, Payload.hashFor(payload, authority));

    Payload.Decoded memory updatePayload = _updateImageHashPayload(authority, next.imageHash, 0);
    bytes memory updateSignature = _signPayload(initial, updatePayload, authority);

    _attachDelegation(authorityPk);
    Stage7702Module(authority).execute(PrimitivesRPC.toPackedPayload(vm, updatePayload), updateSignature);

    (
      uint256 oldThreshold,
      uint256 oldWeight,
      bool oldIsValidImage,
      bytes32 oldImageHash,
      uint256 oldCheckpoint,
      bytes32 oldOpHash
    ) = _recoverPartialSignature(authority, authorityPk, payload, initialSignature);

    assertEq(oldThreshold, 1);
    assertEq(oldWeight, 1);
    assertFalse(oldIsValidImage);
    assertEq(oldImageHash, initial.imageHash);
    assertEq(oldCheckpoint, 0);
    assertEq(oldOpHash, Payload.hashFor(payload, authority));

    bytes memory nextSignature = _signPayload(next, payload, authority);

    (
      uint256 nextThreshold,
      uint256 nextWeight,
      bool nextIsValidImage,
      bytes32 nextImageHash,
      uint256 nextCheckpoint,
      bytes32 nextOpHash
    ) = _recoverPartialSignature(authority, authorityPk, payload, nextSignature);

    assertEq(nextThreshold, 1);
    assertEq(nextWeight, 1);
    assertTrue(nextIsValidImage);
    assertEq(nextImageHash, next.imageHash);
    assertEq(nextCheckpoint, 1);
    assertEq(nextOpHash, Payload.hashFor(payload, authority));
  }

  function test_reverts_update_to_zero_image_hash(
    uint256 authorityPk
  ) external {
    authorityPk = boundPk(authorityPk);

    address payable authority = payable(vm.addr(authorityPk));
    ConfigContext memory initial = _initialConfig(authority, authorityPk);

    Payload.Decoded memory updatePayload = _updateImageHashPayload(authority, bytes32(0), 0);
    bytes memory updateSignature = _signPayload(initial, updatePayload, authority);
    bytes memory innerRevert = abi.encodeWithSelector(Stage7702Auth.ImageHashIsZero.selector);

    vm.expectRevert(abi.encodeWithSelector(Calls.Reverted.selector, updatePayload, 0, innerRevert));
    _attachDelegation(authorityPk);
    Stage7702Module(authority).execute(PrimitivesRPC.toPackedPayload(vm, updatePayload), updateSignature);

    assertEq(_imageHash(authority, authorityPk), initial.imageHash);
  }

  function test_reverts_update_image_hash_when_not_self(
    uint256 authorityPk,
    bytes32 newImageHash
  ) external {
    authorityPk = boundPk(authorityPk);
    vm.assume(newImageHash != bytes32(0));

    address payable authority = payable(vm.addr(authorityPk));

    vm.expectRevert(abi.encodeWithSelector(SelfAuth.OnlySelf.selector, address(this)));
    _attachDelegation(authorityPk);
    Stage7702Module(authority).updateImageHash(newImageHash);
  }

  function test_static_signature_any_address() external {
    uint256 authorityPk = boundPk(123);
    bytes32 digest = keccak256("static-any-address");

    address payable authority = payable(vm.addr(authorityPk));
    ConfigContext memory initial = _initialConfig(authority, authorityPk);

    Payload.Decoded memory payload = Payload.fromDigest(digest);
    bytes32 opHash = Payload.hashFor(payload, authority);
    uint96 validUntil = uint96(block.timestamp + 1 days);

    _executePayload(
      initial, authority, authorityPk, _setStaticSignaturePayload(authority, opHash, address(0), validUntil, 0)
    );

    (address allowedCaller, uint256 timestamp) = _getStaticSignature(authority, authorityPk, opHash);
    assertEq(allowedCaller, address(0));
    assertEq(timestamp, validUntil);

    assertEq(_isValidSignature(authority, authorityPk, digest, hex"80"), IERC1271_MAGIC_VALUE_HASH);
    assertEq(_isValidSignatureFrom(address(0xbeef), authority, authorityPk, digest, hex"80"), IERC1271_MAGIC_VALUE_HASH);
  }

  function test_static_signature_specific_address_and_expiry() external {
    uint256 authorityPk = boundPk(123);
    bytes32 digest = keccak256("static-specific-address");
    address allowedCaller = address(0xcafe);
    address otherCaller = address(0xbeef);

    address payable authority = payable(vm.addr(authorityPk));
    ConfigContext memory initial = _initialConfig(authority, authorityPk);

    Payload.Decoded memory payload = Payload.fromDigest(digest);
    bytes32 opHash = Payload.hashFor(payload, authority);
    uint96 validUntil = uint96(block.timestamp + 1 days);

    _executePayload(
      initial, authority, authorityPk, _setStaticSignaturePayload(authority, opHash, allowedCaller, validUntil, 0)
    );

    assertEq(_isValidSignatureFrom(allowedCaller, authority, authorityPk, digest, hex"80"), IERC1271_MAGIC_VALUE_HASH);

    vm.startPrank(otherCaller);
    vm.expectRevert(
      abi.encodeWithSelector(BaseAuth.InvalidStaticSignatureWrongCaller.selector, opHash, otherCaller, allowedCaller)
    );
    _attachDelegation(authorityPk);
    Stage7702Module(authority).isValidSignature(digest, hex"80");
    vm.stopPrank();

    vm.warp(validUntil);
    vm.expectRevert(abi.encodeWithSelector(BaseAuth.InvalidStaticSignatureExpired.selector, opHash, validUntil));
    _attachDelegation(authorityPk);
    Stage7702Module(authority).isValidSignature(digest, hex"80");
  }

  function test_static_signature_boundaries(
    uint256 authorityPk,
    bytes32 digest,
    address allowedCaller,
    address otherCaller,
    bool allowAnyCaller,
    bool useAllowedCaller,
    bool noChainId,
    uint8 expiryMode
  ) external {
    authorityPk = boundPk(authorityPk);
    expiryMode = uint8(bound(expiryMode, 0, 2));
    allowedCaller = boundNoPrecompile(allowedCaller);
    otherCaller = boundNoPrecompile(otherCaller);

    if (allowedCaller == address(0)) {
      allowedCaller = address(0xcafe);
    }

    if (otherCaller == address(0)) {
      otherCaller = address(0xbeef);
    }

    vm.assume(allowedCaller != otherCaller);

    address payable authority = payable(vm.addr(authorityPk));
    ConfigContext memory initial = _initialConfig(authority, authorityPk);

    Payload.Decoded memory payload = _digestPayload(digest, noChainId);
    bytes32 opHash = Payload.hashFor(payload, authority);

    vm.warp(1_000_000);

    uint96 validUntil;
    if (expiryMode == 0) {
      validUntil = uint96(block.timestamp - 1);
    } else if (expiryMode == 1) {
      validUntil = uint96(block.timestamp);
    } else {
      validUntil = uint96(block.timestamp + 1);
    }

    address configuredCaller = allowAnyCaller ? address(0) : allowedCaller;
    address caller = useAllowedCaller ? allowedCaller : otherCaller;
    bytes memory staticSignature;
    if (noChainId) {
      staticSignature = hex"82";
    } else {
      staticSignature = hex"80";
    }

    _executePayload(
      initial, authority, authorityPk, _setStaticSignaturePayload(authority, opHash, configuredCaller, validUntil, 0)
    );

    if (validUntil <= block.timestamp) {
      vm.expectRevert(abi.encodeWithSelector(BaseAuth.InvalidStaticSignatureExpired.selector, opHash, validUntil));
      _isValidSignatureFrom(caller, authority, authorityPk, digest, staticSignature);
      return;
    }

    if (!allowAnyCaller && caller != allowedCaller) {
      vm.expectRevert(
        abi.encodeWithSelector(BaseAuth.InvalidStaticSignatureWrongCaller.selector, opHash, caller, allowedCaller)
      );
      _isValidSignatureFrom(caller, authority, authorityPk, digest, staticSignature);
      return;
    }

    assertEq(_isValidSignatureFrom(caller, authority, authorityPk, digest, staticSignature), IERC1271_MAGIC_VALUE_HASH);
  }

  function test_no_chain_id_static_signature() external {
    uint256 authorityPk = boundPk(123);

    address payable authority = payable(vm.addr(authorityPk));
    ConfigContext memory initial = _initialConfig(authority, authorityPk);

    Payload.Decoded memory payload = _singleCallPayload(
      Payload.Call({
        to: address(0),
        value: 0,
        data: bytes(""),
        gasLimit: 100000,
        delegateCall: false,
        onlyFallback: false,
        behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
      }),
      1,
      true
    );

    _executePayload(
      initial,
      authority,
      authorityPk,
      _setStaticSignaturePayload(authority, Payload.hashFor(payload, authority), address(0), type(uint96).max, 0)
    );

    bytes memory packedPayload = PrimitivesRPC.toPackedPayload(vm, payload);
    payload.noChainId = false;
    bytes32 payloadHashWithoutChainId = Payload.hashFor(payload, authority);

    vm.expectRevert(
      abi.encodeWithSelector(BaseAuth.InvalidStaticSignatureExpired.selector, payloadHashWithoutChainId, 0)
    );
    _attachDelegation(authorityPk);
    Stage7702Module(authority).execute(packedPayload, hex"80");

    _attachDelegation(authorityPk);
    Stage7702Module(authority).execute(packedPayload, hex"82");
  }

  function test_is_valid_signature_no_chain_id() external {
    uint256 authorityPk = boundPk(123);
    bytes32 digest = keccak256("no-chain-id");

    address payable authority = payable(vm.addr(authorityPk));
    ConfigContext memory initial = _initialConfig(authority, authorityPk);

    Payload.Decoded memory payload = _digestPayload(digest, true);
    bytes memory signature = _signPayload(initial, payload, authority);

    assertEq(_isValidSignature(authority, authorityPk, digest, signature), IERC1271_MAGIC_VALUE_HASH);
  }

  function test_is_valid_signature_eth_sign() external {
    uint256 authorityPk = boundPk(123);
    bytes32 digest = keccak256("eth-sign");

    address payable authority = payable(vm.addr(authorityPk));
    ConfigContext memory initial = _initialConfig(authority, authorityPk);

    Payload.Decoded memory payload = Payload.fromDigest(digest);
    bytes memory signature = _signPayload(initial, payload, authority, true);

    assertEq(_isValidSignature(authority, authorityPk, digest, signature), IERC1271_MAGIC_VALUE_HASH);
  }

  function test_is_valid_signature_erc1271_after_update() external {
    uint256 authorityPk = boundPk(123);
    bytes32 digest = keccak256("erc1271");
    address signer = address(0x1234);
    bytes memory signerSignature = hex"123456";

    address payable authority = payable(vm.addr(authorityPk));
    ConfigContext memory initial = _initialConfig(authority, authorityPk);
    ConfigContext memory next = _singleSignerConfig(signer, 0, 1);

    _updateImageHash(initial, authority, authorityPk, next.imageHash, 0);

    Payload.Decoded memory payload = Payload.fromDigest(digest);
    bytes32 payloadHash = Payload.hashFor(payload, authority);

    vm.mockCall(
      signer,
      abi.encodeWithSignature("isValidSignature(bytes32,bytes)", payloadHash, signerSignature),
      abi.encode(IERC1271_MAGIC_VALUE_HASH)
    );

    bytes memory signature = _encodeERC1271Signature(next.config, signer, signerSignature, true);
    assertEq(_isValidSignature(authority, authorityPk, digest, signature), IERC1271_MAGIC_VALUE_HASH);
  }

  function test_is_valid_signature_sapient_after_update() external {
    uint256 authorityPk = boundPk(123);
    bytes32 digest = keccak256("sapient");
    address signer = address(0x5678);
    bytes memory signerSignature = hex"abcdef";
    bytes32 sapientImageHash = keccak256("sapient-image-hash");

    address payable authority = payable(vm.addr(authorityPk));
    ConfigContext memory initial = _initialConfig(authority, authorityPk);
    ConfigContext memory next = _sapientConfig(signer, sapientImageHash, 1);

    _updateImageHash(initial, authority, authorityPk, next.imageHash, 0);

    Payload.Decoded memory payload = Payload.fromDigest(digest);

    vm.mockCall(
      signer,
      abi.encodeWithSignature(
        "recoverSapientSignature((uint8,bool,(address,uint256,bytes,uint256,bool,bool,uint256)[],uint256,uint256,bytes,bytes32,bytes32,address[]),bytes)",
        payload,
        signerSignature
      ),
      abi.encode(sapientImageHash)
    );

    bytes memory signature = _encodeSapientSignature(next.config, signer, signerSignature, true, false);
    assertEq(_isValidSignature(authority, authorityPk, digest, signature), IERC1271_MAGIC_VALUE_HASH);
  }

  function test_is_valid_signature_chained_after_update() external {
    uint256 authorityPk = boundPk(123);
    uint256 signer1Pk = boundPk(1);
    uint256 signer2Pk = boundPk(2);
    uint256 signer3Pk = boundPk(3);
    bytes32 digest = keccak256("chained");

    address payable authority = payable(vm.addr(authorityPk));
    ConfigContext memory initial = _initialConfig(authority, authorityPk);
    address signer1 = vm.addr(signer1Pk);
    address signer2 = vm.addr(signer2Pk);
    address signer3 = vm.addr(signer3Pk);

    string memory config1 = _newConfig(1, 1, string(abi.encodePacked("signer:", vm.toString(signer1), ":1")));
    string memory config2 = _newConfig(
      1, 2, string(abi.encodePacked("signer:", vm.toString(signer2), ":3 ", "signer:", vm.toString(signer1), ":2"))
    );
    string memory config3 = _newConfig(
      1, 3, string(abi.encodePacked("signer:", vm.toString(signer3), ":2 ", "signer:", vm.toString(signer2), ":2"))
    );

    bytes32 config1Hash = PrimitivesRPC.getImageHash(vm, config1);
    bytes32 config2Hash = PrimitivesRPC.getImageHash(vm, config2);
    bytes32 config3Hash = PrimitivesRPC.getImageHash(vm, config3);

    _updateImageHash(initial, authority, authorityPk, config1Hash, 0);

    Payload.Decoded memory finalPayload = Payload.fromDigest(digest);
    Payload.Decoded memory payloadApprove2 = Payload.fromConfigUpdate(config2Hash);
    Payload.Decoded memory payloadApprove3 = Payload.fromConfigUpdate(config3Hash);

    bytes memory signatureForFinalPayload =
      _encodeHashSignature(config3, signer3, signer3Pk, Payload.hashFor(finalPayload, authority), true);
    bytes memory signature1to2 =
      _encodeHashSignature(config1, signer1, signer1Pk, Payload.hashFor(payloadApprove2, authority), true);
    bytes memory signature2to3 =
      _encodeHashSignature(config2, signer2, signer2Pk, Payload.hashFor(payloadApprove3, authority), true);

    bytes[] memory signatures = new bytes[](3);
    signatures[0] = signatureForFinalPayload;
    signatures[1] = signature2to3;
    signatures[2] = signature1to2;

    bytes memory chainedSignature = PrimitivesRPC.concatSignatures(vm, signatures);

    assertEq(_isValidSignature(authority, authorityPk, digest, chainedSignature), IERC1271_MAGIC_VALUE_HASH);
  }

  function test_execute_updates_image_hash_to_multisig_and_enforces_threshold(
    uint256 authorityPk,
    uint256 signer1Pk,
    uint256 signer2Pk,
    uint256 signer3Pk,
    uint8 signer1Weight,
    uint8 signer2Weight,
    uint8 signer3Weight,
    uint16 threshold,
    uint56 checkpoint,
    bytes32 digest
  ) external {
    authorityPk = boundPk(authorityPk);
    signer1Pk = boundPk(signer1Pk);
    signer2Pk = boundPk(signer2Pk);
    signer3Pk = boundPk(signer3Pk);

    vm.assume(authorityPk != signer1Pk);
    vm.assume(authorityPk != signer2Pk);
    vm.assume(authorityPk != signer3Pk);
    vm.assume(signer1Pk != signer2Pk);
    vm.assume(signer1Pk != signer3Pk);
    vm.assume(signer2Pk != signer3Pk);

    signer1Weight = uint8(bound(signer1Weight, 1, type(uint8).max));
    signer2Weight = uint8(bound(signer2Weight, 1, type(uint8).max));
    signer3Weight = uint8(bound(signer3Weight, 1, type(uint8).max));
    threshold = uint16(bound(threshold, 1, uint16(uint256(signer1Weight) + uint256(signer2Weight))));
    checkpoint = uint56(bound(checkpoint, 1, type(uint56).max));

    address payable authority = payable(vm.addr(authorityPk));
    ConfigContext memory initial = _initialConfig(authority, authorityPk);

    address[] memory signers = new address[](3);
    signers[0] = vm.addr(signer1Pk);
    signers[1] = vm.addr(signer2Pk);
    signers[2] = vm.addr(signer3Pk);

    uint8[] memory weights = new uint8[](3);
    weights[0] = signer1Weight;
    weights[1] = signer2Weight;
    weights[2] = signer3Weight;

    string memory nextConfig = _flatSignerConfig(signers, weights, threshold, checkpoint);
    bytes32 nextImageHash = PrimitivesRPC.getImageHash(vm, nextConfig);

    _updateImageHash(initial, authority, authorityPk, nextImageHash, 0);

    Payload.Decoded memory payload = Payload.fromDigest(digest);
    bytes32 payloadHash = Payload.hashFor(payload, authority);

    address[] memory signingSigners = new address[](2);
    signingSigners[0] = signers[0];
    signingSigners[1] = signers[1];

    uint256[] memory signingSignerPks = new uint256[](2);
    signingSignerPks[0] = signer1Pk;
    signingSignerPks[1] = signer2Pk;

    bytes memory multisigSignature =
      _encodeHashSignatureMulti(nextConfig, signingSigners, signingSignerPks, payloadHash, true, false);
    bytes memory signer1OnlySignature = _encodeHashSignature(nextConfig, signers[0], signer1Pk, payloadHash, true);

    (
      uint256 recoveredThreshold,
      uint256 recoveredWeight,
      bool recoveredIsValidImage,
      bytes32 recoveredImageHash,
      uint256 recoveredCheckpoint,
      bytes32 recoveredOpHash
    ) = _recoverPartialSignature(authority, authorityPk, payload, multisigSignature);

    assertEq(recoveredThreshold, threshold);
    assertEq(recoveredWeight, uint256(signer1Weight) + uint256(signer2Weight));
    assertTrue(recoveredIsValidImage);
    assertEq(recoveredImageHash, nextImageHash);
    assertEq(recoveredCheckpoint, checkpoint);
    assertEq(recoveredOpHash, payloadHash);

    assertEq(_isValidSignature(authority, authorityPk, digest, multisigSignature), IERC1271_MAGIC_VALUE_HASH);

    if (signer1Weight < threshold) {
      vm.expectRevert(abi.encodeWithSelector(BaseAuth.InvalidSignatureWeight.selector, threshold, signer1Weight));
      _isValidSignature(authority, authorityPk, digest, signer1OnlySignature);
    }
  }

  function test_recover_sapient_as_if_nested() external {
    uint256 authorityPk = boundPk(123);
    bytes32 digest = keccak256("nested-sapient");
    address parentWallet = address(0x4444);

    address payable authority = payable(vm.addr(authorityPk));
    ConfigContext memory initial = _initialConfig(authority, authorityPk);

    Payload.Decoded memory payload = Payload.fromDigest(digest);
    address[] memory nextParentWallets = new address[](payload.parentWallets.length + 1);
    nextParentWallets[payload.parentWallets.length] = parentWallet;

    Payload.Decoded memory parentedPayload = payload;
    parentedPayload.parentWallets = nextParentWallets;

    bytes memory parentedSignature = _signPayload(initial, parentedPayload, authority);
    payload.parentWallets = new address[](0);

    assertEq(
      _recoverSapientSignatureFrom(parentWallet, authority, authorityPk, payload, parentedSignature),
      bytes32(uint256(1))
    );
  }

  function test_recover_sapient_as_if_nested_fuzz(
    bytes32 digest,
    address[] memory parentWallets,
    uint256 authorityPk,
    address parentWallet
  ) external {
    vm.assume(parentWallets.length < 4);
    authorityPk = boundPk(authorityPk);
    parentWallet = boundNoPrecompile(parentWallet);

    address payable authority = payable(vm.addr(authorityPk));
    ConfigContext memory initial = _initialConfig(authority, authorityPk);

    Payload.Decoded memory payload = Payload.fromDigest(digest);
    payload.parentWallets = parentWallets;

    address[] memory nextParentWallets = new address[](parentWallets.length + 1);
    for (uint256 i = 0; i < parentWallets.length; i++) {
      nextParentWallets[i] = parentWallets[i];
    }
    nextParentWallets[parentWallets.length] = parentWallet;

    address[] memory prevParentWallets = payload.parentWallets;
    payload.parentWallets = nextParentWallets;
    bytes memory parentedSignature = _signPayload(initial, payload, authority);
    payload.parentWallets = prevParentWallets;

    assertEq(
      _recoverSapientSignatureFrom(parentWallet, authority, authorityPk, payload, parentedSignature),
      bytes32(uint256(1))
    );
  }

  function test_recover_sapient_as_if_nested_wrong_signature_fail(
    bytes32 digest,
    address[] memory parentWallets,
    uint256 authorityPk,
    address parentWallet,
    uint56 differentCheckpoint
  ) external {
    vm.assume(parentWallets.length < 4);
    authorityPk = boundPk(authorityPk);
    parentWallet = boundNoPrecompile(parentWallet);
    differentCheckpoint = uint56(bound(differentCheckpoint, 1, type(uint56).max));

    address payable authority = payable(vm.addr(authorityPk));
    ConfigContext memory different = _singleSignerConfigWithoutCheckpointer(authority, authorityPk, differentCheckpoint);

    Payload.Decoded memory payload = Payload.fromDigest(digest);
    payload.parentWallets = parentWallets;

    address[] memory nextParentWallets = new address[](parentWallets.length + 1);
    for (uint256 i = 0; i < parentWallets.length; i++) {
      nextParentWallets[i] = parentWallets[i];
    }
    nextParentWallets[parentWallets.length] = parentWallet;

    payload.parentWallets = nextParentWallets;
    bytes memory parentedSignature = _signPayload(different, payload, authority);

    Payload.Decoded memory unparentedPayload = Payload.fromDigest(digest);
    unparentedPayload.parentWallets = parentWallets;

    vm.expectRevert();
    _recoverSapientSignatureFrom(parentWallet, authority, authorityPk, unparentedPayload, parentedSignature);
  }

  function test_update_image_hash_twice() external {
    uint256 authorityPk = boundPk(123);
    uint256 signer2Pk = boundPk(456);
    uint256 signer3Pk = boundPk(789);
    bytes32 digest = keccak256("update-twice");

    address payable authority = payable(vm.addr(authorityPk));
    ConfigContext memory initial = _initialConfig(authority, authorityPk);
    ConfigContext memory config2 = _singleSignerConfig(vm.addr(signer2Pk), signer2Pk, 1);
    ConfigContext memory config3 = _singleSignerConfig(vm.addr(signer3Pk), signer3Pk, 2);

    _updateImageHash(initial, authority, authorityPk, config2.imageHash, 0);
    assertEq(_imageHash(authority, authorityPk), config2.imageHash);

    _updateImageHash(config2, authority, authorityPk, config3.imageHash, 1);
    assertEq(_imageHash(authority, authorityPk), config3.imageHash);

    Payload.Decoded memory payload = Payload.fromDigest(digest);
    bytes memory signature = _signPayload(config3, payload, authority);
    assertEq(_isValidSignature(authority, authorityPk, digest, signature), IERC1271_MAGIC_VALUE_HASH);
  }

  function test_update_image_hash_twice_fuzz(
    uint256 authorityPk,
    uint256 signer2Pk,
    uint256 signer3Pk,
    uint56 checkpoint2,
    uint56 checkpoint3,
    bytes32 digest
  ) external {
    authorityPk = boundPk(authorityPk);
    signer2Pk = boundPk(signer2Pk);
    signer3Pk = boundPk(signer3Pk);
    vm.assume(authorityPk != signer2Pk);
    vm.assume(authorityPk != signer3Pk);
    vm.assume(signer2Pk != signer3Pk);

    checkpoint2 = uint56(bound(checkpoint2, 1, type(uint56).max - 1));
    checkpoint3 = uint56(bound(checkpoint3, checkpoint2 + 1, type(uint56).max));

    address payable authority = payable(vm.addr(authorityPk));
    ConfigContext memory initial = _initialConfig(authority, authorityPk);
    ConfigContext memory config2 = _singleSignerConfig(vm.addr(signer2Pk), signer2Pk, checkpoint2);
    ConfigContext memory config3 = _singleSignerConfig(vm.addr(signer3Pk), signer3Pk, checkpoint3);

    _updateImageHash(initial, authority, authorityPk, config2.imageHash, 0);
    _updateImageHash(config2, authority, authorityPk, config3.imageHash, 1);

    Payload.Decoded memory payload = Payload.fromDigest(digest);
    bytes memory config2Signature = _signPayload(config2, payload, authority);
    bytes memory config3Signature = _signPayload(config3, payload, authority);

    (uint256 threshold, uint256 weight, bool isValidImage, bytes32 imageHash, uint256 checkpoint, bytes32 opHash) =
      _recoverPartialSignature(authority, authorityPk, payload, config3Signature);

    assertEq(threshold, 1);
    assertEq(weight, 1);
    assertTrue(isValidImage);
    assertEq(imageHash, config3.imageHash);
    assertEq(checkpoint, checkpoint3);
    assertEq(opHash, Payload.hashFor(payload, authority));

    assertEq(_isValidSignature(authority, authorityPk, digest, config2Signature), bytes4(0));
    assertEq(_isValidSignature(authority, authorityPk, digest, config3Signature), IERC1271_MAGIC_VALUE_HASH);
  }

  function test_is_valid_signature_with_checkpointer_current_snapshot(
    bytes32 digest,
    uint256 authorityPk,
    uint256 signerPk,
    uint56 checkpoint,
    bytes calldata checkpointerData
  ) external {
    authorityPk = boundPk(authorityPk);
    signerPk = boundPk(signerPk);
    checkpoint = uint56(bound(checkpoint, 1, type(uint56).max));
    vm.assume(authorityPk != signerPk);
    vm.assume(checkpointerData.length < 256);

    address payable authority = payable(vm.addr(authorityPk));
    ConfigContext memory initial = _initialConfig(authority, authorityPk);
    ConfigContext memory next = _singleSignerConfig(vm.addr(signerPk), signerPk, checkpoint);

    _updateImageHash(initial, authority, authorityPk, next.imageHash, 0);

    Payload.Decoded memory payload = Payload.fromDigest(digest);
    bytes memory signature = _encodeHashSignatureWithCheckpointerData(
      next.config, next.signer, next.signerPk, Payload.hashFor(payload, authority), true, checkpointerData, false
    );

    Snapshot memory snapshot;
    snapshot.imageHash = next.imageHash;
    snapshot.checkpoint = checkpoint;

    vm.expectCall(
      address(checkpointer), abi.encodeWithSelector(ICheckpointer.snapshotFor.selector, authority, checkpointerData)
    );
    vm.mockCall(
      address(checkpointer),
      abi.encodeWithSelector(ICheckpointer.snapshotFor.selector, authority, checkpointerData),
      abi.encode(snapshot)
    );

    assertEq(_isValidSignature(authority, authorityPk, digest, signature), IERC1271_MAGIC_VALUE_HASH);
  }

  function test_is_valid_signature_with_disabled_checkpointer_snapshot(
    bytes32 digest,
    uint256 authorityPk,
    uint256 signerPk,
    uint56 checkpoint,
    uint56 snapshotCheckpoint,
    bytes calldata checkpointerData
  ) external {
    authorityPk = boundPk(authorityPk);
    signerPk = boundPk(signerPk);
    checkpoint = uint56(bound(checkpoint, 1, type(uint56).max));
    snapshotCheckpoint = uint56(bound(snapshotCheckpoint, checkpoint, type(uint56).max));
    vm.assume(authorityPk != signerPk);
    vm.assume(checkpointerData.length < 256);

    address payable authority = payable(vm.addr(authorityPk));
    ConfigContext memory initial = _initialConfig(authority, authorityPk);
    ConfigContext memory next = _singleSignerConfig(vm.addr(signerPk), signerPk, checkpoint);

    _updateImageHash(initial, authority, authorityPk, next.imageHash, 0);

    Payload.Decoded memory payload = Payload.fromDigest(digest);
    bytes memory signature = _encodeHashSignatureWithCheckpointerData(
      next.config, next.signer, next.signerPk, Payload.hashFor(payload, authority), true, checkpointerData, false
    );

    Snapshot memory snapshot;
    snapshot.imageHash = bytes32(0);
    snapshot.checkpoint = snapshotCheckpoint;

    vm.mockCall(
      address(checkpointer),
      abi.encodeWithSelector(ICheckpointer.snapshotFor.selector, authority, checkpointerData),
      abi.encode(snapshot)
    );

    assertEq(_isValidSignature(authority, authorityPk, digest, signature), IERC1271_MAGIC_VALUE_HASH);
  }

  function test_is_valid_signature_reverts_unused_checkpointer_snapshot(
    bytes32 digest,
    uint256 authorityPk,
    uint256 signerPk,
    uint56 checkpoint,
    uint56 snapshotCheckpoint,
    bytes32 snapshotImageHash,
    bytes calldata checkpointerData
  ) external {
    authorityPk = boundPk(authorityPk);
    signerPk = boundPk(signerPk);
    checkpoint = uint56(bound(checkpoint, 1, type(uint56).max - 1));
    snapshotCheckpoint = uint56(bound(snapshotCheckpoint, checkpoint, type(uint56).max));
    vm.assume(authorityPk != signerPk);
    vm.assume(checkpointerData.length < 256);

    address payable authority = payable(vm.addr(authorityPk));
    ConfigContext memory initial = _initialConfig(authority, authorityPk);
    ConfigContext memory next = _singleSignerConfig(vm.addr(signerPk), signerPk, checkpoint);
    vm.assume(snapshotImageHash != bytes32(0));
    vm.assume(snapshotImageHash != next.imageHash);

    _updateImageHash(initial, authority, authorityPk, next.imageHash, 0);

    Payload.Decoded memory payload = Payload.fromDigest(digest);
    bytes memory signature = _encodeHashSignatureWithCheckpointerData(
      next.config, next.signer, next.signerPk, Payload.hashFor(payload, authority), true, checkpointerData, false
    );

    Snapshot memory snapshot;
    snapshot.imageHash = snapshotImageHash;
    snapshot.checkpoint = snapshotCheckpoint;

    vm.mockCall(
      address(checkpointer),
      abi.encodeWithSelector(ICheckpointer.snapshotFor.selector, authority, checkpointerData),
      abi.encode(snapshot)
    );

    vm.expectRevert(abi.encodeWithSelector(BaseSig.UnusedSnapshot.selector, snapshot));
    _isValidSignature(authority, authorityPk, digest, signature);
  }

  function test_validate_user_op_returns_zero_on_valid_signature() external {
    uint256 authorityPk = boundPk(123);
    bytes32 userOpHash = keccak256("user-op-valid");

    address payable authority = payable(vm.addr(authorityPk));
    ConfigContext memory initial = _initialConfig(authority, authorityPk);
    bytes memory signature = _signPayload(initial, Payload.fromDigest(userOpHash), authority);
    PackedUserOperation memory userOp = _createUserOp(authority, bytes(""), signature);

    vm.startPrank(address(entryPoint));
    _attachDelegation(authorityPk);
    uint256 validationData = Stage7702Module(authority).validateUserOp(userOp, userOpHash, 0);
    vm.stopPrank();

    assertEq(validationData, 0);
  }

  function test_validate_user_op_returns_one_on_invalid_signature(
    bytes32 userOpHash,
    uint256 authorityPk
  ) external {
    authorityPk = boundPk(authorityPk);

    address payable authority = payable(vm.addr(authorityPk));
    PackedUserOperation memory userOp =
      _createUserOp(authority, bytes(""), hex"000010000000000000000000000000000000000000000000");

    vm.startPrank(address(entryPoint));
    _attachDelegation(authorityPk);
    uint256 validationData = Stage7702Module(authority).validateUserOp(userOp, userOpHash, 0);
    vm.stopPrank();

    assertEq(validationData, 1);
  }

  function test_validate_user_op_using_static_signature() external {
    uint256 authorityPk = boundPk(123);
    bytes32 userOpHash = keccak256("user-op-static");

    address payable authority = payable(vm.addr(authorityPk));
    ConfigContext memory initial = _initialConfig(authority, authorityPk);

    _executePayload(
      initial,
      authority,
      authorityPk,
      _setStaticSignaturePayload(
        authority,
        Payload.hashFor(Payload.fromDigest(userOpHash), authority),
        address(entryPoint),
        uint96(block.timestamp + 1 days),
        0
      )
    );

    PackedUserOperation memory userOp = _createUserOp(authority, bytes(""), hex"80");

    vm.startPrank(address(entryPoint));
    _attachDelegation(authorityPk);
    uint256 validationData = Stage7702Module(authority).validateUserOp(userOp, userOpHash, 0);
    vm.stopPrank();

    assertEq(validationData, 0);
  }

  function test_validate_user_op_reverts_invalid_entrypoint() external {
    uint256 authorityPk = boundPk(123);
    bytes32 userOpHash = keccak256("user-op-invalid-entrypoint");
    address randomCaller = address(0xbeef);

    address payable authority = payable(vm.addr(authorityPk));
    PackedUserOperation memory userOp =
      _createUserOp(authority, bytes(""), hex"000010000000000000000000000000000000000000000000");

    vm.startPrank(randomCaller);
    vm.expectRevert(abi.encodeWithSelector(ERC4337v07.InvalidEntryPoint.selector, randomCaller));
    _attachDelegation(authorityPk);
    Stage7702Module(authority).validateUserOp(userOp, userOpHash, 0);
    vm.stopPrank();
  }

  function test_validate_user_op_deposits_missing_funds(
    bytes32 userOpHash,
    uint256 authorityPk,
    uint256 missingFunds
  ) external {
    authorityPk = boundPk(authorityPk);
    missingFunds = bound(missingFunds, 1, 100 ether);

    address payable authority = payable(vm.addr(authorityPk));
    PackedUserOperation memory userOp =
      _createUserOp(authority, bytes(""), hex"000010000000000000000000000000000000000000000000");

    vm.deal(authority, missingFunds);

    vm.startPrank(address(entryPoint));
    vm.expectEmit(true, true, false, true, address(entryPoint));
    emit IStakeManager.Deposited(authority, missingFunds);

    _attachDelegation(authorityPk);
    uint256 validationData = Stage7702Module(authority).validateUserOp(userOp, userOpHash, missingFunds);
    vm.stopPrank();

    assertEq(validationData, 1);
    assertEq(entryPoint.balanceOf(authority), missingFunds);
    assertEq(address(authority).balance, 0);
  }

  function test_validate_user_op_reverts_if_disabled(
    bytes32 userOpHash,
    uint256 authorityPk,
    uint256 missingFunds
  ) external {
    authorityPk = boundPk(authorityPk);
    Stage7702Module disabledModule = new Stage7702Module(address(0), address(checkpointer));
    address payable authority = payable(vm.addr(authorityPk));
    PackedUserOperation memory userOp =
      _createUserOp(authority, bytes(""), hex"000010000000000000000000000000000000000000000000");

    vm.startPrank(address(entryPoint));
    vm.expectRevert(ERC4337v07.ERC4337Disabled.selector);
    _attachDelegation(address(disabledModule), authorityPk);
    Stage7702Module(authority).validateUserOp(userOp, userOpHash, missingFunds);
    vm.stopPrank();
  }

  function test_execute_user_op_executes_payload() external {
    uint256 authorityPk = boundPk(123);
    Emitter emitter = new Emitter();

    address payable authority = payable(vm.addr(authorityPk));

    Payload.Decoded memory payload = _singleCallPayload(
      Payload.Call({
        to: address(emitter),
        value: 0,
        data: abi.encodeWithSelector(Emitter.explicitEmit.selector),
        gasLimit: 0,
        delegateCall: false,
        onlyFallback: false,
        behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
      }),
      0,
      false
    );

    bytes memory packedPayload = PrimitivesRPC.toPackedPayload(vm, payload);

    vm.expectEmit(true, false, false, true, address(emitter));
    emit Emitter.Explicit(authority);

    vm.startPrank(address(entryPoint));
    _attachDelegation(authorityPk);
    Stage7702Module(authority).executeUserOp(packedPayload);
    vm.stopPrank();
  }

  function test_execute_user_op_reverts_invalid_entrypoint(
    uint256 authorityPk,
    address randomCaller,
    bytes calldata payload
  ) external {
    authorityPk = boundPk(authorityPk);
    vm.assume(randomCaller != address(entryPoint));

    address payable authority = payable(vm.addr(authorityPk));

    vm.startPrank(randomCaller);
    vm.expectRevert(abi.encodeWithSelector(ERC4337v07.InvalidEntryPoint.selector, randomCaller));
    _attachDelegation(authorityPk);
    Stage7702Module(authority).executeUserOp(payload);
    vm.stopPrank();
  }

  function test_execute_user_op_reverts_if_disabled(
    uint256 authorityPk,
    bytes calldata payload
  ) external {
    authorityPk = boundPk(authorityPk);
    Stage7702Module disabledModule = new Stage7702Module(address(0), address(checkpointer));
    address payable authority = payable(vm.addr(authorityPk));

    vm.startPrank(address(entryPoint));
    vm.expectRevert(ERC4337v07.ERC4337Disabled.selector);
    _attachDelegation(address(disabledModule), authorityPk);
    Stage7702Module(authority).executeUserOp(payload);
    vm.stopPrank();
  }

  function _attachDelegation(
    uint256 authorityPk
  ) internal {
    _attachDelegation(address(stage7702Module), authorityPk);
  }

  function _attachDelegation(
    address delegate,
    uint256 authorityPk
  ) internal {
    vm.signAndAttachDelegation(delegate, authorityPk);
  }

  function _imageHash(
    address authority,
    uint256 authorityPk
  ) internal returns (bytes32) {
    bytes memory result =
      _delegatedCall(authority, authorityPk, abi.encodeWithSelector(Stage7702Auth.imageHash.selector));
    return abi.decode(result, (bytes32));
  }

  function _getImplementation(
    address authority,
    uint256 authorityPk
  ) internal returns (address) {
    return _getImplementation(authority, authorityPk, address(stage7702Module));
  }

  function _getImplementation(
    address authority,
    uint256 authorityPk,
    address delegate
  ) internal returns (address) {
    bytes memory data = abi.encodeWithSignature("getImplementation()");

    _attachDelegation(delegate, authorityPk);

    (bool success, bytes memory returnData) = authority.call(data);
    if (!success) {
      assembly {
        revert(add(returnData, 0x20), mload(returnData))
      }
    }

    return abi.decode(returnData, (address));
  }

  function _isValidSignature(
    address authority,
    uint256 authorityPk,
    bytes32 digest,
    bytes memory signature
  ) internal returns (bytes4) {
    bytes memory result = _delegatedCall(
      authority, authorityPk, abi.encodeWithSelector(BaseAuth.isValidSignature.selector, digest, signature)
    );
    return abi.decode(result, (bytes4));
  }

  function _isValidSignatureFrom(
    address caller,
    address authority,
    uint256 authorityPk,
    bytes32 digest,
    bytes memory signature
  ) internal returns (bytes4) {
    bytes memory result = _delegatedCallFrom(
      caller, authority, authorityPk, abi.encodeWithSelector(BaseAuth.isValidSignature.selector, digest, signature)
    );
    return abi.decode(result, (bytes4));
  }

  function _recoverPartialSignature(
    address authority,
    uint256 authorityPk,
    Payload.Decoded memory payload,
    bytes memory signature
  ) internal returns (uint256, uint256, bool, bytes32, uint256, bytes32) {
    bytes memory result = _delegatedCall(
      authority, authorityPk, abi.encodeCall(IPartialAuth.recoverPartialSignature, (payload, signature))
    );
    return abi.decode(result, (uint256, uint256, bool, bytes32, uint256, bytes32));
  }

  function _recoverSapientSignatureFrom(
    address caller,
    address authority,
    uint256 authorityPk,
    Payload.Decoded memory payload,
    bytes memory signature
  ) internal returns (bytes32) {
    bytes memory result = _delegatedCallFrom(
      caller,
      authority,
      authorityPk,
      abi.encodeWithSelector(BaseAuth.recoverSapientSignature.selector, payload, signature)
    );
    return abi.decode(result, (bytes32));
  }

  function _getStaticSignature(
    address authority,
    uint256 authorityPk,
    bytes32 hash
  ) internal returns (address, uint256) {
    bytes memory result =
      _delegatedCall(authority, authorityPk, abi.encodeWithSelector(BaseAuth.getStaticSignature.selector, hash));
    return abi.decode(result, (address, uint256));
  }

  function _delegatedCall(
    address authority,
    uint256 authorityPk,
    bytes memory data
  ) internal returns (bytes memory result) {
    _attachDelegation(authorityPk);

    (bool success, bytes memory returnData) = authority.call(data);
    if (!success) {
      assembly {
        revert(add(returnData, 0x20), mload(returnData))
      }
    }

    return returnData;
  }

  function _delegatedCallFrom(
    address caller,
    address authority,
    uint256 authorityPk,
    bytes memory data
  ) internal returns (bytes memory result) {
    vm.startPrank(caller);
    _attachDelegation(authorityPk);

    (bool success, bytes memory returnData) = authority.call(data);
    vm.stopPrank();

    if (!success) {
      assembly {
        revert(add(returnData, 0x20), mload(returnData))
      }
    }

    return returnData;
  }

  function _newConfig(
    uint16 threshold,
    uint56 checkpoint,
    string memory content
  ) internal returns (string memory) {
    return PrimitivesRPC.newConfigWithCheckpointer(vm, address(checkpointer), threshold, checkpoint, content);
  }

  function _newConfigWithoutCheckpointer(
    uint16 threshold,
    uint56 checkpoint,
    string memory content
  ) internal returns (string memory) {
    return PrimitivesRPC.newConfig(vm, threshold, checkpoint, content);
  }

  function _initialConfig(
    address authority,
    uint256 authorityPk
  ) internal returns (ConfigContext memory context) {
    context.signer = authority;
    context.signerPk = authorityPk;
    context.config = _newConfig(1, 0, string(abi.encodePacked("signer:", vm.toString(authority), ":1")));
    context.imageHash = PrimitivesRPC.getImageHash(vm, context.config);
  }

  function _singleSignerConfig(
    address signer,
    uint256 signerPk,
    uint56 checkpoint
  ) internal returns (ConfigContext memory context) {
    context.signer = signer;
    context.signerPk = signerPk;
    context.config = _newConfig(1, checkpoint, string(abi.encodePacked("signer:", vm.toString(signer), ":1")));
    context.imageHash = PrimitivesRPC.getImageHash(vm, context.config);
  }

  function _singleSignerConfigWithoutCheckpointer(
    address signer,
    uint256 signerPk,
    uint56 checkpoint
  ) internal returns (ConfigContext memory context) {
    context.signer = signer;
    context.signerPk = signerPk;
    context.config =
      _newConfigWithoutCheckpointer(1, checkpoint, string(abi.encodePacked("signer:", vm.toString(signer), ":1")));
    context.imageHash = PrimitivesRPC.getImageHash(vm, context.config);
  }

  function _sapientConfig(
    address signer,
    bytes32 sapientImageHash,
    uint56 checkpoint
  ) internal returns (ConfigContext memory context) {
    context.signer = signer;
    context.config = _newConfig(
      1,
      checkpoint,
      string(
        abi.encodePacked(
          "sapient:", vm.toString(sapientImageHash), ":", vm.toString(signer), ":", vm.toString(uint256(1))
        )
      )
    );
    context.imageHash = PrimitivesRPC.getImageHash(vm, context.config);
  }

  function _signPayload(
    ConfigContext memory context,
    Payload.Decoded memory payload,
    address wallet
  ) internal returns (bytes memory) {
    return _signPayload(context, payload, wallet, false);
  }

  function _signPayload(
    ConfigContext memory context,
    Payload.Decoded memory payload,
    address wallet,
    bool useEthSign
  ) internal returns (bytes memory) {
    bytes32 payloadHash = Payload.hashFor(payload, wallet);
    return _encodeHashSignature(
      context.config, context.signer, context.signerPk, payloadHash, !payload.noChainId, useEthSign
    );
  }

  function _encodeHashSignature(
    string memory config,
    address signer,
    uint256 signerPk,
    bytes32 payloadHash,
    bool chainId
  ) internal returns (bytes memory) {
    return _encodeHashSignature(config, signer, signerPk, payloadHash, chainId, false);
  }

  function _encodeHashSignature(
    string memory config,
    address signer,
    uint256 signerPk,
    bytes32 payloadHash,
    bool chainId,
    bool useEthSign
  ) internal returns (bytes memory) {
    bytes32 hashToSign = payloadHash;
    if (useEthSign) {
      hashToSign = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", payloadHash));
    }

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, hashToSign);

    string memory signatureType = useEthSign ? ":eth_sign:" : ":hash:";
    string memory signatures = string(
      abi.encodePacked(vm.toString(signer), signatureType, vm.toString(r), ":", vm.toString(s), ":", vm.toString(v))
    );

    return PrimitivesRPC.toEncodedSignature(vm, config, signatures, chainId);
  }

  function _encodeHashSignatureWithCheckpointerData(
    string memory config,
    address signer,
    uint256 signerPk,
    bytes32 payloadHash,
    bool chainId,
    bytes memory checkpointerData,
    bool useEthSign
  ) internal returns (bytes memory) {
    string memory signatures = _hashSignatureString(signer, signerPk, payloadHash, useEthSign);
    return PrimitivesRPC.toEncodedSignatureWithCheckpointerData(vm, config, signatures, chainId, checkpointerData);
  }

  function _encodeHashSignatureMulti(
    string memory config,
    address[] memory signers,
    uint256[] memory signerPks,
    bytes32 payloadHash,
    bool chainId,
    bool useEthSign
  ) internal returns (bytes memory) {
    string memory signatures;

    for (uint256 i = 0; i < signers.length; i++) {
      signatures = string(
        abi.encodePacked(
          signatures, i == 0 ? "" : " ", _hashSignatureString(signers[i], signerPks[i], payloadHash, useEthSign)
        )
      );
    }

    return PrimitivesRPC.toEncodedSignature(vm, config, signatures, chainId);
  }

  function _hashSignatureString(
    address signer,
    uint256 signerPk,
    bytes32 payloadHash,
    bool useEthSign
  ) internal returns (string memory) {
    bytes32 hashToSign = payloadHash;
    if (useEthSign) {
      hashToSign = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", payloadHash));
    }

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, hashToSign);

    string memory signatureType = useEthSign ? ":eth_sign:" : ":hash:";
    return string(
      abi.encodePacked(vm.toString(signer), signatureType, vm.toString(r), ":", vm.toString(s), ":", vm.toString(v))
    );
  }

  function _encodeERC1271Signature(
    string memory config,
    address signer,
    bytes memory signature,
    bool chainId
  ) internal returns (bytes memory) {
    string memory encoded = string(abi.encodePacked(vm.toString(signer), ":erc1271:", vm.toString(signature)));
    return PrimitivesRPC.toEncodedSignature(vm, config, encoded, chainId);
  }

  function _encodeSapientSignature(
    string memory config,
    address signer,
    bytes memory signature,
    bool chainId,
    bool compact
  ) internal returns (bytes memory) {
    string memory signatureType = compact ? ":sapient_compact:" : ":sapient:";
    string memory encoded = string(abi.encodePacked(vm.toString(signer), signatureType, vm.toString(signature)));
    return PrimitivesRPC.toEncodedSignature(vm, config, encoded, chainId);
  }

  function _executePayload(
    ConfigContext memory context,
    address authority,
    uint256 authorityPk,
    Payload.Decoded memory payload
  ) internal {
    bytes memory signature = _signPayload(context, payload, authority);
    bytes memory packedPayload = PrimitivesRPC.toPackedPayload(vm, payload);

    _attachDelegation(authorityPk);
    Stage7702Module(payable(authority)).execute(packedPayload, signature);
  }

  function _updateImageHash(
    ConfigContext memory context,
    address authority,
    uint256 authorityPk,
    bytes32 imageHash,
    uint256 nonce
  ) internal {
    _executePayload(context, authority, authorityPk, _updateImageHashPayload(authority, imageHash, nonce));
  }

  function _digestPayload(
    bytes32 digest,
    bool noChainId
  ) internal pure returns (Payload.Decoded memory payload) {
    payload = Payload.fromDigest(digest);
    payload.noChainId = noChainId;
  }

  function _singleCallPayload(
    Payload.Call memory call,
    uint256 nonce,
    bool noChainId
  ) internal pure returns (Payload.Decoded memory payload) {
    payload.kind = Payload.KIND_TRANSACTIONS;
    payload.calls = new Payload.Call[](1);
    payload.calls[0] = call;
    payload.nonce = uint56(nonce);
    payload.noChainId = noChainId;
  }

  function _updateImageHashPayload(
    address wallet,
    bytes32 imageHash,
    uint256 nonce
  ) internal pure returns (Payload.Decoded memory payload) {
    payload.kind = Payload.KIND_TRANSACTIONS;
    payload.calls = new Payload.Call[](1);
    payload.calls[0] = Payload.Call({
      to: wallet,
      value: 0,
      data: abi.encodeWithSelector(BaseAuth.updateImageHash.selector, imageHash),
      gasLimit: 100000,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });
    payload.nonce = uint56(nonce);
  }

  function _setStaticSignaturePayload(
    address wallet,
    bytes32 hash,
    address sigAddress,
    uint96 timestamp,
    uint256 nonce
  ) internal pure returns (Payload.Decoded memory payload) {
    payload.kind = Payload.KIND_TRANSACTIONS;
    payload.calls = new Payload.Call[](1);
    payload.calls[0] = Payload.Call({
      to: wallet,
      value: 0,
      data: abi.encodeWithSelector(BaseAuth.setStaticSignature.selector, hash, sigAddress, timestamp),
      gasLimit: 100000,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });
    payload.nonce = uint56(nonce);
  }

  function _createUserOp(
    address sender,
    bytes memory callData,
    bytes memory signature
  ) internal pure returns (PackedUserOperation memory) {
    return PackedUserOperation({
      sender: sender,
      nonce: 0,
      initCode: "",
      callData: callData,
      accountGasLimits: bytes32(0),
      preVerificationGas: 21000,
      gasFees: bytes32(0),
      paymasterAndData: "",
      signature: signature
    });
  }

  function _hasImageHashUpdated(
    Vm.Log[] memory logs,
    address emitter,
    bytes32 newImageHash
  ) internal pure returns (bool) {
    bytes32 topic0 = keccak256("ImageHashUpdated(bytes32)");

    for (uint256 i = 0; i < logs.length; i++) {
      if (logs[i].emitter == emitter && logs[i].topics.length == 1 && logs[i].topics[0] == topic0) {
        return abi.decode(logs[i].data, (bytes32)) == newImageHash;
      }
    }

    return false;
  }

  function _flatSignerConfig(
    address[] memory signers,
    uint8[] memory weights,
    uint16 threshold,
    uint56 checkpoint
  ) internal returns (string memory) {
    string memory content;

    for (uint256 i = 0; i < signers.length; i++) {
      content = string(
        abi.encodePacked(
          content, i == 0 ? "" : " ", "signer:", vm.toString(signers[i]), ":", vm.toString(uint256(weights[i]))
        )
      );
    }

    return _newConfigWithoutCheckpointer(threshold, checkpoint, content);
  }

}
