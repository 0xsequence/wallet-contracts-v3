// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Factory } from "../src/Factory.sol";
import { Stage1Module } from "../src/Stage1Module.sol";
import { Stage2Module } from "../src/Stage2Module.sol";

import { Payload } from "../src/modules/Payload.sol";

import { BaseAuth } from "../src/modules/auth/BaseAuth.sol";

import { SelfAuth } from "../src/modules/auth/SelfAuth.sol";

import { Calls } from "../src/modules/Calls.sol";
import { Stage1Auth } from "../src/modules/auth/Stage1Auth.sol";
import { IPartialAuth } from "../src/modules/interfaces/IPartialAuth.sol";

import { ISapient } from "../src/modules/interfaces/ISapient.sol";
import { PrimitivesRPC } from "./utils/PrimitivesRPC.sol";
import { AdvTest } from "./utils/TestUtils.sol";

import { CanReenter } from "test/mocks/CanReenter.sol";

contract TestStage1Module is AdvTest {

  event ImageHashUpdated(bytes32 newImageHash);

  Factory public factory = new Factory();
  Stage1Module public stage1Module = new Stage1Module(address(factory), address(0));

  event StaticSignatureSet(bytes32 _hash, address _address, uint96 _timestamp);

  function test_fails_on_low_weight(
    uint16 _threshold,
    uint56 _checkpoint,
    uint8 _weight,
    uint256 _pk,
    bytes32 _digest,
    bool _noChainId
  ) external {
    _weight = uint8(bound(_weight, 1, type(uint8).max));
    _threshold = uint16(bound(_threshold, 1, _weight));
    _pk = boundPk(_pk);

    address signer = vm.addr(_pk);

    string memory config;

    {
      string memory ce;
      ce = string(abi.encodePacked(ce, "signer:", vm.toString(signer), ":", vm.toString(_weight)));
      config = PrimitivesRPC.newConfig(vm, _threshold, _checkpoint, ce);
    }

    bytes32 configHash = PrimitivesRPC.getImageHash(vm, config);

    // Deploy wallet for that config
    address payable wallet = payable(factory.deploy(address(stage1Module), configHash));

    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_DIGEST;
    payload.digest = _digest;
    payload.noChainId = _noChainId;

    // Create a signature with only nodes
    bytes memory signature = PrimitivesRPC.toEncodedSignature(vm, config, "", !_noChainId);

    // Call isValidSignature and expect it to fail
    vm.expectRevert(abi.encodeWithSelector(BaseAuth.InvalidSignatureWeight.selector, _threshold, 0));
    Stage1Module(wallet).isValidSignature(_digest, signature);
  }

  function test_1271_single_signer(
    uint16 _threshold,
    uint56 _checkpoint,
    uint8 _weight,
    uint256 _pk,
    bytes32 _digest,
    bool _noChainId
  ) external {
    _threshold = uint16(bound(_threshold, 0, _weight));
    _pk = boundPk(_pk);

    address signer = vm.addr(_pk);

    string memory config;

    {
      string memory ce;
      ce = string(abi.encodePacked(ce, "signer:", vm.toString(signer), ":", vm.toString(_weight)));
      config = PrimitivesRPC.newConfig(vm, _threshold, _checkpoint, ce);
    }

    bytes32 configHash = PrimitivesRPC.getImageHash(vm, config);

    // Deploy wallet for that config
    address payable wallet = payable(factory.deploy(address(stage1Module), configHash));

    // Should predict the address of the wallet using the SDK
    address predictedWallet = PrimitivesRPC.getAddress(vm, configHash, address(factory), address(stage1Module));
    assertEq(wallet, predictedWallet);

    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_DIGEST;
    payload.digest = _digest;
    payload.noChainId = _noChainId;

    // Sign the config
    (uint256 v, bytes32 r, bytes32 s) = vm.sign(_pk, Payload.hashFor(payload, wallet));

    bytes memory signature = PrimitivesRPC.toEncodedSignature(
      vm,
      config,
      string(abi.encodePacked(vm.toString(signer), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v))),
      !_noChainId
    );

    // Call isValidSignature
    bytes4 result = Stage1Module(wallet).isValidSignature(_digest, signature);
    assertEq(result, bytes4(0x1626ba7e));
  }

  struct test_update_config_params {
    uint16 threshold;
    uint56 checkpoint;
    uint8 weight;
    uint256 pk;
    bool noChainId;
    // Next config parameters
    uint16 nextThreshold;
    uint56 nextCheckpoint;
    uint8 nextWeight;
    uint256 nextPk;
    // Test transaction parameters
    bytes32 digest;
  }

  struct test_update_config_vars {
    address ogSigner;
    address nextSigner;
    string ogConfig;
    string nextConfig;
    bytes32 ogConfigHash;
    bytes32 nextConfigHash;
    Payload.Decoded updateConfigPayload;
    bytes updateConfigSignature;
    bytes updateConfigPackedPayload;
    Payload.Decoded useNewImageHashPayload;
    bytes useNewImageHashSignature;
  }

  function test_update_config(
    test_update_config_params memory params
  ) external {
    params.pk = boundPk(params.pk);
    params.nextPk = boundPk(params.nextPk);
    params.threshold = uint16(bound(params.threshold, 0, params.weight));
    params.nextThreshold = uint16(bound(params.nextThreshold, 0, params.nextWeight));

    test_update_config_vars memory vars;

    vars.ogSigner = vm.addr(params.pk);

    {
      string memory ce;
      ce = string(abi.encodePacked(ce, "signer:", vm.toString(vars.ogSigner), ":", vm.toString(params.weight)));
      vars.ogConfig = PrimitivesRPC.newConfig(vm, params.threshold, params.checkpoint, ce);
    }

    vars.ogConfigHash = PrimitivesRPC.getImageHash(vm, vars.ogConfig);

    // Deploy wallet for that config
    address payable wallet = payable(factory.deploy(address(stage1Module), vars.ogConfigHash));

    vars.nextSigner = vm.addr(params.nextPk);

    {
      string memory ce;
      ce = string(abi.encodePacked(ce, "signer:", vm.toString(vars.nextSigner), ":", vm.toString(params.nextWeight)));
      vars.nextConfig = PrimitivesRPC.newConfig(vm, params.nextThreshold, params.nextCheckpoint, ce);
    }

    vars.nextConfigHash = PrimitivesRPC.getImageHash(vm, vars.nextConfig);

    // Update configuration to the next config
    vars.updateConfigPayload.kind = Payload.KIND_TRANSACTIONS;
    vars.updateConfigPayload.calls = new Payload.Call[](1);
    vars.updateConfigPayload.calls[0] = Payload.Call({
      to: address(wallet),
      value: 0,
      data: abi.encodeWithSelector(BaseAuth.updateImageHash.selector, vars.nextConfigHash),
      gasLimit: 100000,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });
    vars.updateConfigPayload.noChainId = params.noChainId;

    {
      // Sign the payload
      (uint256 v, bytes32 r, bytes32 s) = vm.sign(params.pk, Payload.hashFor(vars.updateConfigPayload, wallet));

      // Call updateConfig
      vars.updateConfigSignature = PrimitivesRPC.toEncodedSignature(
        vm,
        vars.ogConfig,
        string(
          abi.encodePacked(
            vm.toString(vars.ogSigner), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v)
          )
        ),
        !params.noChainId
      );
    }

    // Pack payload
    vars.updateConfigPackedPayload = PrimitivesRPC.toPackedPayload(vm, vars.updateConfigPayload);

    // Perform updateConfig
    vm.expectEmit(true, true, false, true, wallet);
    emit ImageHashUpdated(vars.nextConfigHash);
    Stage1Module(wallet).execute(vars.updateConfigPackedPayload, vars.updateConfigSignature);

    // Now the wallet should be at stage 2
    // and its imageHash should be updated
    assertEq(Stage1Module(wallet).getImplementation(), stage1Module.STAGE_2_IMPLEMENTATION());
    assertEq(Stage2Module(wallet).imageHash(), vars.nextConfigHash);

    // Now try to use the new imageHash
    vars.useNewImageHashPayload.kind = Payload.KIND_DIGEST;
    vars.useNewImageHashPayload.digest = params.digest;

    // Sign the payload
    {
      (uint256 v, bytes32 r, bytes32 s) = vm.sign(params.nextPk, Payload.hashFor(vars.useNewImageHashPayload, wallet));

      vars.useNewImageHashSignature = PrimitivesRPC.toEncodedSignature(
        vm,
        vars.nextConfig,
        string(
          abi.encodePacked(
            vm.toString(vars.nextSigner), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v)
          )
        ),
        true
      );
    }

    bytes4 result = Stage2Module(wallet).isValidSignature(params.digest, vars.useNewImageHashSignature);
    assertEq(result, bytes4(0x1626ba7e));
  }

  function test_receiveETH_stage1() external {
    address payable wallet = payable(factory.deploy(address(stage1Module), bytes32(0)));
    vm.deal(address(this), 1 ether);
    wallet.transfer(1 ether);
    assertEq(address(wallet).balance, 1 ether);
  }

  struct test_receiveETH_stage2_params {
    uint256 pk;
    uint256 nextPk;
    uint16 threshold;
    uint16 nextThreshold;
    uint56 checkpoint;
  }

  struct test_receiveETH_stage2_vars {
    address signer;
    address payable wallet;
    bytes updateConfigSignature;
    bytes updateConfigPackedPayload;
    string ogCe;
    string ogConfig;
    string nextCe;
    string nextConfig;
    bytes32 ogConfigHash;
    bytes32 nextConfigHash;
  }

  function test_receiveETH_stage2(
    test_receiveETH_stage2_params memory params
  ) external {
    params.pk = boundPk(params.pk);

    test_receiveETH_stage2_vars memory vars;
    vars.signer = vm.addr(params.pk);

    // Original config (stage1)
    vars.ogCe = string(abi.encodePacked("signer:", vm.toString(vars.signer), ":1"));
    vars.ogConfig = PrimitivesRPC.newConfig(vm, 1, 0, vars.ogCe);
    vars.ogConfigHash = PrimitivesRPC.getImageHash(vm, vars.ogConfig);

    // Deploy wallet in stage1
    vars.wallet = payable(factory.deploy(address(stage1Module), vars.ogConfigHash));

    // Next config (what we'll update to)
    vars.nextCe = string(abi.encodePacked("signer:", vm.toString(vars.signer), ":1"));
    vars.nextConfig = PrimitivesRPC.newConfig(vm, 1, 1, vars.nextCe);
    vars.nextConfigHash = PrimitivesRPC.getImageHash(vm, vars.nextConfig);

    // Construct the payload to update the imageHash (which transitions us to stage2)
    Payload.Decoded memory updateConfigPayload;
    updateConfigPayload.kind = Payload.KIND_TRANSACTIONS;
    updateConfigPayload.calls = new Payload.Call[](1);
    updateConfigPayload.calls[0] = Payload.Call({
      to: address(vars.wallet),
      value: 0,
      data: abi.encodeWithSelector(BaseAuth.updateImageHash.selector, vars.nextConfigHash),
      gasLimit: 100000,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Sign the payload using the original config
    (uint256 v, bytes32 r, bytes32 s) = vm.sign(params.pk, Payload.hashFor(updateConfigPayload, vars.wallet));
    vars.updateConfigSignature = PrimitivesRPC.toEncodedSignature(
      vm,
      vars.ogConfig,
      string(
        abi.encodePacked(vm.toString(vars.signer), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v))
      ),
      true
    );

    // Pack the payload and execute
    vars.updateConfigPackedPayload = PrimitivesRPC.toPackedPayload(vm, updateConfigPayload);
    vm.expectEmit(true, true, false, true, vars.wallet);
    emit ImageHashUpdated(vars.nextConfigHash);
    Stage1Module(vars.wallet).execute(vars.updateConfigPackedPayload, vars.updateConfigSignature);

    // Confirm that the wallet is now running stage2
    assertEq(Stage1Module(vars.wallet).getImplementation(), stage1Module.STAGE_2_IMPLEMENTATION());

    // Send 1 ether to the newly upgraded wallet
    vm.deal(address(this), 1 ether);
    vars.wallet.transfer(1 ether);

    // Check that the wallet received the ether
    assertEq(address(vars.wallet).balance, 1 ether);
  }

  function test_static_signature_any_address(
    bytes32 _digest,
    bytes32 _imageHash,
    uint256 _timestamp,
    uint256 _validUntil,
    address _otherCaller
  ) external {
    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_DIGEST;
    payload.digest = _digest;

    _timestamp = bound(_timestamp, 0, type(uint64).max);
    _validUntil = bound(_validUntil, _timestamp + 1, type(uint96).max);

    vm.warp(_timestamp);

    // Create a new wallet using imageHash
    address payable wallet = payable(factory.deploy(address(stage1Module), _imageHash));

    // Set the static signature
    vm.prank(wallet);
    vm.expectEmit(true, true, false, true, wallet);
    emit StaticSignatureSet(Payload.hashFor(payload, wallet), address(0), uint96(_validUntil));
    Stage1Module(wallet).setStaticSignature(Payload.hashFor(payload, wallet), address(0), uint96(_validUntil));

    (address addr, uint256 timestamp) = Stage1Module(wallet).getStaticSignature(Payload.hashFor(payload, wallet));
    assertEq(addr, address(0));
    assertEq(timestamp, _validUntil);

    // Call isValidSignature and expect it to succeed
    bytes4 result = Stage1Module(wallet).isValidSignature(_digest, hex"80");
    assertEq(result, bytes4(0x1626ba7e));

    // Even if called from other caller
    vm.prank(_otherCaller);
    result = Stage1Module(wallet).isValidSignature(_digest, hex"80");
    assertEq(result, bytes4(0x1626ba7e));
  }

  function test_static_signature_specific_address(
    bytes32 _digest,
    bytes32 _imageHash,
    uint256 _timestamp,
    uint256 _validUntil,
    address _onlyAddress,
    address _otherCaller
  ) external {
    vm.assume(_onlyAddress != address(0) && _onlyAddress != _otherCaller);

    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_DIGEST;
    payload.digest = _digest;

    _timestamp = bound(_timestamp, 0, type(uint64).max);
    _validUntil = bound(_validUntil, _timestamp + 1, type(uint96).max);

    vm.warp(_timestamp);

    // Create a new wallet using imageHash
    address payable wallet = payable(factory.deploy(address(stage1Module), _imageHash));

    // Set the static signature
    vm.prank(wallet);
    vm.expectEmit(true, true, false, true, wallet);
    emit StaticSignatureSet(Payload.hashFor(payload, wallet), _onlyAddress, uint96(_validUntil));
    Stage1Module(wallet).setStaticSignature(Payload.hashFor(payload, wallet), _onlyAddress, uint96(_validUntil));

    (address addr, uint256 timestamp) = Stage1Module(wallet).getStaticSignature(Payload.hashFor(payload, wallet));
    assertEq(addr, _onlyAddress);
    assertEq(timestamp, _validUntil);

    // Call isValidSignature from _onlyAddress should succeed
    vm.prank(_onlyAddress);
    bytes4 result = Stage1Module(wallet).isValidSignature(_digest, hex"80");
    assertEq(result, bytes4(0x1626ba7e));

    // Call isValidSignature from _otherCaller should fail
    vm.prank(_otherCaller);
    vm.expectRevert(
      abi.encodeWithSelector(
        BaseAuth.InvalidStaticSignatureWrongCaller.selector,
        Payload.hashFor(payload, wallet),
        _otherCaller,
        _onlyAddress
      )
    );
    Stage1Module(wallet).isValidSignature(_digest, hex"80");
  }

  function test_reverts_invalid_static_signature_expired(
    bytes32 _digest,
    bytes32 _imageHash,
    uint256 _startTime,
    uint256 _validUntil
  ) external {
    // Ensure validUntil is strictly after startTime and within uint96 range
    _startTime = bound(_startTime, 0, type(uint96).max - 1);
    _validUntil = bound(_validUntil, _startTime + 1, type(uint96).max);

    // Set the current time to _startTime
    vm.warp(_startTime);

    // Create a new wallet
    address payable wallet = payable(factory.deploy(address(stage1Module), _imageHash));

    // Prepare the payload and calculate its hash
    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_DIGEST;
    payload.digest = _digest;
    bytes32 opHash = Payload.hashFor(payload, wallet);

    // Set the static signature from the wallet itself, valid until _validUntil
    // Use address(0) to allow any caller before expiration
    vm.prank(wallet);
    vm.expectEmit(true, true, false, true, wallet);
    emit StaticSignatureSet(opHash, address(0), uint96(_validUntil));
    Stage1Module(wallet).setStaticSignature(opHash, address(0), uint96(_validUntil));

    // Verify it was set correctly
    (address addr, uint256 timestamp) = Stage1Module(wallet).getStaticSignature(opHash);
    assertEq(addr, address(0));
    assertEq(timestamp, _validUntil);

    // --- Test Case 1: Use signature just before expiry (should work) ---
    vm.warp(_validUntil - 1); // Set time to just before expiration
    bytes4 result = Stage1Module(wallet).isValidSignature(_digest, hex"80");
    assertEq(result, bytes4(0x1626ba7e), "Signature should be valid before expiry");

    // --- Test Case 2: Use signature exactly at expiry (should fail) ---
    vm.warp(_validUntil); // Set time exactly to expiration
    vm.expectRevert(abi.encodeWithSelector(BaseAuth.InvalidStaticSignatureExpired.selector, opHash, _validUntil));
    Stage1Module(wallet).isValidSignature(_digest, hex"80");

    // --- Test Case 3: Use signature after expiry (should fail) ---
    vm.warp(_validUntil + 1); // Set time after expiration
    vm.expectRevert(abi.encodeWithSelector(BaseAuth.InvalidStaticSignatureExpired.selector, opHash, _validUntil));
    Stage1Module(wallet).isValidSignature(_digest, hex"80");
  }

  function test_reverts_set_static_signature_not_self(
    bytes32 _hash,
    bytes32 _imageHash,
    address _sigAddress,
    uint96 _timestamp,
    address _caller // The address attempting the call (not the wallet)
  ) external {
    // Create a new wallet
    address payable wallet = payable(factory.deploy(address(stage1Module), _imageHash));

    // Ensure the caller is not the wallet itself
    vm.assume(_caller != wallet);

    // Attempt to call setStaticSignature from _caller
    vm.prank(_caller);
    vm.expectRevert(abi.encodeWithSelector(SelfAuth.OnlySelf.selector, _caller));
    Stage1Module(wallet).setStaticSignature(_hash, _sigAddress, _timestamp);

    // Verify that the signature was NOT set (should still be default values)
    (address addr, uint256 ts) = Stage1Module(wallet).getStaticSignature(_hash);
    assertEq(addr, address(0), "Static signature address should not be set");
    assertEq(ts, 0, "Static signature timestamp should not be set");
  }

  struct test_recover_partial_signature_params {
    Payload.Decoded payload;
    uint16 threshold;
    uint56 checkpoint;
    uint8 signerWeight;
    uint256 pk;
    bool signPayload;
    bool useEthSign;
    bool noChainId;
  }

  struct test_recover_partial_signature_vars {
    address signer;
    string config;
    bytes32 configHash;
    bytes encodedSignature;
    uint8 v;
    bytes32 r;
    bytes32 s;
    bytes32 payloadHash;
    address wallet;
    uint256 expectedWeight;
  }

  function test_recover_partial_signature(
    test_recover_partial_signature_params memory params
  ) external {
    boundToLegalPayload(params.payload);
    params.pk = boundPk(params.pk);
    params.payload.noChainId = params.noChainId;
    if (params.signPayload) {
      params.threshold = uint16(bound(params.threshold, 1, type(uint16).max));
      params.signerWeight = uint8(bound(params.signerWeight, 0, type(uint8).max));
    } else {
      params.threshold = uint16(bound(params.threshold, 0, type(uint16).max));
      params.signerWeight = uint8(bound(params.signerWeight, 0, type(uint8).max));
    }

    test_recover_partial_signature_vars memory vars;
    vars.signer = vm.addr(params.pk);

    string memory ce =
      string(abi.encodePacked("signer:", vm.toString(vars.signer), ":", vm.toString(params.signerWeight)));
    vars.config = PrimitivesRPC.newConfig(vm, params.threshold, params.checkpoint, ce);
    vars.configHash = PrimitivesRPC.getImageHash(vm, vars.config);

    vars.wallet = factory.deploy(address(stage1Module), vars.configHash);

    vars.payloadHash = Payload.hashFor(params.payload, vars.wallet);
    string memory signatures = "";
    vars.expectedWeight = 0;

    if (params.signPayload) {
      bytes32 hashToSign = vars.payloadHash;
      if (params.useEthSign) {
        hashToSign = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", vars.payloadHash));
      }
      (vars.v, vars.r, vars.s) = vm.sign(params.pk, hashToSign);

      string memory signatureType = params.useEthSign ? ":eth_sign:" : ":hash:";
      signatures = string(
        abi.encodePacked(
          vm.toString(vars.signer),
          signatureType,
          vm.toString(vars.r),
          ":",
          vm.toString(vars.s),
          ":",
          vm.toString(vars.v)
        )
      );
      vars.expectedWeight = params.signerWeight;
    }

    vars.encodedSignature = PrimitivesRPC.toEncodedSignature(vm, vars.config, signatures, !params.noChainId);

    (
      uint256 recoveredThreshold,
      uint256 recoveredWeight,
      bool recoveredIsValidImage,
      bytes32 recoveredImageHash,
      uint256 recoveredCheckpoint,
      bytes32 recoveredOpHash
    ) = IPartialAuth(vars.wallet).recoverPartialSignature(params.payload, vars.encodedSignature);

    assertEq(recoveredThreshold, params.threshold, "Threshold mismatch");
    assertEq(recoveredWeight, vars.expectedWeight, "Weight mismatch");
    bool expectedIsValidImage = address(
      uint160(uint256(keccak256(abi.encodePacked(hex"ff", factory, recoveredImageHash, stage1Module.INIT_CODE_HASH()))))
    ) == vars.wallet;
    assertEq(recoveredIsValidImage, expectedIsValidImage, "isValidImage mismatch");
    assertEq(recoveredImageHash, vars.configHash, "ImageHash mismatch");
    assertEq(recoveredCheckpoint, params.checkpoint, "Checkpoint mismatch");
    assertEq(recoveredOpHash, vars.payloadHash, "OpHash mismatch");
  }

  struct test_invalid_is_valid_signature_params {
    bytes32 digest;
    uint16 threshold;
    uint56 checkpoint;
    uint8 weight;
    uint256 intendedPk;
    uint256 actualPk;
    bool noChainId;
  }

  struct test_invalid_is_valid_signature_vars {
    address intendedSigner;
    address actualSigner;
    string config;
    string badConfig;
    bytes32 configHash;
    address payable wallet;
    Payload.Decoded payload;
    bytes32 payloadHash;
    uint8 v;
    bytes32 r;
    bytes32 s;
    bytes encodedSignature;
  }

  function test_invalid_is_valid_signature(
    test_invalid_is_valid_signature_params memory params
  ) external {
    params.intendedPk = boundPk(params.intendedPk);
    params.actualPk = boundPk(params.actualPk);
    vm.assume(params.intendedPk != params.actualPk);
    params.threshold = uint16(bound(params.threshold, 0, type(uint8).max));
    params.weight = uint8(bound(params.weight, params.threshold, type(uint8).max));

    test_invalid_is_valid_signature_vars memory vars;
    vars.intendedSigner = vm.addr(params.intendedPk);
    vars.actualSigner = vm.addr(params.actualPk);

    string memory ce =
      string(abi.encodePacked("signer:", vm.toString(vars.intendedSigner), ":", vm.toString(params.weight)));
    vars.config = PrimitivesRPC.newConfig(vm, params.threshold, params.checkpoint, ce);
    vars.configHash = PrimitivesRPC.getImageHash(vm, vars.config);

    string memory badCe =
      string(abi.encodePacked("signer:", vm.toString(vars.actualSigner), ":", vm.toString(params.weight)));
    vars.badConfig = PrimitivesRPC.newConfig(vm, params.threshold, params.checkpoint, badCe);

    vars.wallet = payable(factory.deploy(address(stage1Module), vars.configHash));

    vars.payload.kind = Payload.KIND_DIGEST;
    vars.payload.digest = params.digest;
    vars.payload.noChainId = params.noChainId;

    vars.payloadHash = Payload.hashFor(vars.payload, vars.wallet);

    (vars.v, vars.r, vars.s) = vm.sign(params.actualPk, vars.payloadHash);

    string memory signatures = string(
      abi.encodePacked(
        vm.toString(vars.actualSigner),
        ":hash:",
        vm.toString(vars.r),
        ":",
        vm.toString(vars.s),
        ":",
        vm.toString(vars.v)
      )
    );
    vars.encodedSignature = PrimitivesRPC.toEncodedSignature(vm, vars.badConfig, signatures, !params.noChainId);

    bytes4 result = Stage1Module(vars.wallet).isValidSignature(params.digest, vars.encodedSignature);
    assertEq(
      result,
      bytes4(0),
      "isValidSignature should return 0x00000000 for invalid signature (wrong signer -> imageHash mismatch)"
    );
  }

  function test_reverts_update_to_zero_image_hash(
    uint16 _threshold,
    uint56 _checkpoint,
    uint8 _weight,
    uint256 _pk,
    bool _noChainId
  ) external {
    _threshold = uint16(bound(_threshold, 0, _weight));
    _pk = boundPk(_pk);

    address signer = vm.addr(_pk);

    string memory config;

    {
      string memory ce;
      ce = string(abi.encodePacked(ce, "signer:", vm.toString(signer), ":", vm.toString(_weight)));
      config = PrimitivesRPC.newConfig(vm, _threshold, _checkpoint, ce);
    }

    bytes32 configHash = PrimitivesRPC.getImageHash(vm, config);

    // Deploy wallet for that config
    address payable wallet = payable(factory.deploy(address(stage1Module), configHash));

    // Update configuration to zero imageHash
    Payload.Decoded memory updateConfigPayload;
    updateConfigPayload.kind = Payload.KIND_TRANSACTIONS;
    updateConfigPayload.calls = new Payload.Call[](1);
    updateConfigPayload.calls[0] = Payload.Call({
      to: address(wallet),
      value: 0,
      data: abi.encodeWithSelector(BaseAuth.updateImageHash.selector, bytes32(0)),
      gasLimit: 100000,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });
    updateConfigPayload.noChainId = _noChainId;

    // Sign the payload
    (uint256 v, bytes32 r, bytes32 s) = vm.sign(_pk, Payload.hashFor(updateConfigPayload, wallet));

    // Call updateConfig
    bytes memory updateConfigSignature = PrimitivesRPC.toEncodedSignature(
      vm,
      config,
      string(abi.encodePacked(vm.toString(signer), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v))),
      !_noChainId
    );

    // Pack payload
    bytes memory updateConfigPackedPayload = PrimitivesRPC.toPackedPayload(vm, updateConfigPayload);

    bytes memory innerRevert = abi.encodeWithSelector(Stage1Auth.ImageHashIsZero.selector);

    // Attempt to update to zero imageHash and expect revert
    vm.expectRevert(abi.encodeWithSelector(Calls.Reverted.selector, updateConfigPayload, 0, innerRevert));
    Stage1Module(wallet).execute(updateConfigPackedPayload, updateConfigSignature);
  }

  struct test_update_image_hash_twice_params {
    uint16 threshold1;
    uint56 checkpoint1;
    uint8 weight1;
    uint256 pk1;
    uint16 threshold2;
    uint56 checkpoint2;
    uint8 weight2;
    uint256 pk2;
    bool noChainId;
  }

  struct test_update_image_hash_twice_vars {
    address signer1;
    address signer2;
    string config1;
    string config2;
    string config3;
    bytes32 configHash1;
    bytes32 configHash2;
    bytes32 configHash3;
    address payable wallet;
    Payload.Decoded updateConfigPayload1;
    Payload.Decoded updateConfigPayload2;
    bytes updateConfigSignature1;
    bytes updateConfigSignature2;
    bytes updateConfigPackedPayload1;
    bytes updateConfigPackedPayload2;
  }

  function test_update_image_hash_twice(
    test_update_image_hash_twice_params memory params
  ) external {
    params.threshold1 = uint16(bound(params.threshold1, 0, params.weight1));
    params.threshold2 = uint16(bound(params.threshold2, 0, params.weight2));
    params.pk1 = boundPk(params.pk1);
    params.pk2 = boundPk(params.pk2);

    test_update_image_hash_twice_vars memory vars;
    vars.signer1 = vm.addr(params.pk1);
    vars.signer2 = vm.addr(params.pk2);

    // First config
    {
      string memory ce;
      ce = string(abi.encodePacked(ce, "signer:", vm.toString(vars.signer1), ":", vm.toString(params.weight1)));
      vars.config1 = PrimitivesRPC.newConfig(vm, params.threshold1, params.checkpoint1, ce);
    }
    vars.configHash1 = PrimitivesRPC.getImageHash(vm, vars.config1);

    // Deploy wallet with first config
    vars.wallet = payable(factory.deploy(address(stage1Module), vars.configHash1));

    // Second config
    {
      string memory ce;
      ce = string(abi.encodePacked(ce, "signer:", vm.toString(vars.signer2), ":", vm.toString(params.weight2)));
      vars.config2 = PrimitivesRPC.newConfig(vm, params.threshold2, params.checkpoint2, ce);
    }
    vars.configHash2 = PrimitivesRPC.getImageHash(vm, vars.config2);

    // First update
    vars.updateConfigPayload1.kind = Payload.KIND_TRANSACTIONS;
    vars.updateConfigPayload1.calls = new Payload.Call[](1);
    vars.updateConfigPayload1.calls[0] = Payload.Call({
      to: address(vars.wallet),
      value: 0,
      data: abi.encodeWithSelector(BaseAuth.updateImageHash.selector, vars.configHash2),
      gasLimit: 100000,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });
    vars.updateConfigPayload1.noChainId = params.noChainId;

    // Sign the first payload
    (uint256 v1, bytes32 r1, bytes32 s1) = vm.sign(params.pk1, Payload.hashFor(vars.updateConfigPayload1, vars.wallet));

    // Call first update
    vars.updateConfigSignature1 = PrimitivesRPC.toEncodedSignature(
      vm,
      vars.config1,
      string(
        abi.encodePacked(
          vm.toString(vars.signer1), ":hash:", vm.toString(r1), ":", vm.toString(s1), ":", vm.toString(v1)
        )
      ),
      !params.noChainId
    );

    // Pack first payload
    vars.updateConfigPackedPayload1 = PrimitivesRPC.toPackedPayload(vm, vars.updateConfigPayload1);

    // Execute first update
    vm.expectEmit(true, true, false, true, vars.wallet);
    emit ImageHashUpdated(vars.configHash2);
    Stage1Module(vars.wallet).execute(vars.updateConfigPackedPayload1, vars.updateConfigSignature1);

    // Verify first update worked
    assertEq(Stage1Module(vars.wallet).getImplementation(), stage1Module.STAGE_2_IMPLEMENTATION());
    assertEq(Stage2Module(vars.wallet).imageHash(), vars.configHash2);

    // Third config
    {
      string memory ce;
      ce = string(abi.encodePacked(ce, "signer:", vm.toString(vars.signer1), ":", vm.toString(params.weight1)));
      vars.config3 = PrimitivesRPC.newConfig(vm, params.threshold1, params.checkpoint1, ce);
    }
    vars.configHash3 = PrimitivesRPC.getImageHash(vm, vars.config3);

    // Second update
    vars.updateConfigPayload2.kind = Payload.KIND_TRANSACTIONS;
    vars.updateConfigPayload2.calls = new Payload.Call[](1);
    vars.updateConfigPayload2.calls[0] = Payload.Call({
      to: address(vars.wallet),
      value: 0,
      data: abi.encodeWithSelector(BaseAuth.updateImageHash.selector, vars.configHash3),
      gasLimit: 100000,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });
    vars.updateConfigPayload2.noChainId = params.noChainId;
    vars.updateConfigPayload2.nonce = 1;

    // Sign the second payload
    (uint256 v2, bytes32 r2, bytes32 s2) = vm.sign(params.pk2, Payload.hashFor(vars.updateConfigPayload2, vars.wallet));

    // Call second update
    vars.updateConfigSignature2 = PrimitivesRPC.toEncodedSignature(
      vm,
      vars.config2,
      string(
        abi.encodePacked(
          vm.toString(vars.signer2), ":hash:", vm.toString(r2), ":", vm.toString(s2), ":", vm.toString(v2)
        )
      ),
      !params.noChainId
    );

    // Pack second payload
    vars.updateConfigPackedPayload2 = PrimitivesRPC.toPackedPayload(vm, vars.updateConfigPayload2);

    // Execute second update
    vm.expectEmit(true, true, false, true, vars.wallet);
    emit ImageHashUpdated(vars.configHash3);
    Stage1Module(vars.wallet).execute(vars.updateConfigPackedPayload2, vars.updateConfigSignature2);

    // Verify second update worked
    assertEq(Stage2Module(vars.wallet).imageHash(), vars.configHash3);
  }

  struct test_update_image_hash_then_zero_params {
    uint16 threshold1;
    uint56 checkpoint1;
    uint8 weight1;
    uint256 pk1;
    uint16 threshold2;
    uint56 checkpoint2;
    uint8 weight2;
    uint256 pk2;
    bool noChainId;
  }

  struct test_update_image_hash_then_zero_vars {
    address signer1;
    address signer2;
    string config1;
    string config2;
    bytes32 configHash1;
    bytes32 configHash2;
    address payable wallet;
    Payload.Decoded updateConfigPayload1;
    Payload.Decoded updateConfigPayload2;
    bytes updateConfigSignature1;
    bytes updateConfigSignature2;
    bytes updateConfigPackedPayload1;
    bytes updateConfigPackedPayload2;
  }

  function test_update_image_hash_then_zero(
    test_update_image_hash_then_zero_params memory params
  ) external {
    params.threshold1 = uint16(bound(params.threshold1, 0, params.weight1));
    params.threshold2 = uint16(bound(params.threshold2, 0, params.weight2));
    params.pk1 = boundPk(params.pk1);
    params.pk2 = boundPk(params.pk2);

    test_update_image_hash_then_zero_vars memory vars;
    vars.signer1 = vm.addr(params.pk1);
    vars.signer2 = vm.addr(params.pk2);

    // First config
    {
      string memory ce;
      ce = string(abi.encodePacked(ce, "signer:", vm.toString(vars.signer1), ":", vm.toString(params.weight1)));
      vars.config1 = PrimitivesRPC.newConfig(vm, params.threshold1, params.checkpoint1, ce);
    }
    vars.configHash1 = PrimitivesRPC.getImageHash(vm, vars.config1);

    // Deploy wallet with first config
    vars.wallet = payable(factory.deploy(address(stage1Module), vars.configHash1));

    // Second config
    {
      string memory ce;
      ce = string(abi.encodePacked(ce, "signer:", vm.toString(vars.signer2), ":", vm.toString(params.weight2)));
      vars.config2 = PrimitivesRPC.newConfig(vm, params.threshold2, params.checkpoint2, ce);
    }
    vars.configHash2 = PrimitivesRPC.getImageHash(vm, vars.config2);

    // First update
    vars.updateConfigPayload1.kind = Payload.KIND_TRANSACTIONS;
    vars.updateConfigPayload1.calls = new Payload.Call[](1);
    vars.updateConfigPayload1.calls[0] = Payload.Call({
      to: address(vars.wallet),
      value: 0,
      data: abi.encodeWithSelector(BaseAuth.updateImageHash.selector, vars.configHash2),
      gasLimit: 100000,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });
    vars.updateConfigPayload1.noChainId = params.noChainId;

    // Sign the first payload
    (uint256 v1, bytes32 r1, bytes32 s1) = vm.sign(params.pk1, Payload.hashFor(vars.updateConfigPayload1, vars.wallet));

    // Call first update
    vars.updateConfigSignature1 = PrimitivesRPC.toEncodedSignature(
      vm,
      vars.config1,
      string(
        abi.encodePacked(
          vm.toString(vars.signer1), ":hash:", vm.toString(r1), ":", vm.toString(s1), ":", vm.toString(v1)
        )
      ),
      !params.noChainId
    );

    // Pack first payload
    vars.updateConfigPackedPayload1 = PrimitivesRPC.toPackedPayload(vm, vars.updateConfigPayload1);

    // Execute first update
    vm.expectEmit(true, true, false, true, vars.wallet);
    emit ImageHashUpdated(vars.configHash2);
    Stage1Module(vars.wallet).execute(vars.updateConfigPackedPayload1, vars.updateConfigSignature1);

    // Verify first update worked
    assertEq(Stage1Module(vars.wallet).getImplementation(), stage1Module.STAGE_2_IMPLEMENTATION());
    assertEq(Stage2Module(vars.wallet).imageHash(), vars.configHash2);

    // Second update (attempting to set to zero)
    vars.updateConfigPayload2.kind = Payload.KIND_TRANSACTIONS;
    vars.updateConfigPayload2.calls = new Payload.Call[](1);
    vars.updateConfigPayload2.calls[0] = Payload.Call({
      to: address(vars.wallet),
      value: 0,
      data: abi.encodeWithSelector(BaseAuth.updateImageHash.selector, bytes32(0)),
      gasLimit: 100000,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });
    vars.updateConfigPayload2.noChainId = params.noChainId;
    vars.updateConfigPayload2.nonce = 1;

    // Sign the second payload
    (uint256 v2, bytes32 r2, bytes32 s2) = vm.sign(params.pk2, Payload.hashFor(vars.updateConfigPayload2, vars.wallet));

    // Call second update
    vars.updateConfigSignature2 = PrimitivesRPC.toEncodedSignature(
      vm,
      vars.config2,
      string(
        abi.encodePacked(
          vm.toString(vars.signer2), ":hash:", vm.toString(r2), ":", vm.toString(s2), ":", vm.toString(v2)
        )
      ),
      !params.noChainId
    );

    // Pack second payload
    vars.updateConfigPackedPayload2 = PrimitivesRPC.toPackedPayload(vm, vars.updateConfigPayload2);

    // Attempt second update and expect revert
    bytes memory innerRevert = abi.encodeWithSelector(Stage1Auth.ImageHashIsZero.selector);
    vm.expectRevert(abi.encodeWithSelector(Calls.Reverted.selector, vars.updateConfigPayload2, 0, innerRevert));
    Stage1Module(vars.wallet).execute(vars.updateConfigPackedPayload2, vars.updateConfigSignature2);

    // Verify imageHash is still configHash2
    assertEq(Stage2Module(vars.wallet).imageHash(), vars.configHash2);
  }

  struct nested_sapient_test_params {
    Payload.Decoded payload;
    uint16 threshold;
    uint56 checkpoint;
    uint8 weight;
    uint256 pk;
    address parentWallet;
  }

  struct nested_sapient_test_vars {
    address signer;
    string config;
    bytes32 configHash;
    address wallet;
    bytes parentedSignature;
  }

  function test_recover_sapient_as_if_nested(
    nested_sapient_test_params memory params
  ) public {
    boundToLegalPayload(params.payload);
    params.threshold = uint16(bound(params.threshold, 0, params.weight));
    params.pk = boundPk(params.pk);

    nested_sapient_test_vars memory vars;

    vars.signer = vm.addr(params.pk);

    {
      string memory ce;
      ce = string(abi.encodePacked(ce, "signer:", vm.toString(vars.signer), ":", vm.toString(params.weight)));
      vars.config = PrimitivesRPC.newConfig(vm, params.threshold, params.checkpoint, ce);
    }
    vars.configHash = PrimitivesRPC.getImageHash(vm, vars.config);

    vars.wallet = payable(factory.deploy(address(stage1Module), vars.configHash));

    address[] memory nextParentWallets = new address[](params.payload.parentWallets.length + 1);
    for (uint256 i = 0; i < params.payload.parentWallets.length; i++) {
      nextParentWallets[i] = params.payload.parentWallets[i];
    }
    nextParentWallets[params.payload.parentWallets.length] = params.parentWallet;

    address[] memory prevParentWallets = params.payload.parentWallets;
    params.payload.parentWallets = nextParentWallets;

    // Sign the parented payload
    (uint256 v, bytes32 r, bytes32 s) = vm.sign(params.pk, Payload.hashFor(params.payload, vars.wallet));
    vars.parentedSignature = PrimitivesRPC.toEncodedSignature(
      vm,
      vars.config,
      string(
        abi.encodePacked(vm.toString(vars.signer), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v))
      ),
      !params.payload.noChainId
    );

    // Restore the original parentWallets
    params.payload.parentWallets = prevParentWallets;

    // Recover the parented payload
    vm.prank(params.parentWallet);
    bytes32 recovered = Stage1Auth(vars.wallet).recoverSapientSignature(params.payload, vars.parentedSignature);
    assertEq(recovered, bytes32(uint256(1)));
  }

  function test_recover_sapient_as_if_nested_wrong_signature_fail(
    nested_sapient_test_params memory params,
    uint56 _differentCheckpoint
  ) public {
    vm.assume(_differentCheckpoint != params.checkpoint);
    boundToLegalPayload(params.payload);
    params.threshold = uint16(bound(params.threshold, 0, params.weight));
    params.pk = boundPk(params.pk);

    nested_sapient_test_vars memory vars;

    vars.signer = vm.addr(params.pk);

    string memory differentCheckpointConfig;
    {
      string memory ce;
      ce = string(abi.encodePacked(ce, "signer:", vm.toString(vars.signer), ":", vm.toString(params.weight)));
      vars.config = PrimitivesRPC.newConfig(vm, params.threshold, params.checkpoint, ce);
      differentCheckpointConfig = PrimitivesRPC.newConfig(vm, params.threshold, _differentCheckpoint, ce);
    }
    vars.configHash = PrimitivesRPC.getImageHash(vm, vars.config);

    vars.wallet = payable(factory.deploy(address(stage1Module), vars.configHash));

    address[] memory nextParentWallets = new address[](params.payload.parentWallets.length + 1);
    for (uint256 i = 0; i < params.payload.parentWallets.length; i++) {
      nextParentWallets[i] = params.payload.parentWallets[i];
    }
    nextParentWallets[params.payload.parentWallets.length] = params.parentWallet;

    address[] memory prevParentWallets = params.payload.parentWallets;
    params.payload.parentWallets = nextParentWallets;

    // Sign the parented payload
    (uint256 v, bytes32 r, bytes32 s) = vm.sign(params.pk, Payload.hashFor(params.payload, vars.wallet));
    vars.parentedSignature = PrimitivesRPC.toEncodedSignature(
      vm,
      differentCheckpointConfig,
      string(
        abi.encodePacked(vm.toString(vars.signer), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v))
      ),
      !params.payload.noChainId
    );

    vm.expectRevert(
      abi.encodeWithSelector(BaseAuth.InvalidSapientSignature.selector, params.payload, vars.parentedSignature)
    );

    // Restore the original parentWallets
    params.payload.parentWallets = prevParentWallets;

    // Recover the parented payload
    vm.prank(params.parentWallet);
    Stage1Auth(vars.wallet).recoverSapientSignature(params.payload, vars.parentedSignature);
  }

  function test_forbid_reentrancy(
    uint16 _threshold,
    uint56 _checkpoint,
    uint8 _weight,
    uint256 _signerPk,
    Payload.Decoded memory _innerPayload,
    bool _outerNoChainId,
    bool _innerNoChainId
  ) external {
    CanReenter canReenter = new CanReenter();
    _weight = uint8(bound(_weight, 0, 255));
    _threshold = uint16(bound(_threshold, 0, _weight));
    _checkpoint = uint56(bound(_checkpoint, 0, type(uint56).max));
    _signerPk = boundPk(_signerPk);

    address signer = vm.addr(_signerPk);

    string memory ce;
    ce = string(abi.encodePacked(ce, "signer:", vm.toString(signer), ":", vm.toString(_weight)));
    string memory config = PrimitivesRPC.newConfig(vm, _threshold, _checkpoint, ce);

    address payable wallet = payable(factory.deploy(address(stage1Module), PrimitivesRPC.getImageHash(vm, config)));

    // Build the inner payload
    _innerPayload.noChainId = _innerNoChainId;
    _innerPayload.kind = Payload.KIND_TRANSACTIONS;
    boundToLegalPayload(_innerPayload);

    // Sign the inner payload
    (uint256 v, bytes32 r, bytes32 s) = vm.sign(_signerPk, Payload.hashFor(_innerPayload, address(wallet)));
    bytes memory innerSignature = PrimitivesRPC.toEncodedSignature(
      vm,
      config,
      string(abi.encodePacked(vm.toString(signer), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v))),
      !_innerNoChainId
    );

    // Pack the inner payload
    bytes memory innerPackedPayload = PrimitivesRPC.toPackedPayload(vm, _innerPayload);

    // Build the outer payload
    Payload.Decoded memory outerPayload;
    outerPayload.kind = Payload.KIND_TRANSACTIONS;
    outerPayload.calls = new Payload.Call[](1);
    outerPayload.calls[0] = Payload.Call({
      to: address(canReenter),
      value: 0,
      data: abi.encodeWithSelector(
        CanReenter.doAnotherCall.selector,
        address(wallet),
        abi.encodeWithSelector(Stage1Module(wallet).execute.selector, innerPackedPayload, innerSignature)
      ),
      gasLimit: 1000000,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    outerPayload.noChainId = _outerNoChainId;

    // Sign the outer payload
    (v, r, s) = vm.sign(_signerPk, Payload.hashFor(outerPayload, address(wallet)));
    bytes memory outerSignature = PrimitivesRPC.toEncodedSignature(
      vm,
      config,
      string(abi.encodePacked(vm.toString(signer), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v))),
      !_outerNoChainId
    );

    // Pack the outer payload
    bytes memory outerPackedPayload = PrimitivesRPC.toPackedPayload(vm, outerPayload);

    // Execute the outer payload
    vm.expectRevert();
    Stage1Module(wallet).execute(outerPackedPayload, outerSignature);
  }

  function test_send_many_transactions(
    uint256 _pk,
    uint8 _weight,
    uint16 _threshold,
    uint256 _checkpoint,
    uint256 _transactionCount,
    bool _noChainId
  ) external {
    _pk = boundPk(_pk);
    _weight = uint8(bound(_weight, 0, 255));
    _threshold = uint16(bound(_threshold, 0, _weight));
    _checkpoint = uint56(bound(_checkpoint, 0, type(uint56).max));
    _transactionCount = uint256(bound(_transactionCount, 2, 10));

    address signer = vm.addr(_pk);

    string memory ce;
    ce = string(abi.encodePacked(ce, "signer:", vm.toString(signer), ":", vm.toString(_weight)));
    string memory config = PrimitivesRPC.newConfig(vm, _threshold, _checkpoint, ce);

    address payable wallet = payable(factory.deploy(address(stage1Module), PrimitivesRPC.getImageHash(vm, config)));

    // Send (i + 1) wei amount of ETH to address(100 + i)
    vm.deal(wallet, 1 ether);

    for (uint256 i = 0; i < _transactionCount; i++) {
      // Construct the payload
      Payload.Decoded memory payload;
      payload.kind = Payload.KIND_TRANSACTIONS;
      payload.calls = new Payload.Call[](1);
      payload.calls[0] = Payload.Call({
        to: address(uint160(100 + i)),
        value: i + 1,
        data: bytes(""),
        gasLimit: 100000,
        delegateCall: false,
        onlyFallback: false,
        behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
      });

      payload.noChainId = _noChainId;
      payload.nonce = i;

      // Sign the payload
      (uint256 v, bytes32 r, bytes32 s) = vm.sign(_pk, Payload.hashFor(payload, address(wallet)));
      bytes memory signature = PrimitivesRPC.toEncodedSignature(
        vm,
        config,
        string(
          abi.encodePacked(vm.toString(signer), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v))
        ),
        !_noChainId
      );

      // Pack the payload
      bytes memory packedPayload = PrimitivesRPC.toPackedPayload(vm, payload);

      // Execute the payload
      (bool success,) = wallet.call{ value: i + 1 }(
        abi.encodeWithSelector(Stage1Module(wallet).execute.selector, packedPayload, signature)
      );
      assertTrue(success);

      // Verify the balance of address(100 + i)
      assertEq(address(uint160(100 + i)).balance, i + 1);
    }
  }

  receive() external payable { }

}
