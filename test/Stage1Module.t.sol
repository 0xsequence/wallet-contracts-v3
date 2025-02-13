// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Factory } from "../src/Factory.sol";
import { Stage1Module } from "../src/Stage1Module.sol";
import { Stage2Module } from "../src/Stage2Module.sol";

import { Payload } from "../src/modules/Payload.sol";

import { BaseAuth } from "../src/modules/auth/BaseAuth.sol";
import { PrimitivesRPC } from "./utils/PrimitivesRPC.sol";
import { AdvTest } from "./utils/TestUtils.sol";

contract TestStage1Module is AdvTest {

  Factory public factory = new Factory();
  Stage1Module public stage1Module = new Stage1Module(address(factory));

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
    address wallet = factory.deploy(address(stage1Module), configHash);

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
    assertEq(result, bytes4(0x20c13b0b));
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
    address wallet = factory.deploy(address(stage1Module), vars.ogConfigHash);

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
    assertEq(result, bytes4(0x20c13b0b));
  }

}
