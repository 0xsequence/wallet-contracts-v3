// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { ExtendedSessionTestBase } from "./ExtendedSessionTestBase.sol";
import { Vm, console } from "forge-std/Test.sol";

import { PrimitivesRPC } from "test/utils/PrimitivesRPC.sol";

import { Factory } from "src/Factory.sol";
import { Stage1Module } from "src/Stage1Module.sol";
import {
  SessionErrors, SessionManager, SessionPermissions, SessionSig
} from "src/extensions/sessions/SessionManager.sol";
import {
  ParameterOperation, ParameterRule, Permission, UsageLimit
} from "src/extensions/sessions/explicit/Permission.sol";
import { Attestation } from "src/extensions/sessions/implicit/Attestation.sol";
import { Calls } from "src/modules/Calls.sol";
import { Nonce } from "src/modules/Nonce.sol";
import { Payload } from "src/modules/Payload.sol";

/// @notice Checks for denial of service attacks on or by sessions.
contract IntegrationSessionDenialOfServiceTest is ExtendedSessionTestBase {

  using Payload for Payload.Decoded;

  function test_DOS_Wallet_SignerRace(
    uint160 space
  ) public {
    space = uint160(bound(space, 0, sessionManager.MAX_SPACE()));

    // Create wallet with sessions and EOA.
    Vm.Wallet memory eoa = vm.createWallet("eoa");
    string memory topology = _createDefaultTopology();
    bytes32 sessionImageHash = PrimitivesRPC.sessionImageHash(vm, topology);
    string memory ce = string(
      abi.encodePacked("sapient:", vm.toString(sessionImageHash), ":", vm.toString(address(sessionManager)), ":1")
    );
    ce = string(abi.encodePacked(ce, " signer:", vm.toString(eoa.addr), ":1"));
    string memory config = PrimitivesRPC.newConfig(vm, 1, 0, ce);
    bytes32 imageHash = PrimitivesRPC.getImageHash(vm, config);
    Stage1Module wallet = Stage1Module(payable(factory.deploy(address(module), imageHash)));

    // Build payload for EOA to sign
    Payload.Decoded memory payload1 = _buildPayload(1);
    payload1.calls = new Payload.Call[](1);
    payload1.calls[0].to = address(mockTarget);
    payload1.calls[0].data = "0x12345678";
    payload1.noChainId = false;
    payload1.space = space;

    // Sign it with the EOA
    bytes32 payloadHash = Payload.hashFor(payload1, address(wallet));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(eoa, payloadHash);
    string memory eoaSignatureStr = string(
      abi.encodePacked(vm.toString(eoa.addr), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v))
    );
    bytes memory eoaSignature = PrimitivesRPC.toEncodedSignature(vm, config, eoaSignatureStr, !payload1.noChainId);

    //FIXME Check it is approved without running it
    // wallet.execute(PrimitivesRPC.toPackedPayload(vm, payload1), eoaSignature);

    // Sign a payload with the same nonce to race execution
    Payload.Decoded memory payload2 = _buildPayload(1);
    payload2.calls = new Payload.Call[](1);
    payload2.calls[0].to = address(mockTarget);
    payload2.calls[0].data = "0x87654321";
    payload2.space = payload1.space;
    payload2.nonce = payload1.nonce;

    string[] memory callSignatures = new string[](1);
    bytes32 callHash = SessionSig.hashCallWithReplayProtection(payload2, 0);
    string memory callSignature = _signAndEncodeRSV(callHash, sessionWallet);
    callSignatures[0] = _explicitCallSignatureToJSON(0, callSignature);

    address[] memory explicitSigners = new address[](1);
    explicitSigners[0] = sessionWallet.addr;
    address[] memory implicitSigners = new address[](0);

    // Construct signature
    bytes memory sessionSignatures =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, explicitSigners, implicitSigners);
    string memory signatures =
      string(abi.encodePacked(vm.toString(address(sessionManager)), ":sapient:", vm.toString(sessionSignatures)));
    bytes memory sessionSignature = PrimitivesRPC.toEncodedSignature(vm, config, signatures, !payload2.noChainId);

    // Execute
    wallet.execute(PrimitivesRPC.toPackedPayload(vm, payload2), sessionSignature);

    // Check the EOA signature is not valid anymore
    vm.expectRevert(abi.encodeWithSelector(Nonce.BadNonce.selector, payload1.space, payload1.nonce, payload1.nonce + 1));
    wallet.execute(PrimitivesRPC.toPackedPayload(vm, payload1), eoaSignature);
  }

  function test_DOS_Wallet_StaticSignatureRace(
    uint160 space
  ) public {
    space = uint160(bound(space, 0, sessionManager.MAX_SPACE()));

    // Create wallet with sessions.
    string memory topology = _createDefaultTopology();
    (Stage1Module wallet, string memory config,) = _createWallet(topology);

    // Build payload for wallet to approve via static signature
    Payload.Decoded memory payload1 = _buildPayload(1);
    payload1.calls = new Payload.Call[](1);
    payload1.calls[0].to = address(mockTarget);
    payload1.calls[0].data = "0x12345678";
    payload1.noChainId = false;
    payload1.space = space;

    // Approve it
    vm.prank(address(wallet));
    wallet.setStaticSignature(payload1.hashFor(address(wallet)), identityWallet.addr, uint96(block.timestamp + 1 days));
    bytes memory staticSignature = bytes(abi.encodePacked(bytes1(0x80)));

    //FIXME Check it is approved without running it
    // vm.prank(identityWallet.addr);
    // wallet.execute(PrimitivesRPC.toPackedPayload(vm, payload1), staticSignature);

    // Sign a payload with the same nonce to race execution
    Payload.Decoded memory payload2 = _buildPayload(1);
    payload2.calls = new Payload.Call[](1);
    payload2.calls[0].to = address(mockTarget);
    payload2.calls[0].data = "0x87654321";
    payload2.space = payload1.space;
    payload2.nonce = payload1.nonce;

    string[] memory callSignatures = new string[](1);
    bytes32 callHash = SessionSig.hashCallWithReplayProtection(payload2, 0);
    string memory callSignature = _signAndEncodeRSV(callHash, sessionWallet);
    callSignatures[0] = _explicitCallSignatureToJSON(0, callSignature);

    address[] memory explicitSigners = new address[](1);
    explicitSigners[0] = sessionWallet.addr;
    address[] memory implicitSigners = new address[](0);

    // Construct signature
    bytes memory sessionSignatures =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, explicitSigners, implicitSigners);
    string memory signatures =
      string(abi.encodePacked(vm.toString(address(sessionManager)), ":sapient:", vm.toString(sessionSignatures)));
    bytes memory sessionSignature = PrimitivesRPC.toEncodedSignature(vm, config, signatures, !payload2.noChainId);

    // Execute
    wallet.execute(PrimitivesRPC.toPackedPayload(vm, payload2), sessionSignature);

    // Check the static signature is not valid anymore
    vm.expectRevert(abi.encodeWithSelector(Nonce.BadNonce.selector, payload1.space, payload1.nonce, payload1.nonce + 1));
    vm.prank(identityWallet.addr);
    wallet.execute(PrimitivesRPC.toPackedPayload(vm, payload1), staticSignature);
  }

  function test_DOS_Wallet_SpaceBlockedHighRange(
    uint160 space
  ) public {
    space = uint160(bound(space, sessionManager.MAX_SPACE() + 1, type(uint160).max));

    // Create wallet with sessions.
    string memory topology = _createDefaultTopology();
    (Stage1Module wallet, string memory config,) = _createWallet(topology);

    // Sign a payload with the same nonce to race execution
    Payload.Decoded memory payload = _buildPayload(1);
    payload.calls = new Payload.Call[](1);
    payload.calls[0].to = address(mockTarget);
    payload.calls[0].data = "0x87654321";
    payload.space = space;

    string[] memory callSignatures = new string[](1);
    bytes32 callHash = SessionSig.hashCallWithReplayProtection(payload, 0);
    string memory callSignature = _signAndEncodeRSV(callHash, sessionWallet);
    callSignatures[0] = _explicitCallSignatureToJSON(0, callSignature);

    address[] memory explicitSigners = new address[](1);
    explicitSigners[0] = sessionWallet.addr;
    address[] memory implicitSigners = new address[](0);

    // Construct signature
    bytes memory sessionSignatures =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, explicitSigners, implicitSigners);
    string memory signatures =
      string(abi.encodePacked(vm.toString(address(sessionManager)), ":sapient:", vm.toString(sessionSignatures)));
    bytes memory sessionSignature = PrimitivesRPC.toEncodedSignature(vm, config, signatures, !payload.noChainId);

    // Execute blocked
    vm.expectRevert(abi.encodeWithSelector(SessionErrors.InvalidSpace.selector, space));
    wallet.execute(PrimitivesRPC.toPackedPayload(vm, payload), sessionSignature);
  }

}
