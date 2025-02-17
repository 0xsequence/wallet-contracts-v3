// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Vm } from "forge-std/Test.sol";
import { SessionTestBase } from "test/extensions/sessions/SessionTestBase.sol";
import { PrimitivesRPC } from "test/utils/PrimitivesRPC.sol";

import { SessionSig } from "src/extensions/sessions/SessionSig.sol";
import { SessionPermissions } from "src/extensions/sessions/explicit/IExplicitSessionManager.sol";
import { ParameterOperation, ParameterRule, Permission } from "src/extensions/sessions/explicit/Permission.sol";

import { Attestation, LibAttestation } from "src/extensions/sessions/implicit/Attestation.sol";
import { Payload } from "src/modules/Payload.sol";

using LibAttestation for Attestation;

contract SessionSigHarness {

  function recover(
    Payload.Decoded calldata payload,
    bytes calldata signature
  ) external pure returns (SessionSig.DecodedSignature memory) {
    return SessionSig.recoverSignature(payload, signature);
  }

}

contract SessionSigTest is SessionTestBase {

  SessionSigHarness internal harness;
  Vm.Wallet internal sessionWallet;
  Vm.Wallet internal globalWallet;

  function setUp() public {
    harness = new SessionSigHarness();
    sessionWallet = vm.createWallet("session");
    globalWallet = vm.createWallet("global");
  }

  // -------------------------------------------------------------------------
  // TESTS
  // -------------------------------------------------------------------------

  /// @notice Tests the case for an explicit call signature.
  function testSingleExplicitSignature() public {
    Payload.Decoded memory payload = _buildPayload(1);
    {
      payload.calls[0] = Payload.Call({
        to: address(0xBEEF),
        value: 123,
        data: "test",
        gasLimit: 0,
        delegateCall: false,
        onlyFallback: false,
        behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
      });
    }
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr,
      valueLimit: 1000,
      deadline: 2000,
      permissions: new Permission[](1)
    });
    {
      sessionPerms.permissions[0] = Permission({ target: address(0xBEEF), rules: new ParameterRule[](1) });
      sessionPerms.permissions[0].rules[0] = ParameterRule({
        cumulative: false,
        operation: ParameterOperation.EQUAL,
        value: bytes32(0),
        offset: 0,
        mask: bytes32(0)
      });
    }

    // Create the topology from the CLI.
    string memory topology;
    {
      topology = PrimitivesRPC.sessionEmpty(vm, globalWallet.addr);
      string memory sessionPermsJson = _sessionPermissionsToJSON(sessionPerms);
      topology = PrimitivesRPC.sessionExplicitAdd(vm, sessionPermsJson, topology);
    }

    // Sign the payload.
    bytes memory callSignature;
    {
      uint8 permissionIdx = 0;
      string memory sessionSignature = _signAndEncodeRSV(Payload.hashCall(payload.calls[0]), sessionWallet);
      callSignature = PrimitivesRPC.sessionExplicitEncodeCallSignature(vm, sessionSignature, permissionIdx);
    }

    // Construct the encoded signature.
    bytes memory encoded;
    {
      string[] memory callSignatures = new string[](1);
      callSignatures[0] = vm.toString(callSignature);
      encoded = PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, false);
    }

    // Recover and validate.
    {
      SessionSig.DecodedSignature memory sig = harness.recover(payload, encoded);
      assertEq(sig.callSignatures.length, 1, "Call signatures length");
      SessionSig.CallSignature memory callSig = sig.callSignatures[0];
      assertFalse(callSig.isImplicit, "Call should be explicit");
      assertEq(callSig.sessionSigner, sessionWallet.addr, "Recovered session signer");
      assertEq(sig.implicitBlacklist.length, 0, "Blacklist should be empty");
      assertEq(sig.sessionPermissions.length, 1, "Session permissions length");
      assertEq(sig.sessionPermissions[0].signer, sessionWallet.addr, "Session permission signer");
    }
  }

  function testSingleImplicitSignature() public {
    Payload.Decoded memory payload = _buildPayload(1);
    {
      payload.calls[0] = Payload.Call({
        to: address(0xBEEF),
        value: 123,
        data: "test",
        gasLimit: 0,
        delegateCall: false,
        onlyFallback: false,
        behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
      });
    }

    // Create attestation.
    Attestation memory attestation;
    {
      attestation = Attestation({
        approvedSigner: sessionWallet.addr,
        identityType: bytes4(0),
        issuerHash: bytes32(0),
        audienceHash: bytes32(0),
        authData: bytes(""),
        applicationData: bytes("")
      });
    }

    // Sign the payload.
    string memory callSignature =
      _createImplicitCallSignature(payload.calls[0], sessionWallet, globalWallet, attestation);

    // Create the topology from the CLI.
    string memory topology;
    {
      topology = PrimitivesRPC.sessionEmpty(vm, globalWallet.addr);
    }

    // Create the encoded signature.
    bytes memory encoded;
    {
      string[] memory callSignatures = new string[](1);
      callSignatures[0] = callSignature;
      encoded = PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, true);
    }

    // Recover and validate.
    {
      SessionSig.DecodedSignature memory sig = harness.recover(payload, encoded);
      assertEq(sig.callSignatures.length, 1, "Call signatures length");
      SessionSig.CallSignature memory callSig = sig.callSignatures[0];
      assertTrue(callSig.isImplicit, "Call should be implicit");
      assertEq(callSig.attestation.approvedSigner, sessionWallet.addr, "Recovered attestation signer");
      assertEq(sig.implicitBlacklist.length, 0, "Blacklist should be empty");
      assertEq(sig.sessionPermissions.length, 0, "Session permissions should be empty");
    }
  }

  function testMultipleImplicitSignatures() public {
    Payload.Decoded memory payload = _buildPayload(2);
    {
      payload.calls[0] = Payload.Call({
        to: address(0xBEEF),
        value: 123,
        data: "test1",
        gasLimit: 0,
        delegateCall: false,
        onlyFallback: false,
        behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
      });

      payload.calls[1] = Payload.Call({
        to: address(0xCAFE),
        value: 456,
        data: "test2",
        gasLimit: 0,
        delegateCall: false,
        onlyFallback: false,
        behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
      });
    }

    Attestation memory attestation = Attestation({
      approvedSigner: sessionWallet.addr,
      identityType: bytes4(0),
      issuerHash: bytes32(0),
      audienceHash: bytes32(0),
      authData: bytes(""),
      applicationData: bytes("")
    });

    // Create attestations and signatures for both calls
    string[] memory callSignatures = new string[](2);
    {
      callSignatures[0] = _createImplicitCallSignature(payload.calls[0], sessionWallet, globalWallet, attestation);
      callSignatures[1] = _createImplicitCallSignature(payload.calls[1], sessionWallet, globalWallet, attestation);
    }

    // Create the topology
    string memory topology = PrimitivesRPC.sessionEmpty(vm, globalWallet.addr);

    // Create the encoded signature
    bytes memory encoded;
    {
      encoded = PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, true);
    }

    // Recover and validate
    {
      SessionSig.DecodedSignature memory sig = harness.recover(payload, encoded);
      assertEq(sig.callSignatures.length, 2, "Call signatures length");

      for (uint256 i = 0; i < sig.callSignatures.length; i++) {
        SessionSig.CallSignature memory callSig = sig.callSignatures[i];
        assertTrue(callSig.isImplicit, "Call should be implicit");
        assertEq(callSig.attestation.approvedSigner, sessionWallet.addr, "Recovered attestation signer");
      }

      assertEq(sig.implicitBlacklist.length, 0, "Blacklist should be empty");
      assertEq(sig.sessionPermissions.length, 0, "Session permissions should be empty");
    }
  }

  /// @notice Tests the case for multiple explicit call signatures with different signers.
  function testMultipleExplicitSignatures() public {
    // Create a second session wallet
    Vm.Wallet memory sessionWallet2 = vm.createWallet("session2");

    Payload.Decoded memory payload = _buildPayload(2);
    {
      payload.calls[0] = Payload.Call({
        to: address(0xBEEF),
        value: 123,
        data: "test1",
        gasLimit: 0,
        delegateCall: false,
        onlyFallback: false,
        behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
      });

      payload.calls[1] = Payload.Call({
        to: address(0xCAFE),
        value: 456,
        data: "test2",
        gasLimit: 0,
        delegateCall: false,
        onlyFallback: false,
        behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
      });
    }

    // Create session permissions for both calls with different signers
    SessionPermissions[] memory sessionPermsArray = new SessionPermissions[](2);
    {
      sessionPermsArray[0] = _createSessionPermissions(address(0xBEEF), 1000, 2000, sessionWallet.addr);
      sessionPermsArray[1] = _createSessionPermissions(address(0xCAFE), 1000, 2000, sessionWallet2.addr);
    }

    // Create the topology from the CLI
    string memory topology;
    {
      topology = PrimitivesRPC.sessionEmpty(vm, globalWallet.addr);
      for (uint256 i = 0; i < sessionPermsArray.length; i++) {
        string memory sessionPermsJson = _sessionPermissionsToJSON(sessionPermsArray[i]);
        topology = PrimitivesRPC.sessionExplicitAdd(vm, sessionPermsJson, topology);
      }
    }

    // Sign the payloads and create call signatures with different signers
    bytes[] memory callSignatures = new bytes[](2);
    {
      // First call signed by sessionWallet
      string memory sessionSignature1 = _signAndEncodeRSV(Payload.hashCall(payload.calls[0]), sessionWallet);
      callSignatures[0] = PrimitivesRPC.sessionExplicitEncodeCallSignature(vm, sessionSignature1, 0);

      // Second call signed by sessionWallet2
      string memory sessionSignature2 = _signAndEncodeRSV(Payload.hashCall(payload.calls[1]), sessionWallet2);
      callSignatures[1] = PrimitivesRPC.sessionExplicitEncodeCallSignature(vm, sessionSignature2, 1);
    }

    // Construct the encoded signature
    bytes memory encoded;
    {
      string[] memory callSignaturesStr = new string[](2);
      for (uint256 i = 0; i < callSignatures.length; i++) {
        callSignaturesStr[i] = vm.toString(callSignatures[i]);
      }
      encoded = PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignaturesStr, false);
    }

    // Recover and validate
    {
      SessionSig.DecodedSignature memory sig = harness.recover(payload, encoded);
      assertEq(sig.callSignatures.length, 2, "Call signatures length");

      // Verify first signature
      assertFalse(sig.callSignatures[0].isImplicit, "First call should be explicit");
      assertEq(sig.callSignatures[0].sessionSigner, sessionWallet.addr, "First session signer");

      // Verify second signature
      assertFalse(sig.callSignatures[1].isImplicit, "Second call should be explicit");
      assertEq(sig.callSignatures[1].sessionSigner, sessionWallet2.addr, "Second session signer");

      assertEq(sig.implicitBlacklist.length, 0, "Blacklist should be empty");
      assertEq(sig.sessionPermissions.length, 2, "Session permissions length");
      assertEq(sig.sessionPermissions[1].signer, sessionWallet.addr, "Session permission signer 0");
      assertEq(sig.sessionPermissions[0].signer, sessionWallet2.addr, "Session permission signer 1");
    }
  }

}
