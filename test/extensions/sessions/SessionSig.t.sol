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

  function recoverConfiguration(
    bytes calldata encoded
  ) external pure returns (SessionSig.DecodedSignature memory, bool hasBlacklist) {
    return SessionSig.recoverConfiguration(encoded);
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
    string memory callSignature;
    {
      uint8 permissionIdx = 0;
      string memory sessionSignature = _signAndEncodeRSV(Payload.hashCall(payload.calls[0]), sessionWallet);
      callSignature = _explicitCallSignatureToJSON(permissionIdx, sessionSignature);
    }

    // Construct the encoded signature.
    bytes memory encoded;
    {
      string[] memory callSignatures = new string[](1);
      callSignatures[0] = callSignature;
      address[] memory explicitSigners = new address[](1);
      explicitSigners[0] = sessionWallet.addr;
      address[] memory implicitSigners = new address[](0);
      encoded =
        PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, explicitSigners, implicitSigners);
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

      bytes32 imageHash = PrimitivesRPC.sessionImageHash(vm, topology);
      assertEq(sig.imageHash, imageHash, "Image hash");
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
      address[] memory explicitSigners = new address[](0);
      address[] memory implicitSigners = new address[](1);
      implicitSigners[0] = sessionWallet.addr;
      encoded =
        PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, explicitSigners, implicitSigners);
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

      bytes32 imageHash = PrimitivesRPC.sessionImageHash(vm, topology);
      assertEq(sig.imageHash, imageHash, "Image hash");
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
      address[] memory explicitSigners = new address[](0);
      address[] memory implicitSigners = new address[](1);
      implicitSigners[0] = sessionWallet.addr;
      encoded =
        PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, explicitSigners, implicitSigners);
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

      bytes32 imageHash = PrimitivesRPC.sessionImageHash(vm, topology);
      assertEq(sig.imageHash, imageHash, "Image hash");
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
    string[] memory callSignatures = new string[](2);
    {
      // First call signed by sessionWallet
      string memory sessionSignature1 = _signAndEncodeRSV(Payload.hashCall(payload.calls[0]), sessionWallet);
      callSignatures[0] = _explicitCallSignatureToJSON(0, sessionSignature1);

      // Second call signed by sessionWallet2
      string memory sessionSignature2 = _signAndEncodeRSV(Payload.hashCall(payload.calls[1]), sessionWallet2);
      callSignatures[1] = _explicitCallSignatureToJSON(1, sessionSignature2);
    }

    // Construct the encoded signature
    bytes memory encoded;
    {
      address[] memory explicitSigners = new address[](2);
      explicitSigners[0] = sessionWallet.addr;
      explicitSigners[1] = sessionWallet2.addr;
      address[] memory implicitSigners = new address[](0);
      encoded =
        PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, explicitSigners, implicitSigners);
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

      bytes32 imageHash = PrimitivesRPC.sessionImageHash(vm, topology);
      assertEq(sig.imageHash, imageHash, "Image hash");
    }
  }

  function testLargeTopology(
    address[] memory explicitSigners,
    uint256 signersIncludeCount,
    bool includeImplicitSigner,
    address[] memory implicitBlacklist
  ) public {
    // Reduce size to max 20
    if (explicitSigners.length > 20) {
      assembly {
        mstore(explicitSigners, 20)
      }
    }
    for (uint256 i = 0; i < explicitSigners.length; i++) {
      vm.assume(explicitSigners[i] != address(0));
      // Ensure there are no duplicates.
      for (uint256 j = 0; j < explicitSigners.length; j++) {
        if (i != j) {
          vm.assume(explicitSigners[i] != explicitSigners[j]);
        }
      }
    }
    if (implicitBlacklist.length > 5) {
      assembly {
        mstore(implicitBlacklist, 5)
      }
    }
    // Ensure no duplicates for the implicit blacklist
    for (uint256 i = 0; i < implicitBlacklist.length; i++) {
      for (uint256 j = 0; j < implicitBlacklist.length; j++) {
        if (i != j) {
          vm.assume(implicitBlacklist[i] != implicitBlacklist[j]);
        }
      }
    }
    signersIncludeCount = bound(signersIncludeCount, 0, explicitSigners.length);

    // Add session permissions and blacklist to the topology
    SessionPermissions memory sessionPerms;
    string memory topology = PrimitivesRPC.sessionEmpty(vm, globalWallet.addr);
    for (uint256 i = 0; i < explicitSigners.length; i++) {
      sessionPerms.signer = explicitSigners[i];
      string memory sessionPermsJson = _sessionPermissionsToJSON(sessionPerms);
      topology = PrimitivesRPC.sessionExplicitAdd(vm, sessionPermsJson, topology);
    }
    for (uint256 i = 0; i < implicitBlacklist.length; i++) {
      topology = PrimitivesRPC.sessionImplicitAddBlacklistAddress(vm, topology, implicitBlacklist[i]);
    }

    // Set signers to include in the configuration
    assembly {
      mstore(explicitSigners, signersIncludeCount)
    }
    address[] memory implicitSigners = new address[](includeImplicitSigner ? 1 : 0);
    if (includeImplicitSigner) {
      implicitSigners[0] = sessionWallet.addr;
    }
    // Call encodeCallSignatures with empty call signatures to encode the topology
    bytes memory encoded =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, new string[](0), explicitSigners, implicitSigners);
    assertGt(encoded.length, 4, "Encoded signature should not be empty");

    // Strip the first 3 bytes (size), and last byte (attestation count)
    bytes memory encodedWithoutSize = new bytes(encoded.length - 4);
    for (uint256 i = 0; i < encodedWithoutSize.length; i++) {
      encodedWithoutSize[i] = encoded[i + 3];
    }

    // Recover the configuration
    (SessionSig.DecodedSignature memory sig, bool hasBlacklist) = harness.recoverConfiguration(encodedWithoutSize);
    assertEq(sig.globalSigner, globalWallet.addr, "Global signer");
    assertEq(sig.sessionPermissions.length, explicitSigners.length, "Session permissions length"); // Truncated list
    for (uint256 i = 0; i < explicitSigners.length; i++) {
      bool found = false;
      for (uint256 j = 0; j < sig.sessionPermissions.length; j++) {
        if (sig.sessionPermissions[j].signer == explicitSigners[i]) {
          found = true;
          break;
        }
      }
      assertTrue(found, "Session permission signer not found");
    }
    if (includeImplicitSigner) {
      assertEq(hasBlacklist, includeImplicitSigner, "Blacklist not included with implicit signer");
      assertEq(sig.implicitBlacklist.length, implicitBlacklist.length, "Implicit blacklist length");
      for (uint256 i = 0; i < implicitBlacklist.length; i++) {
        bool found = false;
        for (uint256 j = 0; j < sig.implicitBlacklist.length; j++) {
          if (sig.implicitBlacklist[j] == implicitBlacklist[i]) {
            found = true;
            break;
          }
        }
        assertTrue(found, "Implicit blacklist address not found");
      }
    }
  }

  function testAttestationOptimisation() public {
    // Create a payload with 2 calls
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

    // Create a second session wallet
    Vm.Wallet memory sessionWallet2 = vm.createWallet("session2");

    // Create 2 attestations
    Attestation memory attestation1 = Attestation({
      approvedSigner: sessionWallet.addr,
      identityType: bytes4(0),
      issuerHash: bytes32(0),
      audienceHash: bytes32(0),
      authData: bytes(""),
      applicationData: bytes("")
    });
    Attestation memory attestation2 = Attestation({
      approvedSigner: sessionWallet2.addr,
      identityType: bytes4(0),
      issuerHash: bytes32(0),
      audienceHash: bytes32(0),
      authData: bytes(""),
      applicationData: bytes("")
    });

    // Create 2 call signatures for the same session wallet and attestation
    string memory callSignatureA =
      _createImplicitCallSignature(payload.calls[0], sessionWallet, globalWallet, attestation1);
    string memory callSignatureB =
      _createImplicitCallSignature(payload.calls[1], sessionWallet, globalWallet, attestation1);

    // Create the second call signature for the second session wallet and attestation
    string memory callSignatureC =
      _createImplicitCallSignature(payload.calls[1], sessionWallet2, globalWallet, attestation2);

    // Create a topology
    string memory topology = PrimitivesRPC.sessionEmpty(vm, globalWallet.addr);

    // Encode the call signatures for single session wallet
    address[] memory implicitSigners = new address[](1);
    implicitSigners[0] = sessionWallet.addr;
    string[] memory callSignatures = new string[](2);
    callSignatures[0] = callSignatureA;
    callSignatures[1] = callSignatureB;
    bytes memory encoded =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, new address[](0), implicitSigners);

    // Encode the call signatures for both session wallets
    implicitSigners = new address[](2);
    implicitSigners[0] = sessionWallet.addr;
    implicitSigners[1] = sessionWallet2.addr;
    callSignatures = new string[](2);
    callSignatures[0] = callSignatureA;
    callSignatures[1] = callSignatureC;
    bytes memory encoded2 =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, new address[](0), implicitSigners);

    // Ensure the length of the calldata has been optimised when reusing the same attestation
    assertLt(
      encoded.length, encoded2.length, "Encoded call signatures should be shorter when reusing the same attestation"
    );
  }

}
