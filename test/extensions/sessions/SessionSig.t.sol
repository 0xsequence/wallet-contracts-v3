// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Vm } from "forge-std/Test.sol";
import { SessionTestBase } from "test/extensions/sessions/SessionTestBase.sol";
import { PrimitivesRPC } from "test/utils/PrimitivesRPC.sol";

import { SessionErrors } from "src/extensions/sessions/SessionErrors.sol";
import { SessionSig } from "src/extensions/sessions/SessionSig.sol";
import { SessionPermissions } from "src/extensions/sessions/explicit/IExplicitSessionManager.sol";
import { ParameterOperation, ParameterRule, Permission } from "src/extensions/sessions/explicit/Permission.sol";

import { Attestation, AuthData, LibAttestation } from "src/extensions/sessions/implicit/Attestation.sol";
import { Payload } from "src/modules/Payload.sol";

using LibAttestation for Attestation;

contract SessionSigHarness {

  function recover(
    Payload.Decoded calldata payload,
    bytes calldata signature
  ) external view returns (SessionSig.DecodedSignature memory) {
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
  Vm.Wallet internal identityWallet;

  function setUp() public {
    harness = new SessionSigHarness();
    sessionWallet = vm.createWallet("session");
    identityWallet = vm.createWallet("identity");
  }

  function testHashCallCollision(
    uint256 chainId,
    Payload.Decoded memory payload1,
    Payload.Decoded memory payload2
  ) public {
    vm.assume(payload1.calls.length > 0);
    vm.assume(payload2.calls.length > 0);
    chainId = bound(chainId, 1, 2 ** 26 - 1);
    vm.chainId(chainId);

    uint256 maxCalls = 10;

    if (payload1.calls.length > maxCalls) {
      Payload.Call[] memory payload1Calls = payload1.calls;
      assembly {
        mstore(payload1Calls, maxCalls)
      }
      payload1.calls = payload1Calls;
    }

    if (payload2.calls.length > maxCalls) {
      Payload.Call[] memory payload2Calls = payload2.calls;
      assembly {
        mstore(payload2Calls, maxCalls)
      }
      payload2.calls = payload2Calls;
    }

    for (uint256 i = 0; i < payload1.calls.length; i++) {
      Payload.Call memory call1 = payload1.calls[i];
      for (uint256 j = 0; j < payload2.calls.length; j++) {
        Payload.Call memory call2 = payload2.calls[j];

        if (
          i == j && call1.to == call2.to && keccak256(call1.data) == keccak256(call2.data)
            && call1.gasLimit == call2.gasLimit && call1.delegateCall == call2.delegateCall
            && call1.onlyFallback == call2.onlyFallback && call1.behaviorOnError == call2.behaviorOnError
            && payload1.space == payload2.space && payload1.nonce == payload2.nonce
            && payload1.noChainId == payload2.noChainId
        ) {
          // The allowed collision case
          continue;
        }

        bytes32 callHash1 = SessionSig.hashCallWithReplayProtection(payload1, i);
        bytes32 callHash2 = SessionSig.hashCallWithReplayProtection(payload2, j);
        assertNotEq(callHash1, callHash2, "Call hashes should be different");
      }
    }
  }

  function testSingleExplicitSignature(
    bool useChainId
  ) public {
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
      chainId: useChainId ? block.chainid : 0,
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
      topology = PrimitivesRPC.sessionEmpty(vm, identityWallet.addr);
      string memory sessionPermsJson = _sessionPermissionsToJSON(sessionPerms);
      topology = PrimitivesRPC.sessionExplicitAdd(vm, sessionPermsJson, topology);
    }

    // Sign the payload.
    string memory callSignature;
    {
      uint8 permissionIdx = 0;
      bytes32 callHash = SessionSig.hashCallWithReplayProtection(payload, 0);
      string memory sessionSignature = _signAndEncodeRSV(callHash, sessionWallet);
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

  function testSingleImplicitSignature(
    Attestation memory attestation
  ) public {
    attestation.approvedSigner = sessionWallet.addr;
    attestation.authData.redirectUrl = "https://example.com"; // Normalise for safe JSONify
    attestation.authData.issuedAt = uint64(bound(attestation.authData.issuedAt, 0, block.timestamp));

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

    // Sign the payload.
    string memory callSignature = _createImplicitCallSignature(payload, 0, sessionWallet, identityWallet, attestation);

    // Create the topology from the CLI.
    string memory topology;
    {
      topology = PrimitivesRPC.sessionEmpty(vm, identityWallet.addr);
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

  function testMultipleImplicitSignatures(
    Attestation memory attestation
  ) public {
    attestation.approvedSigner = sessionWallet.addr;
    attestation.authData.redirectUrl = "https://example.com"; // Normalise for safe JSONify
    attestation.authData.issuedAt = uint64(bound(attestation.authData.issuedAt, 0, block.timestamp));

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

    // Create attestations and signatures for both calls
    string[] memory callSignatures = new string[](2);
    {
      callSignatures[0] = _createImplicitCallSignature(payload, 0, sessionWallet, identityWallet, attestation);
      callSignatures[1] = _createImplicitCallSignature(payload, 1, sessionWallet, identityWallet, attestation);
    }

    // Create the topology
    string memory topology = PrimitivesRPC.sessionEmpty(vm, identityWallet.addr);

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

  function testMultipleExplicitSignatures(
    bool useChainId
  ) public {
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
      sessionPermsArray[0] =
        _createSessionPermissions(address(0xBEEF), useChainId ? block.chainid : 0, 1000, 2000, sessionWallet.addr);
      sessionPermsArray[1] =
        _createSessionPermissions(address(0xCAFE), useChainId ? block.chainid : 0, 1000, 2000, sessionWallet2.addr);
    }

    // Create the topology from the CLI
    string memory topology;
    {
      topology = PrimitivesRPC.sessionEmpty(vm, identityWallet.addr);
      for (uint256 i = 0; i < sessionPermsArray.length; i++) {
        string memory sessionPermsJson = _sessionPermissionsToJSON(sessionPermsArray[i]);
        topology = PrimitivesRPC.sessionExplicitAdd(vm, sessionPermsJson, topology);
      }
    }

    // Sign the payloads and create call signatures with different signers
    string[] memory callSignatures = new string[](2);
    {
      // First call signed by sessionWallet
      bytes32 callHash = SessionSig.hashCallWithReplayProtection(payload, 0);
      string memory sessionSignature1 = _signAndEncodeRSV(callHash, sessionWallet);
      callSignatures[0] = _explicitCallSignatureToJSON(0, sessionSignature1);

      // Second call signed by sessionWallet2
      callHash = SessionSig.hashCallWithReplayProtection(payload, 1);
      string memory sessionSignature2 = _signAndEncodeRSV(callHash, sessionWallet2);
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
      bool found0 = false;
      bool found1 = false;
      for (uint256 i = 0; i < sig.sessionPermissions.length; i++) {
        if (sig.sessionPermissions[i].signer == sessionWallet.addr) {
          found0 = true;
        }
        if (sig.sessionPermissions[i].signer == sessionWallet2.addr) {
          found1 = true;
        }
      }
      assertTrue(found0, "Session permission signer 0 not found");
      assertTrue(found1, "Session permission signer 1 not found");

      bytes32 imageHash = PrimitivesRPC.sessionImageHash(vm, topology);
      assertEq(sig.imageHash, imageHash, "Image hash");
    }
  }

  function testRecover_invalidSessionSigner(
    bool useChainId
  ) public {
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
      chainId: useChainId ? block.chainid : 0,
      valueLimit: 1000,
      deadline: 2000,
      permissions: new Permission[](1)
    });
    sessionPerms.permissions[0] = Permission({ target: address(0xBEEF), rules: new ParameterRule[](0) });

    // Create the topology from the CLI.
    string memory topology;
    {
      topology = PrimitivesRPC.sessionEmpty(vm, identityWallet.addr);
      string memory sessionPermsJson = _sessionPermissionsToJSON(sessionPerms);
      topology = PrimitivesRPC.sessionExplicitAdd(vm, sessionPermsJson, topology);
    }

    // Generate an invalid session signature
    string memory sessionSignature =
      "0x0000000000000000000000000000000000000000000000000000000000000000:0x0000000000000000000000000000000000000000000000000000000000000000:0";
    string memory callSignature = _explicitCallSignatureToJSON(0, sessionSignature);

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
    vm.expectRevert(abi.encodeWithSelector(SessionErrors.InvalidSessionSigner.selector, address(0)));
    harness.recover(payload, encoded);
  }

  function testRecover_invalidIdentitySigner_unset() public {
    // Create a topology with an invalid identity signer
    string memory topology = PrimitivesRPC.sessionEmpty(vm, address(0));
    Payload.Decoded memory payload = _buildPayload(1);
    payload.calls[0] = Payload.Call({
      to: address(0xBEEF),
      value: 123,
      data: "test",
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Create a call signature
    bytes memory encoded =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, new string[](0), new address[](0), new address[](0));

    // Recover the signature
    vm.expectRevert(SessionErrors.InvalidIdentitySigner.selector);
    harness.recover(payload, encoded);
  }

  function testRecover_invalidIdentitySigner_noMatchAttestationSigner(
    Attestation memory attestation
  ) public {
    attestation.approvedSigner = sessionWallet.addr;
    attestation.authData.redirectUrl = "https://example.com"; // Normalise for safe JSONify
    attestation.authData.issuedAt = uint64(bound(attestation.authData.issuedAt, 0, block.timestamp));

    // Create a topology with an invalid identity signer
    string memory topology = PrimitivesRPC.sessionEmpty(vm, identityWallet.addr);
    Payload.Decoded memory payload = _buildPayload(1);
    payload.calls[0] = Payload.Call({
      to: address(0xBEEF),
      value: 123,
      data: "test",
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    Vm.Wallet memory attestationWallet = vm.createWallet("attestation");

    // Sign the payload.
    string memory callSignature =
      _createImplicitCallSignature(payload, 0, sessionWallet, attestationWallet, attestation);

    // Create a call signature
    string[] memory callSignatures = new string[](1);
    callSignatures[0] = callSignature;
    address[] memory implicitSigners = new address[](1);
    implicitSigners[0] = sessionWallet.addr;
    bytes memory encoded =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, new address[](0), implicitSigners);

    // Recover the signature
    vm.expectRevert(SessionErrors.InvalidIdentitySigner.selector);
    harness.recover(payload, encoded);
  }

  function testRecover_invalidIdentitySigner_noSignersEncoded(
    Attestation memory attestation
  ) public {
    attestation.approvedSigner = sessionWallet.addr;
    attestation.authData.redirectUrl = "https://example.com"; // Normalise for safe JSONify
    attestation.authData.issuedAt = uint64(bound(attestation.authData.issuedAt, 0, block.timestamp));

    // Create a topology with an invalid identity signer
    string memory topology = PrimitivesRPC.sessionEmpty(vm, address(0));
    Payload.Decoded memory payload = _buildPayload(1);
    payload.calls[0] = Payload.Call({
      to: address(0xBEEF),
      value: 123,
      data: "test",
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    Vm.Wallet memory attestationWallet = vm.createWallet("attestation");

    // Sign the payload.
    string memory callSignature =
      _createImplicitCallSignature(payload, 0, sessionWallet, attestationWallet, attestation);

    // Create a call signature
    string[] memory callSignatures = new string[](1);
    callSignatures[0] = callSignature;
    bytes memory encoded =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, new address[](0), new address[](0));

    // Recover the signature
    vm.expectRevert(SessionErrors.InvalidIdentitySigner.selector);
    harness.recover(payload, encoded);
  }

  function testRecover_invalidBlacklist_requiredForImplicitSigner(
    Attestation memory attestation
  ) public {
    attestation.approvedSigner = sessionWallet.addr;
    attestation.authData.redirectUrl = "https://example.com"; // Normalise for safe JSONify
    attestation.authData.issuedAt = uint64(bound(attestation.authData.issuedAt, 0, block.timestamp));

    string memory topology = PrimitivesRPC.sessionEmpty(vm, identityWallet.addr);
    Payload.Decoded memory payload = _buildPayload(1);
    payload.calls[0] = Payload.Call({
      to: address(0xBEEF),
      value: 123,
      data: "test",
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Call encodeCallSignatures with empty call signatures to encode the topology
    bytes memory encodedTopologyWithSize =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, new string[](0), new address[](0), new address[](0));
    assertGt(encodedTopologyWithSize.length, 4, "Encoded signature should not be empty");

    // Strip the last byte (attestation count)
    bytes memory encoded = new bytes(encodedTopologyWithSize.length - 1);
    for (uint256 i = 0; i < encoded.length; i++) {
      encoded[i] = encodedTopologyWithSize[i];
    }

    // Encode the attestation and signature
    bytes32 attestationHash = attestation.toHash();
    bytes memory compactSignature = signRSVCompact(attestationHash, identityWallet);
    encoded = abi.encodePacked(encoded, uint8(1), LibAttestation.toPacked(attestation), compactSignature);

    // We don't bother encoding the call signatures as will fail before then

    // Recover the signature
    vm.expectRevert(SessionErrors.InvalidBlacklist.selector);
    harness.recover(payload, encoded);
  }

  function testRecover_invalidAttestationIndex(Attestation memory attestation, uint256 count, uint256 index) public {
    attestation.approvedSigner = sessionWallet.addr;
    attestation.authData.redirectUrl = "https://example.com"; // Normalise for safe JSONify
    count = bound(count, 1, 10);
    index = bound(index, count + 1, type(uint8).max / 2); // /2 as top bit used in flag

    string memory topology = PrimitivesRPC.sessionEmpty(vm, identityWallet.addr);
    Payload.Decoded memory payload = _buildPayload(1);
    payload.calls[0] = Payload.Call({
      to: address(0xBEEF),
      value: 123,
      data: "test",
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Call encodeCallSignatures with empty call signatures to encode the topology
    address[] memory implicitSigners = new address[](1);
    implicitSigners[0] = sessionWallet.addr;
    bytes memory encodedTopologyWithSize =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, new string[](0), new address[](0), implicitSigners);
    assertGt(encodedTopologyWithSize.length, 4, "Encoded signature should not be empty");

    // Strip the last byte (attestation count)
    bytes memory encoded = new bytes(encodedTopologyWithSize.length - 1);
    for (uint256 i = 0; i < encoded.length; i++) {
      encoded[i] = encodedTopologyWithSize[i];
    }

    // Encode the attestations and signatures
    bytes32 attestationHash = attestation.toHash();
    bytes memory compactSignature = signRSVCompact(attestationHash, identityWallet);
    encoded = abi.encodePacked(encoded, uint8(count));
    for (uint256 i = 0; i < count; i++) {
      encoded = abi.encodePacked(encoded, LibAttestation.toPacked(attestation), compactSignature);
    }

    // Encode the call signature with invalid index
    uint8 implicitFlag = uint8(index | 0x80);
    encoded = abi.encodePacked(encoded, implicitFlag);
    // Ignore encoding the signature as will fail before then

    // Recover the signature
    vm.expectRevert(SessionErrors.InvalidAttestation.selector);
    harness.recover(payload, encoded);
  }

  function testConfiguration_largeBlacklist(
    address[] memory blacklist
  ) public {
    vm.assume(blacklist.length > 0);
    if (blacklist.length < 0x0f) {
      address[] memory largerBlacklist = new address[](0x0f);
      for (uint256 i = 0; i < largerBlacklist.length; i++) {
        largerBlacklist[i] = blacklist[i % blacklist.length];
      }
      blacklist = largerBlacklist;
    } else if (blacklist.length > 0xff) {
      // Truncate size to max 0xff
      assembly {
        mstore(blacklist, 0xff)
      }
    }

    // Remove duplicates
    {
      address[] memory uniqueBlacklist = new address[](blacklist.length);
      uint256 uniqueBlacklistIndex = 0;
      for (uint256 i = 0; i < blacklist.length; i++) {
        bool found = false;
        for (uint256 j = 0; j < uniqueBlacklistIndex; j++) {
          if (blacklist[i] == uniqueBlacklist[j]) {
            found = true;
            break;
          }
        }
        if (!found) {
          uniqueBlacklist[uniqueBlacklistIndex++] = blacklist[i];
        }
      }
      blacklist = uniqueBlacklist;
      assembly {
        mstore(blacklist, uniqueBlacklistIndex)
      }
    }

    // Create a topology
    string memory topology = PrimitivesRPC.sessionEmpty(vm, identityWallet.addr);
    for (uint256 i = 0; i < blacklist.length; i++) {
      topology = PrimitivesRPC.sessionImplicitAddBlacklistAddress(vm, topology, blacklist[i]);
    }

    // Call encodeCallSignatures with empty call signatures to encode the topology
    address[] memory implicitSigners = new address[](1);
    implicitSigners[0] = sessionWallet.addr;
    bytes memory encoded = PrimitivesRPC.sessionEncodeTopology(vm, topology);

    // Recover the configuration
    (SessionSig.DecodedSignature memory sig, bool hasBlacklist) = harness.recoverConfiguration(encoded);
    assertEq(sig.implicitBlacklist.length, blacklist.length, "Implicit blacklist length");
    assertEq(hasBlacklist, true, "Blacklist should be present");
  }

  function testConfiguration_duplicateBlacklistNodes(address[5] memory fiveBlacklists, uint8 size) public {
    size = uint8(bound(size, 0, 5));
    address[] memory blacklist = new address[](size);
    for (uint256 i = 0; i < size; i++) {
      blacklist[i] = fiveBlacklists[i];
    }

    _sortAddressesMemory(blacklist);

    bytes memory encoded = new bytes(0);
    for (uint256 i = 0; i < 2; i++) {
      // Flag is top 4 bits 0x03, lower 4 bits are blacklist count
      uint8 blacklistFlag = uint8(0x30) | uint8(blacklist.length);
      encoded = abi.encodePacked(encoded, blacklistFlag);
      for (uint256 j = 0; j < blacklist.length; j++) {
        encoded = abi.encodePacked(encoded, blacklist[j]);
      }
    }

    // Recover the configuration
    vm.expectRevert(SessionErrors.InvalidBlacklist.selector);
    harness.recoverConfiguration(encoded);
  }

  function testConfiguration_duplicateBlacklistNodes_inBranch(address[5] memory fiveBlacklists, uint8 size) public {
    size = uint8(bound(size, 0, 5));
    address[] memory blacklist = new address[](size);
    for (uint256 i = 0; i < size; i++) {
      blacklist[i] = fiveBlacklists[i];
    }

    _sortAddressesMemory(blacklist);

    bytes memory encoded = new bytes(0);
    // Blacklist encoding
    bytes memory blacklistEncoded = new bytes(0);
    uint8 blacklistFlag = uint8(0x30) | uint8(blacklist.length);
    blacklistEncoded = abi.encodePacked(blacklistEncoded, blacklistFlag);
    for (uint256 j = 0; j < blacklist.length; j++) {
      blacklistEncoded = abi.encodePacked(blacklistEncoded, blacklist[j]);
    }

    // Branch encoding
    uint8 branchSize = uint8(blacklistEncoded.length);
    uint8 branchFlag = uint8(0x21);
    encoded = abi.encodePacked(encoded, branchFlag, branchSize, blacklistEncoded);

    // Two of these branches
    encoded = abi.encodePacked(encoded, encoded);

    // Recover the configuration
    vm.expectRevert(SessionErrors.InvalidBlacklist.selector);
    harness.recoverConfiguration(encoded);
  }

  function testConfiguration_duplicateIdentityNodes(address identitySigner1, address identitySigner2) public {
    vm.assume(identitySigner1 != address(0));
    vm.assume(identitySigner2 != address(0));

    bytes memory encoded = abi.encodePacked(uint8(0x40), identitySigner1);
    encoded = abi.encodePacked(encoded, uint8(0x40), identitySigner2);

    // Recover the configuration
    vm.expectRevert(SessionErrors.InvalidIdentitySigner.selector);
    harness.recoverConfiguration(encoded);
  }

  function testConfiguration_duplicateIdentityNodes_inBranch(
    address identitySigner
  ) public {
    vm.assume(identitySigner != address(0));

    // Identity signer encoding
    bytes memory identityEncoded = abi.encodePacked(uint8(0x40), identitySigner);

    // Branch encoding
    uint8 branchSize = uint8(identityEncoded.length);
    uint8 branchFlag = uint8(0x21);
    bytes memory encoded = abi.encodePacked(branchFlag, branchSize, identityEncoded);

    // Two of these branches
    encoded = abi.encodePacked(encoded, encoded);

    // Recover the configuration
    vm.expectRevert(SessionErrors.InvalidIdentitySigner.selector);
    harness.recoverConfiguration(encoded);
  }

  function testConfiguration_invalidNode(
    uint8 invalidNodeFlag
  ) public {
    invalidNodeFlag = uint8(bound(invalidNodeFlag, 0x05, 0x0f));

    bytes memory encoded = abi.encodePacked(invalidNodeFlag << 4);

    // Recover the configuration
    vm.expectRevert(abi.encodeWithSelector(SessionErrors.InvalidNodeType.selector, invalidNodeFlag));
    harness.recoverConfiguration(encoded);
  }

  function testLargeTopology(
    address[] memory explicitSigners,
    uint256 signersIncludeCount,
    bool includeImplicitSigner,
    address[] memory implicitBlacklist
  ) public {
    _sortAddressesMemory(implicitBlacklist);

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
    string memory topology = PrimitivesRPC.sessionEmpty(vm, identityWallet.addr);
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
    // Call encodeCallSignatures with empty call signatures to encode the topology (minimised)
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
    assertEq(sig.identitySigner, identityWallet.addr, "Identity signer");
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

  function testAttestationOptimisation(Attestation memory attestation1, Attestation memory attestation2) public {
    // Create a second session wallet
    Vm.Wallet memory sessionWallet2 = vm.createWallet("session2");

    attestation1.approvedSigner = sessionWallet.addr;
    attestation2.approvedSigner = sessionWallet2.addr;
    attestation1.authData.redirectUrl = "https://example.com"; // Normalise for safe JSONify
    attestation2.authData.redirectUrl = "https://example.com"; // Normalise for safe JSONify

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

    // Create 2 call signatures for the same session wallet and attestation
    string memory callSignatureA = _createImplicitCallSignature(payload, 0, sessionWallet, identityWallet, attestation1);
    string memory callSignatureB = _createImplicitCallSignature(payload, 1, sessionWallet, identityWallet, attestation1);

    // Create the second call signature for the second session wallet and attestation
    string memory callSignatureC =
      _createImplicitCallSignature(payload, 1, sessionWallet2, identityWallet, attestation2);

    // Create a topology
    string memory topology = PrimitivesRPC.sessionEmpty(vm, identityWallet.addr);

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

  function testEmptyPermissionsStructSize_direct(
    address signer,
    uint256 chainId,
    uint256 valueLimit,
    uint64 deadline
  ) public view {
    // Create an empty permissions struct
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: signer,
      chainId: chainId,
      valueLimit: valueLimit,
      deadline: deadline,
      permissions: new Permission[](0)
    });

    // Directly encode the permissions struct
    bytes memory encoded = abi.encodePacked(
      uint8(SessionSig.FLAG_PERMISSIONS),
      sessionPerms.signer,
      sessionPerms.chainId,
      sessionPerms.valueLimit,
      sessionPerms.deadline,
      uint8(0) // empty permissions array length
    );

    // Verify the size is the minimum size
    assertEq(encoded.length, SessionSig.MIN_ENCODED_PERMISSION_SIZE, "Incorrect size for empty permissions struct");

    // Verify we can decode it back
    (SessionSig.DecodedSignature memory sig,) = harness.recoverConfiguration(encoded);
    assertEq(sig.sessionPermissions.length, 1, "Should have one permissions struct");
    assertEq(sig.sessionPermissions[0].signer, signer, "Signer should match");
    assertEq(sig.sessionPermissions[0].chainId, chainId, "Chain ID should match");
    assertEq(sig.sessionPermissions[0].valueLimit, valueLimit, "Value limit should match");
    assertEq(sig.sessionPermissions[0].deadline, deadline, "Deadline should match");
    assertEq(sig.sessionPermissions[0].permissions.length, 0, "Should have no permissions");
  }

}
