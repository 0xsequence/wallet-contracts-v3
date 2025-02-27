// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

/*

import { Attestation, LibAttestation } from "src/extensions/sessions/Attestation.sol";
import {
  IImplicitSessionManager,
  IImplicitSessionManagerSignals
} from "src/extensions/sessions/implicit/IImplicitSessionManager.sol";
import { ISignalsImplicitMode } from "src/extensions/sessions/implicit/ISignalsImplicitMode.sol";
import { ImplicitSessionManager } from "src/extensions/sessions/implicit/ImplicitSessionManager.sol";
import { ISapient, Payload } from "src/modules/interfaces/ISapient.sol";

import { MockImplicitContract } from "../../../mocks/MockImplicitContract.sol";
import { PrimitivesRPC } from "../../../utils/PrimitivesRPC.sol";
import { AdvTest } from "../../../utils/TestUtils.sol";

contract MockInvalidImplicitContract is ISignalsImplicitMode {

  function acceptImplicitRequest(
    address,
    Attestation calldata,
    bytes32,
    Payload.Call calldata
  ) external pure returns (bytes32) {
    // Return an incorrect magic value so the implicit result is invalid.
    return bytes32(0);
  }

}

contract ImplicitSessionManagerTest is AdvTest, IImplicitSessionManagerSignals {

  using LibAttestation for Attestation;

  ImplicitSessionManager public sessionManager;
  MockImplicitContract public mockImplicit;

  uint256 public sessionSignerPk = 1;
  uint256 public identitySignerPk = 2;
  address public sessionSigner;
  address public identitySigner;

  function setUp() public {
    sessionManager = new ImplicitSessionManager();
    mockImplicit = new MockImplicitContract();
    sessionSigner = vm.addr(sessionSignerPk);
    identitySigner = vm.addr(identitySignerPk);

    vm.label(sessionSigner, "sessionSigner");
    vm.label(identitySigner, "identitySigner");
    vm.label(address(sessionManager), "sessionManager");
    vm.label(address(mockImplicit), "mockImplicit");
  }

  /// @notice Verifies that the session manager supports the required interfaces.
  function test_SupportsInterface() public view {
    assertTrue(sessionManager.supportsInterface(type(ISapient).interfaceId));
    assertTrue(sessionManager.supportsInterface(type(IImplicitSessionManager).interfaceId));
  }

  /// @dev Helper to create a Payload.Decoded with one call.
  function _createPayloadWithCall(
    address to,
    bool delegateCall,
    uint256 value,
    bytes memory data
  ) internal pure returns (Payload.Decoded memory payload) {
    Payload.Call memory call = Payload.Call({
      to: to,
      value: value,
      data: data,
      gasLimit: 0,
      delegateCall: delegateCall,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_IGNORE_ERROR
    });
    Payload.Call[] memory calls = new Payload.Call[](1);
    calls[0] = call;
    payload = Payload.Decoded({
      kind: Payload.KIND_TRANSACTIONS,
      noChainId: false,
      calls: calls,
      space: 0,
      nonce: 0,
      message: new bytes(0),
      imageHash: bytes32(0),
      digest: bytes32(0),
      parentWallets: new address[](0)
    });
  }

  /// @dev Helper to create an empty payload (no calls).
  function _createEmptyPayload() internal pure returns (Payload.Decoded memory payload) {
    Payload.Call[] memory calls = new Payload.Call[](0);
    payload = Payload.Decoded({
      kind: Payload.KIND_TRANSACTIONS,
      noChainId: false,
      calls: calls,
      space: 0,
      nonce: 0,
      message: new bytes(0),
      imageHash: bytes32(0),
      digest: bytes32(0),
      parentWallets: new address[](0)
    });
  }

  function _attestationToJson(
    Attestation memory attestation
  ) internal pure returns (string memory) {
    // Encode bytes4 as a string for proper length encoding.
    bytes memory identityTypeBytes = abi.encodePacked(attestation.identityType);
    return string.concat(
      '{"approvedSigner":"',
      vm.toString(attestation.approvedSigner),
      '",',
      '"identityType":"',
      vm.toString(identityTypeBytes),
      '",',
      '"issuerHash":"',
      vm.toString(attestation.issuerHash),
      '",',
      '"audienceHash":"',
      vm.toString(attestation.audienceHash),
      '",',
      '"authData":"',
      vm.toString(attestation.authData),
      '",',
      '"applicationData":"',
      vm.toString(attestation.applicationData),
      '"}'
    );
  }

  /// @notice Test for a valid implicit session.
  function test_validImplicitSession(
    bytes calldata authData,
    bytes calldata applicationData,
    address[] memory fuzzBlacklist
  ) public {
    // Bound the fuzzBlacklist length to 10.
    if (fuzzBlacklist.length > 10) {
      assembly {
        mstore(fuzzBlacklist, 10)
      }
    }
    // Create a payload with a single call to the mock implicit contract.
    Payload.Decoded memory payload = _createPayloadWithCall(address(mockImplicit), false, 0, "");
    // Create an empty session configuration.
    string memory sessionJson = PrimitivesRPC.emptyImplicitSession(vm);
    // Add the fuzzed blacklist to the session.
    for (uint256 i = 0; i < fuzzBlacklist.length; i++) {
      sessionJson = PrimitivesRPC.addImplicitSessionBlacklist(vm, sessionJson, fuzzBlacklist[i]);
    }
    // Remove the call target from the blacklist. (Even if it wasn't added, this should be a no-op.)
    sessionJson = PrimitivesRPC.removeImplicitSessionBlacklist(vm, sessionJson, address(mockImplicit));

    string memory sessionSignature;
    string memory identitySignature;
    string memory attestationJson;
    bytes32 attestationHash;
    {
      // Sign the payload using the session key.
      bytes32 payloadHash = keccak256(abi.encode(payload));
      (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionSignerPk, payloadHash);
      sessionSignature = string(abi.encodePacked(vm.toString(r), ":", vm.toString(s), ":", vm.toString(v)));
      {
        address correctSessionSigner = ecrecover(payloadHash, v, r, s);
        assertEq(correctSessionSigner, sessionSigner, "Session signer mismatch");
      }
    }
    {
      Attestation memory attestation = Attestation({
        approvedSigner: sessionSigner,
        identityType: bytes4(0),
        issuerHash: bytes32(0),
        audienceHash: bytes32(0),
        authData: authData,
        applicationData: applicationData
      });
      attestationJson = _attestationToJson(attestation);
      // Sign the attestation using the identity key.
      attestationHash = attestation.toHash();
      (uint8 v, bytes32 r, bytes32 s) = vm.sign(identitySignerPk, attestationHash);
      identitySignature = string(abi.encodePacked(vm.toString(r), ":", vm.toString(s), ":", vm.toString(v)));
    }

    // Use the RPC helper to encode the implicit session signature.
    bytes memory sig =
      PrimitivesRPC.useImplicitSession(vm, sessionSignature, identitySignature, attestationJson, sessionJson);
    bytes32 imageHash = sessionManager.isValidSapientSignature(payload, sig);

    //TODO Validate imageHash
  }

  /*

  /// @notice Test for delegateCall not allowed.
  function test_delegateCallNotAllowed(bytes calldata authData, bytes calldata applicationData) public {
    Payload.Decoded memory payload = _createPayloadWithCall(
      address(mockImplicit),
      true, // delegateCall enabled -> should revert
      0,
      ""
    );
    bytes32 payloadHash = keccak256(abi.encode(payload));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionSignerPk, payloadHash);
    address correctSessionSigner = ecrecover(payloadHash, v, r, s);
    Attestation memory attestation = Attestation({
      approvedSigner: correctSessionSigner,
      identityType: bytes4(0),
      issuerHash: bytes32(0),
      audienceHash: bytes32(0),
      authData: authData,
      applicationData: applicationData
    });
    address[] memory emptyBlacklist = new address[](0);
    bytes memory sig = _encodeImplicitSessionSignatureRPC(payload, attestation, emptyBlacklist);

    vm.prank(address(this));
    vm.expectRevert(abi.encodeWithSelector(InvalidDelegateCall.selector));
    sessionManager.isValidSapientSignature(payload, sig);
  }

  /// @notice Test for non-zero value not allowed.
  function test_nonZeroValueNotAllowed(
    bytes calldata authData,
    bytes calldata applicationData,
    uint256 nonZeroValue
  ) public {
    vm.assume(nonZeroValue > 0);
    Payload.Decoded memory payload = _createPayloadWithCall(
      address(mockImplicit),
      false,
      nonZeroValue, // non-zero value -> should revert
      ""
    );
    bytes32 payloadHash = keccak256(abi.encode(payload));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionSignerPk, payloadHash);
    address correctSessionSigner = ecrecover(payloadHash, v, r, s);
    Attestation memory attestation = Attestation({
      approvedSigner: correctSessionSigner,
      identityType: bytes4(0),
      issuerHash: bytes32(0),
      audienceHash: bytes32(0),
      authData: authData,
      applicationData: applicationData
    });
    address[] memory emptyBlacklist = new address[](0);
    bytes memory sig = _encodeImplicitSessionSignatureRPC(payload, attestation, emptyBlacklist);

    vm.prank(address(this));
    vm.expectRevert(abi.encodeWithSelector(InvalidValue.selector));
    sessionManager.isValidSapientSignature(payload, sig);
  }

  /// @notice Test for blacklisted address.
  function test_blacklistedAddressNotAllowed(
    bytes calldata authData,
    bytes calldata applicationData,
    address[] calldata fuzzBlacklist
  ) public {
    // Force the blacklist to contain the call target.
    address[] memory blacklist;
    if (fuzzBlacklist.length == 0) {
      blacklist = new address[](1);
      blacklist[0] = address(mockImplicit);
    } else {
      // Copy fuzzBlacklist into memory and force the first element to be the call target.
      blacklist = new address[](fuzzBlacklist.length);
      blacklist[0] = address(mockImplicit);
      for (uint256 i = 1; i < fuzzBlacklist.length; i++) {
        blacklist[i] = fuzzBlacklist[i];
      }
    }
    // Sort the blacklist so that binary search in the contract works correctly.
    blacklist = _sortAddressesMemory(blacklist);

    Payload.Decoded memory payload = _createPayloadWithCall(address(mockImplicit), false, 0, "");
    bytes32 payloadHash = keccak256(abi.encode(payload));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionSignerPk, payloadHash);
    address correctSessionSigner = ecrecover(payloadHash, v, r, s);
    Attestation memory attestation = Attestation({
      approvedSigner: correctSessionSigner,
      identityType: bytes4(0),
      issuerHash: bytes32(0),
      audienceHash: bytes32(0),
      authData: authData,
      applicationData: applicationData
    });
    bytes memory sig = _encodeImplicitSessionSignatureRPC(payload, attestation, blacklist);

    vm.prank(address(this));
    vm.expectRevert(abi.encodeWithSelector(BlacklistedAddress.selector, address(mockImplicit)));
    sessionManager.isValidSapientSignature(payload, sig);
  }

  /// @notice Test for invalid implicit result.
  function test_invalidImplicitResult(bytes calldata authData, bytes calldata applicationData) public {
    // Deploy a contract that returns an incorrect implicit result.
    MockInvalidImplicitContract invalidContract = new MockInvalidImplicitContract();
    vm.label(address(invalidContract), "invalidContract");

    Payload.Decoded memory payload = _createPayloadWithCall(address(invalidContract), false, 0, "");
    bytes32 payloadHash = keccak256(abi.encode(payload));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionSignerPk, payloadHash);
    address correctSessionSigner = ecrecover(payloadHash, v, r, s);
    Attestation memory attestation = Attestation({
      approvedSigner: correctSessionSigner,
      identityType: bytes4(0),
      issuerHash: bytes32(0),
      audienceHash: bytes32(0),
      authData: authData,
      applicationData: applicationData
    });
    address[] memory emptyBlacklist = new address[](0);
    bytes memory sig = _encodeImplicitSessionSignatureRPC(payload, attestation, emptyBlacklist);

    vm.prank(address(this));
    vm.expectRevert(abi.encodeWithSelector(InvalidImplicitResult.selector));
    sessionManager.isValidSapientSignature(payload, sig);
  }

  /// @notice Test for malformed signature.
  function test_malformedSignature(
    bytes calldata randomSig
  ) public {
    Payload.Decoded memory payload = _createEmptyPayload();
    vm.expectRevert();
    sessionManager.isValidSapientSignature(payload, randomSig);
  }

}
*/
