// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Test, Vm } from "forge-std/Test.sol";

import { PrimitivesRPC } from "test/utils/PrimitivesRPC.sol";
import { AdvTest } from "test/utils/TestUtils.sol";

import { SessionManager } from "src/extensions/sessions/SessionManager.sol";
import { SessionSig } from "src/extensions/sessions/SessionSig.sol";
import { SessionPermissions } from "src/extensions/sessions/explicit/IExplicitSessionManager.sol";
import { ParameterOperation, ParameterRule, Permission } from "src/extensions/sessions/explicit/Permission.sol";

import { Attestation, LibAttestation } from "src/extensions/sessions/implicit/Attestation.sol";
import { Payload } from "src/modules/Payload.sol";

abstract contract SessionTestBase is AdvTest {

  using LibAttestation for Attestation;

  address internal constant VALUE_TRACKING_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

  function _signAndEncodeRSV(bytes32 hash, Vm.Wallet memory wallet) internal pure returns (string memory) {
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(wallet.privateKey, hash);
    return string(abi.encodePacked(vm.toString(r), ":", vm.toString(s), ":", vm.toString(v)));
  }

  /// @dev Helper to build a Payload.Decoded with a given number of calls.
  function _buildPayload(
    uint256 callCount
  ) internal pure returns (Payload.Decoded memory payload) {
    payload.kind = Payload.KIND_TRANSACTIONS;
    payload.noChainId = true;
    payload.space = 0;
    payload.nonce = 0;
    payload.parentWallets = new address[](0);
    payload.calls = new Payload.Call[](callCount);
  }

  function _sessionPermissionsToJSON(
    SessionPermissions memory sessionPerms
  ) internal pure returns (string memory) {
    string memory json = '{"signer":"';
    json = string.concat(json, vm.toString(sessionPerms.signer));
    json = string.concat(json, '","chainId":"');
    json = string.concat(json, vm.toString(sessionPerms.chainId));
    json = string.concat(json, '","valueLimit":"');
    json = string.concat(json, vm.toString(sessionPerms.valueLimit));
    json = string.concat(json, '","deadline":"');
    json = string.concat(json, vm.toString(sessionPerms.deadline));
    json = string.concat(json, '","permissions":[');
    for (uint256 i = 0; i < sessionPerms.permissions.length; i++) {
      if (i > 0) {
        json = string.concat(json, ",");
      }
      json = string.concat(json, _permissionToJSON(sessionPerms.permissions[i]));
    }
    json = string.concat(json, "]}");
    return json;
  }

  function _permissionToJSON(
    Permission memory permission
  ) internal pure returns (string memory) {
    string memory json = '{"target":"';
    json = string.concat(json, vm.toString(permission.target));
    json = string.concat(json, '","rules":[');
    for (uint256 i = 0; i < permission.rules.length; i++) {
      if (i > 0) {
        json = string.concat(json, ",");
      }
      json = string.concat(json, _ruleToJSON(permission.rules[i]));
    }
    json = string.concat(json, "]}");
    return json;
  }

  function _ruleToJSON(
    ParameterRule memory rule
  ) internal pure returns (string memory) {
    string memory json = '{"cumulative":';
    json = string.concat(json, vm.toString(rule.cumulative));
    json = string.concat(json, ',"operation":');
    json = string.concat(json, vm.toString(uint8(rule.operation)));
    json = string.concat(json, ',"value":"');
    json = string.concat(json, vm.toString(rule.value));
    json = string.concat(json, '","offset":"');
    json = string.concat(json, vm.toString(rule.offset));
    json = string.concat(json, '","mask":"');
    json = string.concat(json, vm.toString(rule.mask));
    json = string.concat(json, '"}');
    return json;
  }

  function _attestationToJSON(
    Attestation memory attestation
  ) internal pure returns (string memory) {
    string memory json = '{"approvedSigner":"';
    json = string.concat(json, vm.toString(attestation.approvedSigner));
    json = string.concat(json, '","identityType":"');
    json = string.concat(json, vm.toString(attestation.identityType));
    json = string.concat(json, '","issuerHash":"');
    json = string.concat(json, vm.toString(attestation.issuerHash));
    json = string.concat(json, '","audienceHash":"');
    json = string.concat(json, vm.toString(attestation.audienceHash));
    json = string.concat(json, '","authData":{"redirectUrl":"');
    json = string.concat(json, attestation.authData.redirectUrl);
    json = string.concat(json, '","issuedAt":"');
    json = string.concat(json, vm.toString(attestation.authData.issuedAt));
    json = string.concat(json, '"},"applicationData":"');
    json = string.concat(json, vm.toString(attestation.applicationData));
    json = string.concat(json, '"}');
    return json;
  }

  function _createImplicitCallSignature(
    Payload.Decoded memory payload,
    uint256 callIdx,
    Vm.Wallet memory signer,
    Vm.Wallet memory identitySigner,
    Attestation memory attestation
  ) internal view returns (string memory) {
    bytes32 attestationHash = attestation.toHash();
    string memory identitySignature = _signAndEncodeRSV(attestationHash, identitySigner);
    bytes32 callHash = SessionSig.hashCallWithReplayProtection(payload, callIdx);
    string memory sessionSignature = _signAndEncodeRSV(callHash, signer);
    return _implicitCallSignatureToJSON(attestation, sessionSignature, identitySignature);
  }

  function _implicitCallSignatureToJSON(
    Attestation memory attestation,
    string memory sessionSignature,
    string memory identitySignature
  ) internal pure returns (string memory) {
    string memory json = '{"attestation":';
    json = string.concat(json, _attestationToJSON(attestation));
    json = string.concat(json, ',"sessionSignature":"');
    json = string.concat(json, sessionSignature);
    json = string.concat(json, '","identitySignature":"');
    json = string.concat(json, identitySignature);
    json = string.concat(json, '"}');
    return json;
  }

  function _explicitCallSignatureToJSON(
    uint8 permissionIndex,
    string memory sessionSignature
  ) internal pure returns (string memory) {
    string memory json = '{"permissionIndex":"';
    json = string.concat(json, vm.toString(permissionIndex));
    json = string.concat(json, '","sessionSignature":"');
    json = string.concat(json, sessionSignature);
    json = string.concat(json, '"}');
    return json;
  }

  function _createSessionPermissions(
    address target,
    uint256 chainId,
    uint256 valueLimit,
    uint64 deadline,
    address signer
  ) internal pure returns (SessionPermissions memory) {
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: signer,
      chainId: chainId,
      valueLimit: valueLimit,
      deadline: deadline,
      permissions: new Permission[](1)
    });

    sessionPerms.permissions[0] = Permission({ target: target, rules: new ParameterRule[](1) });
    sessionPerms.permissions[0].rules[0] = ParameterRule({
      cumulative: false,
      operation: ParameterOperation.EQUAL,
      value: bytes32(0),
      offset: 0,
      mask: bytes32(0)
    });

    return sessionPerms;
  }

  // Convert a single SessionPermissions struct into an array.
  function _toArray(
    SessionPermissions memory perm
  ) internal pure returns (SessionPermissions[] memory) {
    SessionPermissions[] memory arr = new SessionPermissions[](1);
    arr[0] = perm;
    return arr;
  }

  /// @notice Sorts an array of addresses in memory.
  /// @param addresses The array of addresses to sort.
  function _sortAddressesMemory(
    address[] memory addresses
  ) internal pure {
    // Sort the addresses using bubble sort.
    for (uint256 i = 0; i < addresses.length; i++) {
      for (uint256 j = 0; j < addresses.length - i - 1; j++) {
        if (addresses[j] > addresses[j + 1]) {
          address temp = addresses[j];
          addresses[j] = addresses[j + 1];
          addresses[j + 1] = temp;
        }
      }
    }
  }

}
