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

  function _signAndEncodeRSV(bytes32 hash, Vm.Wallet memory wallet) internal pure returns (string memory) {
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(wallet.privateKey, hash);
    return string(abi.encodePacked(vm.toString(r), ":", vm.toString(s), ":", vm.toString(v)));
  }

  /// @dev Encodes the explicit config.
  function _encodeExplicitConfig(
    address signer,
    uint256 valueLimit,
    uint256 deadline
  ) internal pure returns (bytes memory) {
    bytes memory node = abi.encodePacked(
      uint8(SessionSig.FLAG_PERMISSIONS),
      signer,
      valueLimit,
      deadline,
      uint24(0) // empty permissions array length
    );
    return abi.encodePacked(uint24(node.length), node);
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
    json = string.concat(json, '","valueLimit":');
    json = string.concat(json, vm.toString(sessionPerms.valueLimit));
    json = string.concat(json, ',"deadline":');
    json = string.concat(json, vm.toString(sessionPerms.deadline));
    json = string.concat(json, ',"permissions":[');
    for (uint256 i = 0; i < sessionPerms.permissions.length; i++) {
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
    json = string.concat(json, '","offset":');
    json = string.concat(json, vm.toString(rule.offset));
    json = string.concat(json, ',"mask":"');
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
    json = string.concat(json, '","authData":"');
    json = string.concat(json, vm.toString(attestation.authData));
    json = string.concat(json, '","applicationData":"');
    json = string.concat(json, vm.toString(attestation.applicationData));
    json = string.concat(json, '"}');
    return json;
  }

  function _createImplicitCallSignature(
    Payload.Call memory call,
    Vm.Wallet memory signer,
    Vm.Wallet memory globalSigner,
    Attestation memory attestation
  ) internal returns (string memory) {
    string memory globalSignature = _signAndEncodeRSV(LibAttestation.toHash(attestation), globalSigner);
    string memory sessionSignature = _signAndEncodeRSV(Payload.hashCall(call), signer);

    bytes memory callSignature = PrimitivesRPC.sessionImplicitEncodeCallSignature(
      vm, sessionSignature, globalSignature, _attestationToJSON(attestation)
    );
    return vm.toString(callSignature);
  }

  function _createSessionPermissions(
    address target,
    uint256 valueLimit,
    uint256 deadline,
    address signer
  ) internal pure returns (SessionPermissions memory) {
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: signer,
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

}
