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
import { Payload } from "src/modules/Payload.sol";

/// @notice Session limit increment tests.
contract IntegrationSessionLimitIncrementTest is ExtendedSessionTestBase {

  function test_SessionLimitIncrement_DoSSigner(
    string memory signer2Name
  ) public {
    Vm.Wallet memory signer2 = vm.createWallet(signer2Name);
    vm.assume(signer2.addr != sessionWallet.addr);

    // Create a topology with the session signer
    string memory topology = _createDefaultTopology();
    // Add session signer 2 to the topology
    SessionPermissions memory signer2Perms = SessionPermissions({
      signer: signer2.addr,
      chainId: 0,
      valueLimit: 0,
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](1)
    });
    signer2Perms.permissions[0] = Permission({ target: address(mockTarget), rules: new ParameterRule[](1) });
    signer2Perms.permissions[0].rules[0] = ParameterRule({
      cumulative: true,
      operation: ParameterOperation.EQUAL,
      value: bytes32(uint256(1)),
      offset: 0,
      mask: bytes32(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
    });
    string memory signer2PermsJson = _sessionPermissionsToJSON(signer2Perms);
    topology = PrimitivesRPC.sessionExplicitAdd(vm, signer2PermsJson, topology);
    // Create the wallet
    (Stage1Module wallet, string memory config,) = _createWallet(topology);

    // Create a valid payload
    UsageLimit[] memory usageLimits = new UsageLimit[](1);
    usageLimits[0] = UsageLimit({
      usageHash: keccak256(abi.encode(signer2.addr, signer2Perms.permissions[0], uint256(0))),
      usageAmount: uint256(1)
    });

    // Make the increment call with signer1
    Payload.Decoded memory signer1Payload = _buildPayload(1);
    signer1Payload.calls[0].to = address(sessionManager);
    signer1Payload.calls[0].data = abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, usageLimits);
    signer1Payload.calls[0].behaviorOnError = Payload.BEHAVIOR_REVERT_ON_ERROR;

    // Sign it
    bytes memory signer1Signature =
      _validExplicitSignature(signer1Payload, sessionWallet, config, topology, new uint8[](1));

    // Validate we can't DoS it
    bytes memory packedSigner1Payload = PrimitivesRPC.toPackedPayload(vm, signer1Payload);
    vm.expectRevert(abi.encodeWithSelector(SessionErrors.InvalidLimitUsageIncrement.selector));
    wallet.execute(packedSigner1Payload, signer1Signature);
  }

}
