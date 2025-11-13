// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { ExtendedSessionTestBase, Vm } from "./ExtendedSessionTestBase.sol";
import { PrimitivesRPC } from "test/utils/PrimitivesRPC.sol";

import { Stage1Module } from "src/Stage1Module.sol";
import { SessionErrors } from "src/extensions/sessions/SessionManager.sol";
import { SessionPermissions } from "src/extensions/sessions/explicit/IExplicitSessionManager.sol";
import { ParameterRule, Permission } from "src/extensions/sessions/explicit/Permission.sol";

import { Payload } from "src/modules/Payload.sol";

/// @notice Tests for sessions self-calling.
contract IntegrationSessionSelfCall is ExtendedSessionTestBase {

  using Payload for Payload.Decoded;

  function setUp() public override {
    super.setUp();
  }

  function test_ExplicitSession_SelfCall(
    bytes32 initImageHash
  ) external {
    // Deploy the wallet with an EOA signer
    Stage1Module wallet = Stage1Module(payable(factory.deploy(address(module), initImageHash)));

    // Update the topology to include a session with self-call permissions
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: 0,
      valueLimit: 0,
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](1)
    });
    sessionPerms.permissions[0] = Permission({ target: address(wallet), rules: new ParameterRule[](0) });
    string memory topology = _createTopology(sessionPerms);
    bytes32 sessionImageHash = PrimitivesRPC.sessionImageHash(vm, topology);
    string memory ce = string(
      abi.encodePacked("sapient:", vm.toString(sessionImageHash), ":", vm.toString(address(sessionManager)), ":1")
    );
    string memory updatedConfig = PrimitivesRPC.newConfig(vm, 1, 0, ce);
    bytes32 updatedImageHash = PrimitivesRPC.getImageHash(vm, updatedConfig);

    // Update the wallet to use the session image hash
    vm.prank(address(wallet));
    wallet.updateImageHash(updatedImageHash);

    // Construct a self call payload
    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_TRANSACTIONS;
    payload.calls = new Payload.Call[](1);
    payload.calls[0] = Payload.Call({
      to: address(wallet),
      value: 0,
      data: hex"12345678",
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    // Sign with the session wallet
    bytes memory signature =
      _validExplicitSignature(address(wallet), payload, sessionWallet, updatedConfig, topology, new uint8[](1));

    // Execute the self call payload
    bytes memory packedPayload = PrimitivesRPC.toPackedPayload(vm, payload);
    vm.expectRevert(abi.encodeWithSelector(SessionErrors.InvalidSelfCall.selector));
    wallet.execute(packedPayload, signature);
  }

}
