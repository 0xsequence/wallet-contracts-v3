// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { ExtendedSessionTestBase } from "./ExtendedSessionTestBase.sol";
import { Vm, console } from "forge-std/Test.sol";

import { PrimitivesRPC } from "test/utils/PrimitivesRPC.sol";

import { Factory } from "src/Factory.sol";
import { Stage1Module } from "src/Stage1Module.sol";
import { SessionErrors, SessionManager, SessionSig } from "src/extensions/sessions/SessionManager.sol";
import { SessionPermissions } from "src/extensions/sessions/explicit/IExplicitSessionManager.sol";
import {
  ParameterOperation,
  ParameterRule,
  Permission,
  UsageLimit
} from "src/extensions/sessions/explicit/Permission.sol";
import { Attestation } from "src/extensions/sessions/implicit/Attestation.sol";
import { Calls } from "src/modules/Calls.sol";
import { Nonce } from "src/modules/Nonce.sol";
import { Payload } from "src/modules/Payload.sol";
import { ValueForwarder } from "test/mocks/ValueForwarder.sol";

/// @notice Checks for value forwarding by sessions.
contract IntegrationSessionValueForwardingTest is ExtendedSessionTestBase {

  using Payload for Payload.Decoded;

  ValueForwarder public valueForwarder;

  function setUp() public override {
    super.setUp();
    valueForwarder = new ValueForwarder();
  }

  function test_ValueForwarding_Explicit_Limited(
    uint256 chainId,
    uint160 space,
    address recipient,
    uint256 valueSent,
    uint256 valueCap
  ) public {
    assumeNotPrecompile2(recipient);
    chainId = bound(chainId, 0, 2 ** 26 - 1);
    if (chainId != 0) {
      vm.chainId(chainId);
    }
    space = uint160(bound(space, 0, sessionManager.MAX_SPACE()));
    valueSent = bound(valueSent, 2, 100 ether);
    valueCap = bound(valueCap, 1, valueSent - 1); // Under value sent

    // Create wallet with sessions
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: chainId,
      valueLimit: valueCap,
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](1)
    });
    sessionPerms.permissions[0] = Permission({ target: address(valueForwarder), rules: new ParameterRule[](0) });
    string memory topology = _createTopology(sessionPerms);
    (Stage1Module wallet, string memory config,) = _createWallet(topology);
    vm.assume(address(wallet) != recipient);

    // Give enough ETH for transfer
    vm.deal(address(wallet), valueSent);

    // Build payload for transfer
    Payload.Decoded memory payload = _buildPayload(2);
    payload.noChainId = chainId == 0;
    payload.space = space;
    // Increment
    UsageLimit[] memory limits = new UsageLimit[](1);
    limits[0].usageHash = keccak256(abi.encode(sessionWallet.addr, VALUE_TRACKING_ADDRESS));
    limits[0].usageAmount = valueSent;
    payload.calls[0].to = address(sessionManager);
    payload.calls[0].data = abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, limits);
    payload.calls[0].behaviorOnError = Payload.BEHAVIOR_REVERT_ON_ERROR;
    // Send value
    payload.calls[1].to = address(valueForwarder);
    payload.calls[1].data = abi.encodeWithSelector(valueForwarder.forwardValue.selector, recipient, valueSent);
    payload.calls[1].value = valueSent;
    payload.calls[1].behaviorOnError = Payload.BEHAVIOR_REVERT_ON_ERROR;

    // Sign it with the session
    bytes memory signature =
      _validExplicitSignature(address(wallet), payload, sessionWallet, config, topology, new uint8[](2));

    // Execute should fail due to limit exceeded
    vm.expectRevert(SessionErrors.InvalidValue.selector);
    wallet.execute(PrimitivesRPC.toPackedPayload(vm, payload), signature);

    // Drop the usage below the limit
    valueSent = bound(valueSent, 1, valueCap);
    limits[0].usageAmount = valueSent;
    payload.calls[0].data = abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, limits);
    payload.calls[1].data = abi.encodeWithSelector(valueForwarder.forwardValue.selector, recipient, valueSent);
    payload.calls[1].value = valueSent;

    // Sign and execute successfully
    signature = _validExplicitSignature(address(wallet), payload, sessionWallet, config, topology, new uint8[](2));
    wallet.execute(PrimitivesRPC.toPackedPayload(vm, payload), signature);

    // Check the balance of the recipient
    assertEq(address(recipient).balance, valueSent);

    // Try to spend above the limit with new payload
    payload.nonce++;
    valueSent = bound(valueSent, valueCap - valueSent + 1, 100 ether);
    limits[0].usageAmount += valueSent;
    payload.calls[0].data = abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, limits);
    payload.calls[1].data = abi.encodeWithSelector(valueForwarder.forwardValue.selector, recipient, valueSent);
    payload.calls[1].value = valueSent;
    // Ensure the wallet has enough ETH
    vm.deal(address(wallet), valueSent);

    // Sign and fail sending
    signature = _validExplicitSignature(address(wallet), payload, sessionWallet, config, topology, new uint8[](2));
    vm.expectRevert(SessionErrors.InvalidValue.selector);
    wallet.execute(PrimitivesRPC.toPackedPayload(vm, payload), signature);
  }

  function test_ValueForwarding_Explicit_OverMultipleCalls(
    uint256 chainId,
    uint160 space,
    address recipient,
    uint256 valueSent,
    uint256 valueCap
  ) public {
    vm.assume(recipient.code.length == 0);
    chainId = bound(chainId, 0, 2 ** 26 - 1);
    if (chainId != 0) {
      vm.chainId(chainId);
    }
    space = uint160(bound(space, 0, sessionManager.MAX_SPACE()));
    valueCap = bound(valueCap, 1 ether, 100 ether);
    // We will send 3 tx in a batch and want this to overflow
    valueSent = bound(valueSent, valueCap / 2, 100 ether);

    // Create wallet with sessions
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: chainId,
      valueLimit: valueCap,
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](1)
    });
    sessionPerms.permissions[0] = Permission({ target: address(valueForwarder), rules: new ParameterRule[](0) });
    string memory topology = _createTopology(sessionPerms);
    (Stage1Module wallet, string memory config,) = _createWallet(topology);
    vm.assume(address(wallet) != recipient);

    // Give enough ETH for transfer
    vm.deal(address(wallet), valueCap);

    // Build payload for transfer
    Payload.Decoded memory payload = _buildPayload(4);
    payload.noChainId = chainId == 0;
    payload.space = space;
    // Increment
    UsageLimit[] memory limits = new UsageLimit[](1);
    limits[0].usageHash = keccak256(abi.encode(sessionWallet.addr, VALUE_TRACKING_ADDRESS));
    limits[0].usageAmount = valueSent * 3;
    payload.calls[0].to = address(sessionManager);
    payload.calls[0].data = abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, limits);
    payload.calls[0].behaviorOnError = Payload.BEHAVIOR_REVERT_ON_ERROR;
    // Send value
    payload.calls[1].to = address(valueForwarder);
    payload.calls[1].data = abi.encodeWithSelector(valueForwarder.forwardValue.selector, recipient, valueSent);
    payload.calls[1].value = valueSent;
    payload.calls[1].behaviorOnError = Payload.BEHAVIOR_REVERT_ON_ERROR;
    payload.calls[2] = payload.calls[1];
    payload.calls[3] = payload.calls[1];

    // Sign it with the session
    bytes memory signature =
      _validExplicitSignature(address(wallet), payload, sessionWallet, config, topology, new uint8[](4));

    // Execute should fail due to limit exceeded
    vm.expectRevert(SessionErrors.InvalidValue.selector);
    wallet.execute(PrimitivesRPC.toPackedPayload(vm, payload), signature);

    // Drop the usage below the limit
    valueSent = bound(valueSent, 1, valueCap / 3);
    limits[0].usageAmount = valueSent * 3;
    payload.calls[0].data = abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, limits);
    payload.calls[1].data = abi.encodeWithSelector(valueForwarder.forwardValue.selector, recipient, valueSent);
    payload.calls[1].value = valueSent;
    payload.calls[2] = payload.calls[1];
    payload.calls[3] = payload.calls[1];

    // Sign and execute successfully
    signature = _validExplicitSignature(address(wallet), payload, sessionWallet, config, topology, new uint8[](4));
    wallet.execute(PrimitivesRPC.toPackedPayload(vm, payload), signature);

    // Check the balance of the recipient
    assertEq(address(recipient).balance, valueSent * 3);

    // Try to spend above the limit with new payload
    payload.nonce++;
    valueSent = bound(valueSent, ((valueCap - valueSent * 3) / 3) + 1, 100 ether);
    limits[0].usageAmount += valueSent * 3; // Should be an increment
    payload.calls[0].data = abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, limits);
    payload.calls[1].data = abi.encodeWithSelector(valueForwarder.forwardValue.selector, recipient, valueSent);
    payload.calls[1].value = valueSent;
    payload.calls[2] = payload.calls[1];
    payload.calls[3] = payload.calls[1];
    // Ensure the wallet has enough ETH
    vm.deal(address(wallet), valueSent * 3);

    // Sign and fail sending
    signature = _validExplicitSignature(address(wallet), payload, sessionWallet, config, topology, new uint8[](4));
    vm.expectRevert(SessionErrors.InvalidValue.selector);
    wallet.execute(PrimitivesRPC.toPackedPayload(vm, payload), signature);
  }

  function test_ValueForwarding_NoRequiredIncrementAfterIncrement(
    uint256 chainId,
    uint160 space,
    address recipient,
    uint256 valueSent,
    uint256 valueCap
  ) public {
    vm.assume(recipient.code.length == 0);
    chainId = bound(chainId, 0, 2 ** 26 - 1);
    if (chainId != 0) {
      vm.chainId(chainId);
    }
    space = uint160(bound(space, 0, sessionManager.MAX_SPACE()));
    valueCap = bound(valueCap, 1 ether, 100 ether);
    valueSent = bound(valueSent, 1, valueCap);

    // Create wallet with sessions
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr,
      chainId: chainId,
      valueLimit: valueCap,
      deadline: uint64(block.timestamp + 1 days),
      permissions: new Permission[](2)
    });
    sessionPerms.permissions[0] = Permission({ target: address(valueForwarder), rules: new ParameterRule[](0) });
    sessionPerms.permissions[1] = Permission({ target: address(mockTarget), rules: new ParameterRule[](0) });
    string memory topology = _createTopology(sessionPerms);
    (Stage1Module wallet, string memory config,) = _createWallet(topology);
    vm.assume(address(wallet) != recipient);

    // Give enough ETH for transfer
    vm.deal(address(wallet), valueCap);

    // Build payload for transfer
    Payload.Decoded memory payload = _buildPayload(2);
    payload.noChainId = chainId == 0;
    payload.space = space;
    // Increment
    UsageLimit[] memory limits = new UsageLimit[](1);
    limits[0].usageHash = keccak256(abi.encode(sessionWallet.addr, VALUE_TRACKING_ADDRESS));
    limits[0].usageAmount = valueSent;
    payload.calls[0].to = address(sessionManager);
    payload.calls[0].data = abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, limits);
    payload.calls[0].behaviorOnError = Payload.BEHAVIOR_REVERT_ON_ERROR;
    // Send value
    payload.calls[1].to = address(valueForwarder);
    payload.calls[1].data = abi.encodeWithSelector(valueForwarder.forwardValue.selector, recipient, valueSent);
    payload.calls[1].value = valueSent;
    payload.calls[1].behaviorOnError = Payload.BEHAVIOR_REVERT_ON_ERROR;

    // Sign it with the session
    bytes memory signature =
      _validExplicitSignature(address(wallet), payload, sessionWallet, config, topology, new uint8[](4));

    // Sign and execute successfully
    uint256 recipientBalance = address(recipient).balance;
    wallet.execute(PrimitivesRPC.toPackedPayload(vm, payload), signature);

    // Check the balance of the recipient
    assertEq(address(recipient).balance, recipientBalance + valueSent);

    // Try another payload that doesn't use an increment permission
    payload = _buildPayload(2);
    payload.noChainId = chainId == 0;
    payload.space = space;
    payload.nonce = 1;
    // Note: It still needs an increment call, even though there is no increment usage...
    payload.calls[0].to = address(sessionManager);
    payload.calls[0].data = abi.encodeWithSelector(sessionManager.incrementUsageLimit.selector, limits);
    payload.calls[0].behaviorOnError = Payload.BEHAVIOR_REVERT_ON_ERROR;
    // Call mock target
    payload.calls[1].to = address(mockTarget);
    payload.calls[1].data = "0x12345678";

    // Sign and send success
    uint8[] memory permsUsed = new uint8[](2);
    permsUsed[1] = 1; // Uses mockTarget permission
    signature = _validExplicitSignature(address(wallet), payload, sessionWallet, config, topology, permsUsed);
    wallet.execute(PrimitivesRPC.toPackedPayload(vm, payload), signature);
  }

}
