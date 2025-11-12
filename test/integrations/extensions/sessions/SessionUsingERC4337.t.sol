// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { ExtendedSessionTestBase } from "./ExtendedSessionTestBase.sol";

import { PrimitivesRPC } from "test/utils/PrimitivesRPC.sol";

import { IEntryPoint } from "account-abstraction/core/EntryPoint.sol";
import { PackedUserOperation } from "account-abstraction/core/UserOperationLib.sol";
import { Stage1Module } from "src/Stage1Module.sol";
import { SessionErrors } from "src/extensions/sessions/SessionManager.sol";
import { ERC4337v07 } from "src/modules/ERC4337v07.sol";
import { Payload } from "src/modules/Payload.sol";

/// @notice Tests for sessions using ERC4337.
contract IntegrationSessionUsing4337 is ExtendedSessionTestBase {

  using Payload for Payload.Decoded;

  function setUp() public override {
    super.setUp();
  }

  function _prepareUserOp(
    address sender
  ) internal returns (PackedUserOperation memory) {
    // Create a payload to call the mock target contract.
    Payload.Decoded memory decodedPayload;
    decodedPayload.kind = Payload.KIND_TRANSACTIONS;
    decodedPayload.calls = new Payload.Call[](1);
    decodedPayload.calls[0] = Payload.Call({
      to: address(mockTarget),
      value: 0,
      data: hex"12345678",
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    bytes memory packedPayload = PrimitivesRPC.toPackedPayload(vm, decodedPayload);

    // Gas stuff
    uint256 verificationGasLimit = 1_000_000;
    uint256 callGasLimit = 100_000;
    uint256 preVerificationGas = 100_000;
    uint256 maxFeePerGas = block.basefee;
    uint256 maxPriorityFeePerGas = block.basefee;
    uint256 totalGasLimit = verificationGasLimit + callGasLimit + preVerificationGas;
    vm.deal(sender, totalGasLimit * (maxFeePerGas + maxPriorityFeePerGas));

    // Construct the UserOp.
    PackedUserOperation memory userOp;
    userOp.callData = abi.encodeWithSelector(ERC4337v07.executeUserOp.selector, packedPayload);
    userOp.sender = sender;
    userOp.nonce = 0;
    userOp.initCode = "";
    userOp.accountGasLimits = bytes32(abi.encodePacked(uint128(verificationGasLimit), uint128(callGasLimit)));
    userOp.preVerificationGas = preVerificationGas;
    userOp.gasFees = bytes32(abi.encodePacked(uint128(maxPriorityFeePerGas), uint128(maxFeePerGas)));
    userOp.paymasterAndData = "";

    return userOp;
  }

  function test_ExplicitSession_ERC4337_InvalidPayloadKind(
    address beneficiary
  ) external {
    vm.assume(beneficiary != address(0));
    beneficiary = boundNoPrecompile(beneficiary);
    vm.assume(beneficiary.code.length == 0);

    // Deploy the wallet
    string memory topology = _createDefaultTopology();
    (Stage1Module wallet, string memory config,) = _createWallet(topology);

    // Get the userOpHash that the EntryPoint will use by calling its getUserOpHash function
    PackedUserOperation memory userOp = _prepareUserOp(address(wallet));
    bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

    // Create a signature for the userOpHash using the session wallet.
    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_DIGEST;
    payload.digest = userOpHash;

    bytes memory signature =
      _validExplicitSignature(address(wallet), payload, sessionWallet, config, topology, new uint8[](1));
    userOp.signature = signature;

    PackedUserOperation[] memory ops = new PackedUserOperation[](1);
    ops[0] = userOp;

    // Check execution fails with the expected error.
    vm.expectRevert(
      abi.encodeWithSelector(
        IEntryPoint.FailedOpWithRevert.selector,
        0,
        "AA23 reverted",
        abi.encodePacked(SessionErrors.InvalidPayloadKind.selector)
      )
    );
    entryPoint.handleOps(ops, payable(beneficiary));
  }

  function test_ImplicitSession_ERC4337_InvalidPayloadKind(
    address beneficiary
  ) external {
    vm.assume(beneficiary != address(0));
    beneficiary = boundNoPrecompile(beneficiary);
    vm.assume(beneficiary.code.length == 0);

    // Deploy the wallet
    string memory topology = _createDefaultTopology();
    (Stage1Module wallet, string memory config,) = _createWallet(topology);

    // Get the userOpHash that the EntryPoint will use by calling its getUserOpHash function
    PackedUserOperation memory userOp = _prepareUserOp(address(wallet));
    bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

    // Create a signature for the userOpHash using the session wallet.
    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_DIGEST;
    payload.digest = userOpHash;

    bytes memory signature = _validImplicitSignature(address(wallet), payload, sessionWallet, config, topology);
    userOp.signature = signature;

    PackedUserOperation[] memory ops = new PackedUserOperation[](1);
    ops[0] = userOp;

    // Check execution fails with the expected error.
    vm.expectRevert(
      abi.encodeWithSelector(
        IEntryPoint.FailedOpWithRevert.selector,
        0,
        "AA23 reverted",
        abi.encodePacked(SessionErrors.InvalidPayloadKind.selector)
      )
    );
    entryPoint.handleOps(ops, payable(beneficiary));
  }

}
