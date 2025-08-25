// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Factory, Wallet } from "src/Factory.sol";
import { Stage1Module } from "src/Stage1Module.sol";
import { ERC4337v07 } from "src/modules/ERC4337v07.sol";
import { Payload } from "src/modules/Payload.sol";

import { Emitter } from "test/mocks/Emitter.sol";
import { PrimitivesRPC } from "test/utils/PrimitivesRPC.sol";
import { AdvTest, Vm } from "test/utils/TestUtils.sol";

import { EntryPoint } from "account-abstraction/core/EntryPoint.sol";
import { PackedUserOperation, UserOperationLib } from "account-abstraction/core/UserOperationLib.sol";

contract IntegrationERC4337v07Test is AdvTest {

  Factory public factory;
  EntryPoint public entryPoint;
  Stage1Module public stage1Module;
  address payable public wallet;
  string public walletConfig;
  bytes32 public walletImageHash;
  Vm.Wallet public signer;

  function setUp() public {
    factory = new Factory();
    entryPoint = new EntryPoint();
    stage1Module = new Stage1Module(address(factory), address(entryPoint));

    // Basic wallet setup for most tests.
    signer = vm.createWallet("signer");
    walletConfig =
      PrimitivesRPC.newConfig(vm, 1, 0, string(abi.encodePacked("signer:", vm.toString(signer.addr), ":1")));
    walletImageHash = PrimitivesRPC.getImageHash(vm, walletConfig);
  }

  // --- Helper Functions ---

  function hashRealUserOp(
    PackedUserOperation calldata userOp
  ) public pure returns (bytes32) {
    return UserOperationLib.hash(userOp);
  }

  function predictWalletAddress(
    bytes32 imageHash
  ) public view returns (address) {
    bytes memory code = abi.encodePacked(Wallet.creationCode, uint256(uint160(address(stage1Module))));
    bytes32 initCodeHash = keccak256(code);

    return address(uint160(uint256(keccak256(abi.encodePacked(hex"ff", address(factory), imageHash, initCodeHash)))));
  }

  // --- tests ---

  function test_Entrypoint_happypath(
    address beneficiary
  ) external {
    vm.assume(beneficiary != address(0));
    beneficiary = boundNoPrecompile(beneficiary);
    vm.assume(beneficiary.code.length == 0);

    // Deploy the wallet
    wallet = payable(factory.deploy(address(stage1Module), walletImageHash));

    // Setup a mock contract to call.
    Emitter emitter = new Emitter();

    // Create a payload to call the emitter contract.
    Payload.Decoded memory decodedPayload;
    decodedPayload.kind = Payload.KIND_TRANSACTIONS;
    decodedPayload.calls = new Payload.Call[](1);
    decodedPayload.calls[0] = Payload.Call({
      to: address(emitter),
      value: 0,
      data: abi.encodeWithSelector(Emitter.explicitEmit.selector),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    bytes memory packedPayload = PrimitivesRPC.toPackedPayload(vm, decodedPayload);

    // Gas stuff
    uint256 verificationGasLimit = 100_000;
    uint256 callGasLimit = 100_000;
    uint256 preVerificationGas = 100_000;
    uint256 maxFeePerGas = block.basefee;
    uint256 maxPriorityFeePerGas = block.basefee;
    uint256 totalGasLimit = verificationGasLimit + callGasLimit + preVerificationGas;
    vm.deal(wallet, totalGasLimit * (maxFeePerGas + maxPriorityFeePerGas));

    // Construct the UserOp.
    PackedUserOperation memory userOp;
    userOp.callData = abi.encodeWithSelector(ERC4337v07.executeUserOp.selector, packedPayload);
    userOp.sender = wallet;
    userOp.nonce = 0;
    userOp.initCode = "";
    userOp.accountGasLimits = bytes32(abi.encodePacked(uint128(verificationGasLimit), uint128(callGasLimit)));
    userOp.preVerificationGas = preVerificationGas;
    userOp.gasFees = bytes32(abi.encodePacked(uint128(maxPriorityFeePerGas), uint128(maxFeePerGas)));
    userOp.paymasterAndData = "";

    // Get the userOpHash that the EntryPoint will use by calling its getUserOpHash function
    bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

    // Create a signature for the userOpHash using the wallet's signer config.
    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_DIGEST;
    payload.digest = userOpHash;
    bytes32 payloadDigest = Payload.hashFor(payload, wallet);

    // Create a signature for the userOpHash using the wallet's signer config.
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signer, payloadDigest);
    string memory signatures = string(
      abi.encodePacked(vm.toString(signer.addr), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v))
    );
    userOp.signature = PrimitivesRPC.toEncodedSignature(vm, walletConfig, signatures, true);

    PackedUserOperation[] memory ops = new PackedUserOperation[](1);
    ops[0] = userOp;

    // Call the entrypoint.
    vm.expectEmit(true, false, false, true, address(emitter));
    emit Emitter.Explicit(wallet);
    entryPoint.handleOps(ops, payable(beneficiary));
  }

  function test_Entrypoint_initcode(
    address beneficiary
  ) external {
    vm.assume(beneficiary != address(0));
    beneficiary = boundNoPrecompile(beneficiary);
    vm.assume(beneficiary.code.length == 0);

    // Setup a mock contract to call.
    Emitter emitter = new Emitter();

    address predictedWallet = predictWalletAddress(walletImageHash);

    // Create a payload to call the emitter contract.
    Payload.Decoded memory decodedPayload;
    decodedPayload.kind = Payload.KIND_TRANSACTIONS;
    decodedPayload.calls = new Payload.Call[](1);
    decodedPayload.calls[0] = Payload.Call({
      to: address(emitter),
      value: 0,
      data: abi.encodeWithSelector(Emitter.explicitEmit.selector),
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
    vm.deal(predictedWallet, totalGasLimit * (maxFeePerGas + maxPriorityFeePerGas));

    // Construct the UserOp.
    PackedUserOperation memory userOp;
    userOp.callData = abi.encodeWithSelector(ERC4337v07.executeUserOp.selector, packedPayload);
    userOp.sender = predictedWallet;
    userOp.nonce = 0;
    userOp.initCode = abi.encodePacked(
      address(factory), abi.encodeWithSelector(Factory.deploy.selector, address(stage1Module), walletImageHash)
    ); // Deploy args
    userOp.accountGasLimits = bytes32(abi.encodePacked(uint128(verificationGasLimit), uint128(callGasLimit)));
    userOp.preVerificationGas = preVerificationGas;
    userOp.gasFees = bytes32(abi.encodePacked(uint128(maxPriorityFeePerGas), uint128(maxFeePerGas)));
    userOp.paymasterAndData = "";

    // Get the userOpHash that the EntryPoint will use by calling its getUserOpHash function
    bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

    // Create a signature for the userOpHash using the wallet's signer config.
    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_DIGEST;
    payload.digest = userOpHash;
    bytes32 payloadDigest = Payload.hashFor(payload, predictedWallet);

    // Create a signature for the userOpHash using the wallet's signer config.
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signer, payloadDigest);
    string memory signatures = string(
      abi.encodePacked(vm.toString(signer.addr), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v))
    );
    userOp.signature = PrimitivesRPC.toEncodedSignature(vm, walletConfig, signatures, true);

    PackedUserOperation[] memory ops = new PackedUserOperation[](1);
    ops[0] = userOp;

    // Call the entrypoint.
    vm.expectEmit(true, false, false, true, address(emitter));
    emit Emitter.Explicit(predictedWallet);
    entryPoint.handleOps(ops, payable(beneficiary));
  }

}
