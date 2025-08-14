// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Factory } from "../../src/Factory.sol";
import { Stage1Module } from "../../src/Stage1Module.sol";

import { ERC4337v07 } from "../../src/modules/ERC4337v07.sol";
import { Payload } from "../../src/modules/Payload.sol";
import { IAccount, PackedUserOperation } from "../../src/modules/interfaces/IAccount.sol";
import { IEntryPoint } from "../../src/modules/interfaces/IEntryPoint.sol";
import { Emitter } from "../mocks/Emitter.sol";
import { PrimitivesRPC } from "../utils/PrimitivesRPC.sol";
import { AdvTest } from "../utils/TestUtils.sol";

// Mock EntryPoint for testing purposes.
contract MockEntryPoint is IEntryPoint {

  event Deposited(address indexed account, uint256 totalDeposited);

  mapping(address => uint256) public deposits;

  function depositTo(
    address account
  ) external payable {
    deposits[account] += msg.value;
    emit Deposited(account, msg.value);
  }

}

contract ERC4337v07Test is AdvTest {

  Factory public factory;
  MockEntryPoint public entryPoint;
  Stage1Module public stage1Module;
  address payable public wallet;
  string public walletConfig;
  bytes32 public walletImageHash;
  uint256 public signerPk;
  address public signer;

  function setUp() public {
    factory = new Factory();
    entryPoint = new MockEntryPoint();
    stage1Module = new Stage1Module(address(factory), address(entryPoint));

    // Basic wallet setup for most tests.
    signerPk = boundPk(123);
    signer = vm.addr(signerPk);
    walletConfig = PrimitivesRPC.newConfig(vm, 1, 0, string(abi.encodePacked("signer:", vm.toString(signer), ":1")));
    walletImageHash = PrimitivesRPC.getImageHash(vm, walletConfig);
    wallet = payable(factory.deploy(address(stage1Module), walletImageHash));
  }

  // --- Helper Functions ---

  function _createUserOp(
    bytes memory _callData,
    bytes memory _signature
  ) internal view returns (PackedUserOperation memory) {
    return PackedUserOperation({
      sender: wallet,
      nonce: 0, // Nonce is validated by the real entrypoint, not the account.
      initCode: "",
      callData: _callData,
      accountGasLimits: bytes32(0),
      preVerificationGas: 21000,
      gasFees: bytes32(0),
      paymasterAndData: "",
      signature: _signature
    });
  }

  // --- validateUserOp Tests ---

  function test_validateUserOp_reverts_if_disabled(
    PackedUserOperation calldata userOp,
    bytes32 userOpHash,
    uint256 missingFunds
  ) public {
    // Deploy a new wallet with 4337 disabled (entrypoint is address(0)).
    Stage1Module moduleDisabled = new Stage1Module(address(factory), address(0));
    address payable walletDisabled = payable(factory.deploy(address(moduleDisabled), walletImageHash));

    vm.prank(address(entryPoint));
    vm.expectRevert(ERC4337v07.ERC4337Disabled.selector);
    Stage1Module(walletDisabled).validateUserOp(userOp, userOpHash, missingFunds);
  }

  function test_validateUserOp_reverts_invalidEntryPoint(
    PackedUserOperation calldata userOp,
    bytes32 userOpHash,
    uint256 missingFunds,
    address randomCaller
  ) public {
    vm.assume(randomCaller != address(entryPoint));

    vm.prank(randomCaller);
    vm.expectRevert(abi.encodeWithSelector(ERC4337v07.InvalidEntryPoint.selector, randomCaller));
    Stage1Module(wallet).validateUserOp(userOp, userOpHash, missingFunds);
  }

  function test_validateUserOp_depositsMissingFunds(bytes32 userOpHash, uint256 missingFunds) public {
    vm.assume(missingFunds > 0);
    // Signature doesn't need to be valid for this test.
    PackedUserOperation memory userOp = _createUserOp(bytes(""), hex"000010000000000000000000000000000000000000000000");

    // The wallet needs the funds *before* the call to be able to deposit them,
    // as validateUserOp is not payable.
    vm.deal(wallet, missingFunds);

    vm.prank(address(entryPoint));

    vm.expectEmit(true, true, false, true, address(entryPoint));
    emit MockEntryPoint.Deposited(wallet, missingFunds);

    // Call validateUserOp without sending value. The wallet will use its own balance to deposit.
    uint256 validationData = Stage1Module(wallet).validateUserOp(userOp, userOpHash, missingFunds);

    assertEq(validationData, 1, "Should return 1 for signature failure");
    assertEq(entryPoint.deposits(wallet), missingFunds, "Missing funds were not deposited correctly");
    assertEq(address(wallet).balance, 0, "Wallet should have used its balance for the deposit");
  }

  function test_validateUserOp_returns_zero_on_validSignature(
    bytes32 userOpHash
  ) public {
    // Create a signature for the userOpHash using the wallet's signer config.
    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_DIGEST;
    payload.digest = userOpHash;

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, Payload.hashFor(payload, wallet));
    string memory signatures =
      string(abi.encodePacked(vm.toString(signer), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v)));
    bytes memory encodedSignature = PrimitivesRPC.toEncodedSignature(vm, walletConfig, signatures, true);

    PackedUserOperation memory userOp = _createUserOp(bytes(""), encodedSignature);

    vm.prank(address(entryPoint));
    uint256 validationData = Stage1Module(wallet).validateUserOp(userOp, userOpHash, 0);

    assertEq(validationData, 0, "Should return 0 for a valid signature");
  }

  function test_validateUserOp_returns_one_on_invalidSignature(
    bytes32 userOpHash
  ) public {
    // Use a random, invalid signature provided by the fuzzer.
    PackedUserOperation memory userOp = _createUserOp(bytes(""), hex"000010000000000000000000000000000000000000000000");

    vm.prank(address(entryPoint));
    uint256 validationData = Stage1Module(wallet).validateUserOp(userOp, userOpHash, 0);

    assertEq(validationData, 1, "Should return 1 (SIG_VALIDATION_FAILED) for an invalid signature");
  }

  // --- executeUserOp Tests ---

  function test_executeUserOp_reverts_if_disabled(
    bytes calldata payload
  ) public {
    // Deploy a new wallet with 4337 disabled.
    Stage1Module moduleDisabled = new Stage1Module(address(factory), address(0));
    address payable walletDisabled = payable(factory.deploy(address(moduleDisabled), walletImageHash));

    vm.prank(address(entryPoint));
    vm.expectRevert(ERC4337v07.ERC4337Disabled.selector);
    Stage1Module(walletDisabled).executeUserOp(payload);
  }

  function test_executeUserOp_reverts_invalidEntryPoint(bytes calldata payload, address randomCaller) public {
    vm.assume(randomCaller != address(entryPoint));

    vm.prank(randomCaller);
    vm.expectRevert(abi.encodeWithSelector(ERC4337v07.InvalidEntryPoint.selector, randomCaller));
    Stage1Module(wallet).executeUserOp(payload);
  }

  function test_executeUserOp_executes_payload() external {
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

    // Expect the call to succeed and the event to be emitted from the Emitter contract.
    vm.expectEmit(true, false, false, true, address(emitter));
    emit Emitter.Explicit(wallet);

    // Execute the userOp via the entrypoint.
    vm.prank(address(entryPoint));
    Stage1Module(wallet).executeUserOp(packedPayload);
  }
}
