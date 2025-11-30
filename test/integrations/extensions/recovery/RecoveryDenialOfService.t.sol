// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Test, Vm } from "forge-std/Test.sol";

import { AcceptAll } from "test/mocks/AcceptAll.sol";
import { PrimitivesRPC } from "test/utils/PrimitivesRPC.sol";
import { AdvTest } from "test/utils/TestUtils.sol";

import { Factory } from "src/Factory.sol";
import { Stage1Module } from "src/Stage1Module.sol";
import { Recovery } from "src/extensions/recovery/Recovery.sol";

import { Nonce } from "src/modules/Nonce.sol";
import { Payload } from "src/modules/Payload.sol";

contract IntegrationRecoveryDenialOfService is AdvTest {

  Factory public factory;
  Stage1Module public module;
  Recovery public recovery;
  Vm.Wallet public eoaWallet;
  Vm.Wallet public recoveryWallet;
  AcceptAll public mockTarget;

  function setUp() public virtual {
    eoaWallet = vm.createWallet("eoa");
    recoveryWallet = vm.createWallet("recovery");
    recovery = new Recovery();
    factory = new Factory();
    module = new Stage1Module(address(factory), address(0));
    mockTarget = new AcceptAll();
  }

  struct Signer {
    address signer;
    uint24 requiredDeltaTime;
    uint64 minTimestamp;
  }

  function _createWalletWithSigner(
    Signer memory signer
  ) internal returns (Stage1Module wallet, string memory walletConfig, bytes memory recoveryConfig) {
    string memory leaves = string.concat(
      "signer:",
      vm.toString(signer.signer),
      ":",
      vm.toString(signer.requiredDeltaTime),
      ":",
      vm.toString(signer.minTimestamp)
    );
    recoveryConfig = PrimitivesRPC.recoveryEncode(vm, leaves);
    bytes32 recoveryImageHash = PrimitivesRPC.recoveryHashFromLeaves(vm, leaves);
    string memory ce =
      string(abi.encodePacked("sapient:", vm.toString(recoveryImageHash), ":", vm.toString(address(recovery)), ":1"));
    ce = string(abi.encodePacked(ce, " signer:", vm.toString(eoaWallet.addr), ":1"));
    walletConfig = PrimitivesRPC.newConfig(vm, 1, 0, ce);
    bytes32 imageHash = PrimitivesRPC.getImageHash(vm, walletConfig);
    wallet = Stage1Module(payable(factory.deploy(address(module), imageHash)));

    return (wallet, walletConfig, recoveryConfig);
  }

  function _validRecoverySignature(
    Stage1Module wallet,
    Payload.Decoded memory payload
  ) internal view returns (bytes memory signature) {
    bytes32 recoveryPayloadHash = recovery.recoveryPayloadHash(address(wallet), payload);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(recoveryWallet.privateKey, recoveryPayloadHash);
    bytes32 yParityAndS = bytes32((uint256(v - 27) << 255) | uint256(s));
    signature = abi.encodePacked(r, yParityAndS);
  }

  function _validWalletSignature(
    Payload.Decoded memory payload,
    string memory walletConfig,
    bytes memory recoveryConfig
  ) internal returns (bytes memory signature) {
    string memory signatures =
      string(abi.encodePacked(vm.toString(address(recovery)), ":sapient_compact:", vm.toString(recoveryConfig)));
    signature = PrimitivesRPC.toEncodedSignature(vm, walletConfig, signatures, !payload.noChainId);
  }

  function test_Recovery_Reexecution(
    uint160 space,
    uint64 minTimestamp,
    uint24 requiredDeltaTime
  ) public {
    minTimestamp = uint64(bound(minTimestamp, 1, type(uint64).max - requiredDeltaTime));
    vm.warp(minTimestamp);

    Signer memory signer =
      Signer({ signer: recoveryWallet.addr, requiredDeltaTime: requiredDeltaTime, minTimestamp: minTimestamp });
    (Stage1Module wallet, string memory walletConfig, bytes memory recoveryConfig) = _createWalletWithSigner(signer);

    // Prepare recovery payload
    Payload.Decoded memory recoveryPayload;
    recoveryPayload.kind = Payload.KIND_TRANSACTIONS;
    recoveryPayload.calls = new Payload.Call[](1);
    recoveryPayload.calls[0].to = address(mockTarget);
    recoveryPayload.space = space;

    // Queue recovery payload
    bytes memory recoverySignature = _validRecoverySignature(wallet, recoveryPayload);
    recovery.queuePayload(address(wallet), signer.signer, recoveryPayload, recoverySignature);

    // Wait the required time
    vm.warp(minTimestamp + requiredDeltaTime);

    // Execute the payload
    bytes memory walletSignature = _validWalletSignature(recoveryPayload, walletConfig, recoveryConfig);
    wallet.execute(PrimitivesRPC.toPackedPayload(vm, recoveryPayload), walletSignature);

    // Resubmission fails
    vm.expectRevert(abi.encodeWithSelector(Nonce.BadNonce.selector, recoveryPayload.space, recoveryPayload.nonce, 1));
    wallet.execute(PrimitivesRPC.toPackedPayload(vm, recoveryPayload), walletSignature);
  }

  function test_Recovery_DenialOfService(
    uint160 space,
    uint64 minTimestamp,
    uint24 requiredDeltaTime
  ) public {
    minTimestamp = uint64(bound(minTimestamp, 1, type(uint64).max - requiredDeltaTime));
    vm.warp(minTimestamp);

    Signer memory signer =
      Signer({ signer: recoveryWallet.addr, requiredDeltaTime: requiredDeltaTime, minTimestamp: minTimestamp });
    (Stage1Module wallet, string memory walletConfig, bytes memory recoveryConfig) = _createWalletWithSigner(signer);

    // Prepare recovery payload
    Payload.Decoded memory recoveryPayload;
    recoveryPayload.kind = Payload.KIND_TRANSACTIONS;
    recoveryPayload.calls = new Payload.Call[](1);
    recoveryPayload.calls[0].to = address(mockTarget);
    recoveryPayload.calls[0].data = "0x23456789";
    recoveryPayload.space = space;

    // Queue recovery payload
    bytes memory recoverySignature = _validRecoverySignature(wallet, recoveryPayload);
    recovery.queuePayload(address(wallet), signer.signer, recoveryPayload, recoverySignature);

    // Wait the required time
    vm.warp(minTimestamp + requiredDeltaTime);

    // Block it by having the EOA submit a payload
    Payload.Decoded memory eoaPayload;
    eoaPayload.kind = Payload.KIND_TRANSACTIONS;
    eoaPayload.calls = new Payload.Call[](1);
    eoaPayload.calls[0].to = address(mockTarget);
    eoaPayload.calls[0].data = "0x12345678";
    eoaPayload.space = space;

    // EOA sign
    bytes32 payloadHash = Payload.hashFor(eoaPayload, address(wallet));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(eoaWallet, payloadHash);
    string memory eoaSignatureStr = string(
      abi.encodePacked(vm.toString(eoaWallet.addr), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v))
    );
    bytes memory eoaSignature =
      PrimitivesRPC.toEncodedSignature(vm, walletConfig, eoaSignatureStr, !eoaPayload.noChainId);

    // Execute with EOA
    wallet.execute(PrimitivesRPC.toPackedPayload(vm, eoaPayload), eoaSignature);

    // Recovery fails
    bytes memory walletSignature = _validWalletSignature(recoveryPayload, walletConfig, recoveryConfig);
    vm.expectRevert(abi.encodeWithSelector(Nonce.BadNonce.selector, recoveryPayload.space, recoveryPayload.nonce, 1));
    wallet.execute(PrimitivesRPC.toPackedPayload(vm, recoveryPayload), walletSignature);
  }

  function test_Recovery_CallableByAnyone(
    uint160 space,
    uint64 minTimestamp,
    uint24 requiredDeltaTime,
    address queuer,
    address executor
  ) public {
    minTimestamp = uint64(bound(minTimestamp, 1, type(uint64).max - requiredDeltaTime));
    vm.warp(minTimestamp);

    Signer memory signer =
      Signer({ signer: recoveryWallet.addr, requiredDeltaTime: requiredDeltaTime, minTimestamp: minTimestamp });
    (Stage1Module wallet, string memory walletConfig, bytes memory recoveryConfig) = _createWalletWithSigner(signer);

    // Prepare recovery payload
    Payload.Decoded memory recoveryPayload;
    recoveryPayload.kind = Payload.KIND_TRANSACTIONS;
    recoveryPayload.calls = new Payload.Call[](1);
    recoveryPayload.calls[0].to = address(mockTarget);
    recoveryPayload.space = space;

    // Queue recovery payload
    bytes memory recoverySignature = _validRecoverySignature(wallet, recoveryPayload);
    vm.prank(queuer);
    recovery.queuePayload(address(wallet), signer.signer, recoveryPayload, recoverySignature);

    // Wait the required time
    vm.warp(minTimestamp + requiredDeltaTime);

    // Execute the payload
    bytes memory walletSignature = _validWalletSignature(recoveryPayload, walletConfig, recoveryConfig);
    vm.prank(executor);
    wallet.execute(PrimitivesRPC.toPackedPayload(vm, recoveryPayload), walletSignature);
  }

}
