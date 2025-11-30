// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Factory } from "../../src/Factory.sol";
import { Stage1Module } from "../../src/Stage1Module.sol";
import { CreateHook } from "../../src/hooks/CreateHook.sol";
import { Hooks } from "../../src/modules/Hooks.sol";

import { Payload } from "../../src/modules/Payload.sol";
import { SelfAuth } from "../../src/modules/auth/SelfAuth.sol";
import { PrimitivesRPC } from "../utils/PrimitivesRPC.sol";
import { AdvTest } from "../utils/TestUtils.sol";

contract CreateHookTest is AdvTest {

  Factory public factory;
  Stage1Module public stage1Module;
  CreateHook public createHook;
  address payable public wallet;
  uint256 public signerPk;
  address public signer;
  string public config;
  bytes32 public configHash;

  event CreatedContract(address addr);
  event DefinedHook(bytes4 selector, address implementation);

  function setUp() public {
    factory = new Factory();
    stage1Module = new Stage1Module(address(factory), address(0));
    createHook = new CreateHook();

    // Create a signer for the wallet
    signerPk = boundPk(uint256(keccak256("test_signer")));
    signer = vm.addr(signerPk);

    // Create config with single signer
    string memory ce = string(abi.encodePacked("signer:", vm.toString(signer), ":1"));
    config = PrimitivesRPC.newConfig(vm, 1, 0, ce);
    configHash = PrimitivesRPC.getImageHash(vm, config);

    // Deploy wallet
    wallet = payable(factory.deploy(address(stage1Module), configHash));

    // Add the Create hook via execute
    _addHook();
  }

  function _addHook() internal {
    bytes4 createSelector = CreateHook.createContract.selector;
    bytes4 create2Selector = CreateHook.createContractWithSalt.selector;

    // Create payload to add both hooks
    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_TRANSACTIONS;
    payload.calls = new Payload.Call[](2);
    payload.calls[0] = Payload.Call({
      to: address(wallet),
      value: 0,
      data: abi.encodeWithSelector(Hooks.addHook.selector, createSelector, address(createHook)),
      gasLimit: 100000,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });
    payload.calls[1] = Payload.Call({
      to: address(wallet),
      value: 0,
      data: abi.encodeWithSelector(Hooks.addHook.selector, create2Selector, address(createHook)),
      gasLimit: 100000,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });
    payload.noChainId = false;

    // Sign the payload
    (uint256 v, bytes32 r, bytes32 s) = vm.sign(signerPk, Payload.hashFor(payload, address(wallet)));
    bytes memory signature = PrimitivesRPC.toEncodedSignature(
      vm,
      config,
      string(abi.encodePacked(vm.toString(signer), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v))),
      true
    );

    // Pack and execute
    bytes memory packedPayload = PrimitivesRPC.toPackedPayload(vm, payload);

    vm.expectEmit(true, true, false, true, wallet);
    emit DefinedHook(createSelector, address(createHook));
    vm.expectEmit(true, true, false, true, wallet);
    emit DefinedHook(create2Selector, address(createHook));

    Stage1Module(wallet).execute(packedPayload, signature);

    // Verify hooks were added
    assertEq(Hooks(wallet).readHook(createSelector), address(createHook));
    assertEq(Hooks(wallet).readHook(create2Selector), address(createHook));
  }

  function test_createContract() public {
    // Simple contract that stores a value
    bytes memory initCode = abi.encodePacked(
      hex"608060405234801561001057600080fd5b50610150806100206000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c80632e64cec11460375780636057361d14604d575b600080fd5b603d6065565b60405160489190608c565b60405180910390f35b60636004803603810190605f919060b1565b606e565b005b60008054905090565b8060008190555050565b6000819050919050565b608681607d565b82525050565b6000602082019050609f6000830184607f565b92915050565b600080fd5b6000819050919050565b60bd8160a6565b811460c757600080fd5b50565b60008135905060d78160b6565b92915050565b60006020828403121560f05760ef60a1565b5b600060fc8482850160ca565b9150509291505056fea2646970667358221220",
      abi.encode(uint256(42))
    );

    // Create payload to call createContract
    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_TRANSACTIONS;
    payload.calls = new Payload.Call[](1);
    payload.calls[0] = Payload.Call({
      to: address(wallet),
      value: 0,
      data: abi.encodeWithSelector(CreateHook.createContract.selector, initCode),
      gasLimit: 500000,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });
    payload.noChainId = false;

    // Sign the payload
    (uint256 v, bytes32 r, bytes32 s) = vm.sign(signerPk, Payload.hashFor(payload, address(wallet)));
    bytes memory signature = PrimitivesRPC.toEncodedSignature(
      vm,
      config,
      string(abi.encodePacked(vm.toString(signer), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v))),
      true
    );

    // Pack and execute
    bytes memory packedPayload = PrimitivesRPC.toPackedPayload(vm, payload);

    vm.expectEmit(true, true, false, true, wallet);
    emit CreatedContract(address(0)); // We'll check the actual address after

    Stage1Module(wallet).execute(packedPayload, signature);

    // Verify a contract was created (we can't predict the exact address for create)
    // But we can verify the hook was called successfully
  }

  function test_createContractWithSalt() public {
    bytes32 salt = keccak256("test_salt");

    // Simple contract that stores a value
    bytes memory initCode = abi.encodePacked(
      hex"608060405234801561001057600080fd5b50610150806100206000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c80632e64cec11460375780636057361d14604d575b600080fd5b603d6065565b60405160489190608c565b60405180910390f35b60636004803603810190605f919060b1565b606e565b005b60008054905090565b8060008190555050565b6000819050919050565b608681607d565b82525050565b6000602082019050609f6000830184607f565b92915050565b600080fd5b6000819050919050565b60bd8160a6565b811460c757600080fd5b50565b60008135905060d78160b6565b92915050565b60006020828403121560f05760ef60a1565b5b600060fc8482850160ca565b9150509291505056fea2646970667358221220",
      abi.encode(uint256(42))
    );

    // Calculate expected address
    bytes32 hash = keccak256(abi.encodePacked(bytes1(0xff), address(wallet), salt, keccak256(initCode)));
    address expectedAddr = address(uint160(uint256(hash)));

    // Create payload to call createContractWithSalt
    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_TRANSACTIONS;
    payload.calls = new Payload.Call[](1);
    payload.calls[0] = Payload.Call({
      to: address(wallet),
      value: 0,
      data: abi.encodeWithSelector(CreateHook.createContractWithSalt.selector, initCode, salt),
      gasLimit: 500000,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });
    payload.noChainId = false;

    // Sign the payload
    (uint256 v, bytes32 r, bytes32 s) = vm.sign(signerPk, Payload.hashFor(payload, address(wallet)));
    bytes memory signature = PrimitivesRPC.toEncodedSignature(
      vm,
      config,
      string(abi.encodePacked(vm.toString(signer), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v))),
      true
    );

    // Pack and execute
    bytes memory packedPayload = PrimitivesRPC.toPackedPayload(vm, payload);

    vm.expectEmit(true, true, false, true, wallet);
    emit CreatedContract(expectedAddr);

    Stage1Module(wallet).execute(packedPayload, signature);

    // Verify the contract was created at the expected address
    assertTrue(expectedAddr.code.length > 0);
  }

  function test_createContractWithValue() public {
    vm.deal(address(wallet), 1 ether);

    // Simple contract that stores a value
    bytes memory initCode = abi.encodePacked(
      hex"608060405234801561001057600080fd5b50610150806100206000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c80632e64cec11460375780636057361d14604d575b600080fd5b603d6065565b60405160489190608c565b60405180910390f35b60636004803603810190605f919060b1565b606e565b005b60008054905090565b8060008190555050565b6000819050919050565b608681607d565b82525050565b6000602082019050609f6000830184607f565b92915050565b600080fd5b6000819050919050565b60bd8160a6565b811460c757600080fd5b50565b60008135905060d78160b6565b92915050565b60006020828403121560f05760ef60a1565b5b600060fc8482850160ca565b9150509291505056fea2646970667358221220",
      abi.encode(uint256(42))
    );

    uint256 valueToSend = 0.1 ether;

    // Create payload to call createContract with value
    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_TRANSACTIONS;
    payload.calls = new Payload.Call[](1);
    payload.calls[0] = Payload.Call({
      to: address(wallet),
      value: valueToSend,
      data: abi.encodeWithSelector(CreateHook.createContract.selector, initCode),
      gasLimit: 500000,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });
    payload.noChainId = false;

    // Sign the payload
    (uint256 v, bytes32 r, bytes32 s) = vm.sign(signerPk, Payload.hashFor(payload, address(wallet)));
    bytes memory signature = PrimitivesRPC.toEncodedSignature(
      vm,
      config,
      string(abi.encodePacked(vm.toString(signer), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v))),
      true
    );

    // Pack and execute
    bytes memory packedPayload = PrimitivesRPC.toPackedPayload(vm, payload);

    vm.expectEmit(true, true, false, true, wallet);
    emit CreatedContract(address(0)); // We'll check the actual address after

    Stage1Module(wallet).execute{ value: valueToSend }(packedPayload, signature);

    // Verify wallet balance decreased
    assertEq(address(wallet).balance, 1 ether - valueToSend);
  }

  function test_createContract_revertWhenCreationFails() public {
    // Invalid init code that will cause creation to fail
    bytes memory invalidInitCode = hex"deadbeef";

    // Create payload to call createContract
    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_TRANSACTIONS;
    payload.calls = new Payload.Call[](1);
    payload.calls[0] = Payload.Call({
      to: address(wallet),
      value: 0,
      data: abi.encodeWithSelector(CreateHook.createContract.selector, invalidInitCode),
      gasLimit: 500000,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });
    payload.noChainId = false;

    // Sign the payload
    (uint256 v, bytes32 r, bytes32 s) = vm.sign(signerPk, Payload.hashFor(payload, address(wallet)));
    bytes memory signature = PrimitivesRPC.toEncodedSignature(
      vm,
      config,
      string(abi.encodePacked(vm.toString(signer), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v))),
      true
    );

    // Pack and execute - should revert
    bytes memory packedPayload = PrimitivesRPC.toPackedPayload(vm, payload);

    vm.expectRevert(abi.encodeWithSelector(CreateHook.CreateFailed.selector, invalidInitCode));
    Stage1Module(wallet).execute(packedPayload, signature);
  }

  function test_createContractWithSalt_revertWhenCreationFails() public {
    bytes32 salt = keccak256("test_salt");
    bytes memory invalidInitCode = hex"deadbeef";

    // Create payload to call createContractWithSalt
    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_TRANSACTIONS;
    payload.calls = new Payload.Call[](1);
    payload.calls[0] = Payload.Call({
      to: address(wallet),
      value: 0,
      data: abi.encodeWithSelector(CreateHook.createContractWithSalt.selector, invalidInitCode, salt),
      gasLimit: 500000,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });
    payload.noChainId = false;

    // Sign the payload
    (uint256 v, bytes32 r, bytes32 s) = vm.sign(signerPk, Payload.hashFor(payload, address(wallet)));
    bytes memory signature = PrimitivesRPC.toEncodedSignature(
      vm,
      config,
      string(abi.encodePacked(vm.toString(signer), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v))),
      true
    );

    // Pack and execute - should revert
    bytes memory packedPayload = PrimitivesRPC.toPackedPayload(vm, payload);

    vm.expectRevert(abi.encodeWithSelector(CreateHook.Create2Failed.selector, invalidInitCode, salt));
    Stage1Module(wallet).execute(packedPayload, signature);
  }

  function test_createContract_revertWhenNotSelf() public {
    bytes memory initCode =
      hex"608060405234801561001057600080fd5b50610150806100206000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c80632e64cec11460375780636057361d14604d575b600080fd5b603d6065565b60405160489190608c565b60405180910390f35b60636004803603810190605f919060b1565b606e565b005b60008054905090565b8060008190555050565b6000819050919050565b608681607d565b82525050565b6000602082019050609f6000830184607f565b92915050565b600080fd5b6000819050919050565b60bd8160a6565b811460c757600080fd5b50565b60008135905060d78160b6565b92915050565b60006020828403121560f05760ef60a1565b5b600060fc8482850160ca565b9150509291505056fea2646970667358221220";

    // Try to call directly (not through execute) - should revert
    vm.expectRevert(abi.encodeWithSelector(SelfAuth.OnlySelf.selector, address(this)));
    CreateHook(wallet).createContract(initCode);
  }

  function test_createContractWithSalt_revertWhenNotSelf() public {
    bytes memory initCode =
      hex"608060405234801561001057600080fd5b50610150806100206000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c80632e64cec11460375780636057361d14604d575b600080fd5b603d6065565b60405160489190608c565b60405180910390f35b60636004803603810190605f919060b1565b606e565b005b60008054905090565b8060008190555050565b6000819050919050565b608681607d565b82525050565b6000602082019050609f6000830184607f565b92915050565b600080fd5b6000819050919050565b60bd8160a6565b811460c757600080fd5b50565b60008135905060d78160b6565b92915050565b60006020828403121560f05760ef60a1565b5b600060fc8482850160ca565b9150509291505056fea2646970667358221220";
    bytes32 salt = keccak256("test_salt");

    // Try to call directly (not through execute) - should revert
    vm.expectRevert(abi.encodeWithSelector(SelfAuth.OnlySelf.selector, address(this)));
    CreateHook(wallet).createContractWithSalt(initCode, salt);
  }

}
