// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Stage7702Module } from "../src/Stage7702Module.sol";

import { Hooks } from "../src/modules/Hooks.sol";
import { Nonce } from "../src/modules/Nonce.sol";
import { ReentrancyGuard } from "../src/modules/ReentrancyGuard.sol";
import { BaseAuth } from "../src/modules/auth/BaseAuth.sol";
import { BaseSig } from "../src/modules/auth/BaseSig.sol";
import { Stage7702Auth } from "../src/modules/auth/Stage7702Auth.sol";
import { LibOptim } from "../src/utils/LibOptim.sol";
import { Test } from "forge-std/Test.sol";

/// @notice Delegate that writes arbitrary storage slots of whatever account it runs in
contract StoragePlanter {

  function plant(
    bytes32 _slot,
    bytes32 _value
  ) external {
    assembly {
      sstore(_slot, _value)
    }
  }

}

/// @notice EIP-7702 re-delegation does not clear account storage
/// @dev An EOA that was delegated to another implementation, including one it was phished into,
///      arrives at `Stage7702Module` with that implementation's storage still in place. These tests
///      plant values at the slots the module reads and show that the module honors them. There is no
///      contract fix here: delegating to Sequence must not be read as sanitizing the account, and
///      onboarding has to inspect the account before treating it as fresh.
contract Stage7702StoragePersistenceTest is Test {

  bytes32 internal constant IMAGE_HASH_KEY = keccak256("org.arcadeum.module.auth.upgradable.image.hash");
  bytes32 internal constant HOOKS_KEY = keccak256("org.arcadeum.module.hooks.hooks");
  bytes32 internal constant STATIC_SIGNATURE_KEY = keccak256("org.sequence.module.auth.static");
  bytes32 internal constant NONCE_KEY = keccak256("org.arcadeum.module.calls.nonce");
  bytes32 internal constant REENTRANCY_STATUS_KEY = keccak256("org.sequence.module.reentrancyguard.status");

  /// @dev `ReentrancyGuard._ENTERED`
  bytes32 internal constant ENTERED = bytes32(uint256(2));

  uint256 internal constant AUTHORITY_PK = uint256(keccak256("stage7702.storage.persistence.authority"));
  uint256 internal constant CLEAN_AUTHORITY_PK = uint256(keccak256("stage7702.storage.persistence.clean"));

  address internal constant MALICIOUS_HOOK = address(0xBAD);
  address internal constant ENTRY_POINT = address(0xEE);
  address internal constant DEFAULT_CHECKPOINTER = address(0);

  Stage7702Module internal module;
  StoragePlanter internal planter;

  address internal authority;
  address internal cleanAuthority;

  function setUp() public {
    module = new Stage7702Module(ENTRY_POINT, DEFAULT_CHECKPOINTER);
    planter = new StoragePlanter();
    authority = vm.addr(AUTHORITY_PK);
    cleanAuthority = vm.addr(CLEAN_AUTHORITY_PK);
  }

  /// @notice A planted image hash survives re-delegation and silently replaces the counterfactual config
  function test_plantedImageHash_survivesRedelegationToModule() external {
    bytes32 plantedImageHash = keccak256("attacker controlled configuration");

    _delegateTo(address(planter), AUTHORITY_PK);
    _plant(IMAGE_HASH_KEY, plantedImageHash);

    _delegateTo(address(module), AUTHORITY_PK);

    assertEq(Stage7702Auth(authority).imageHash(), plantedImageHash);
    assertTrue(plantedImageHash != _counterfactualImageHash(authority));
  }

  /// @notice An account whose storage was never touched does report the counterfactual config
  function test_untouchedAccount_reportsCounterfactualImageHash() external {
    _delegateTo(address(module), CLEAN_AUTHORITY_PK);

    assertEq(Stage7702Auth(cleanAuthority).imageHash(), _counterfactualImageHash(cleanAuthority));
  }

  /// @notice A planted hook survives re-delegation and stays reachable through the fallback
  function test_plantedHook_survivesRedelegationToModule() external {
    bytes4 selector = bytes4(keccak256("someHookedFunction()"));

    _delegateTo(address(planter), AUTHORITY_PK);
    _plant(_hooksSlot(selector), bytes32(uint256(uint160(MALICIOUS_HOOK))));

    _delegateTo(address(module), AUTHORITY_PK);
    _delegateTo(address(module), CLEAN_AUTHORITY_PK);

    assertEq(Hooks(payable(authority)).readHook(selector), MALICIOUS_HOOK);
    assertEq(Hooks(payable(cleanAuthority)).readHook(selector), address(0));
  }

  /// @notice A reentrancy status left at `_ENTERED` survives re-delegation and bricks `execute`
  function test_plantedReentrancyStatus_blocksExecute() external {
    _delegateTo(address(planter), AUTHORITY_PK);
    _plant(REENTRANCY_STATUS_KEY, ENTERED);

    _delegateTo(address(module), AUTHORITY_PK);

    // The guard runs in the modifier, before the payload is decoded, so any calldata reverts here
    vm.expectRevert(ReentrancyGuard.ReentrantCall.selector);
    Stage7702Module(payable(authority)).execute(hex"00", hex"");
  }

  /// @notice A planted static signature survives re-delegation
  function test_plantedStaticSignature_survivesRedelegationToModule() external {
    bytes32 opHash = keccak256("some operation");
    address caller = address(0xBAD1);
    uint96 expires = 1_000_000;

    _delegateTo(address(planter), AUTHORITY_PK);
    _plant(_staticSignatureSlot(opHash), bytes32(uint256(uint160(caller)) << 96 | uint256(expires)));

    _delegateTo(address(module), AUTHORITY_PK);

    (address storedCaller, uint256 storedExpires) = BaseAuth(authority).getStaticSignature(opHash);
    assertEq(storedCaller, caller);
    assertEq(storedExpires, expires);
  }

  /// @notice A planted nonce survives re-delegation
  function test_plantedNonce_survivesRedelegationToModule() external {
    uint256 space = 7;
    uint256 plantedNonce = 42;

    _delegateTo(address(planter), AUTHORITY_PK);
    _plant(_nonceSlot(space), bytes32(plantedNonce));

    _delegateTo(address(module), AUTHORITY_PK);

    assertEq(Nonce(authority).readNonce(space), plantedNonce);
  }

  function _delegateTo(
    address _delegate,
    uint256 _pk
  ) internal {
    vm.signAndAttachDelegation(_delegate, _pk);
  }

  /// @dev Runs `StoragePlanter` in the authority's context, so the write lands on the EOA
  function _plant(
    bytes32 _slot,
    bytes32 _value
  ) internal {
    StoragePlanter(authority).plant(_slot, _value);
  }

  /// @dev Same slot `Storage.writeBytes32Map(HOOKS_KEY, bytes32(selector), ...)` writes to
  function _hooksSlot(
    bytes4 _selector
  ) internal pure returns (bytes32) {
    return keccak256(abi.encode(HOOKS_KEY, bytes32(_selector)));
  }

  function _staticSignatureSlot(
    bytes32 _opHash
  ) internal pure returns (bytes32) {
    return keccak256(abi.encode(STATIC_SIGNATURE_KEY, _opHash));
  }

  function _nonceSlot(
    uint256 _space
  ) internal pure returns (bytes32) {
    return keccak256(abi.encode(NONCE_KEY, bytes32(_space)));
  }

  /// @dev What `imageHash()` returns when nothing is stored: the account as its own 1-of-1 signer
  function _counterfactualImageHash(
    address _account
  ) internal pure returns (bytes32) {
    bytes32 node = BaseSig._leafForAddressAndWeight(_account, 1);
    node = LibOptim.fkeccak256(node, bytes32(uint256(1)));
    node = LibOptim.fkeccak256(node, bytes32(uint256(0)));
    return LibOptim.fkeccak256(node, bytes32(uint256(uint160(DEFAULT_CHECKPOINTER))));
  }

}
