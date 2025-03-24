// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Vm } from "forge-std/Test.sol";

import { SessionErrors } from "src/extensions/sessions/SessionErrors.sol";
import { SessionPermissions } from "src/extensions/sessions/explicit/IExplicitSessionManager.sol";
import { Attestation, LibAttestation } from "src/extensions/sessions/implicit/Attestation.sol";
import { ISignalsImplicitMode } from "src/extensions/sessions/implicit/ISignalsImplicitMode.sol";
import { ImplicitSessionManager } from "src/extensions/sessions/implicit/ImplicitSessionManager.sol";
import { ISapient, Payload } from "src/modules/interfaces/ISapient.sol";

import { SessionTestBase } from "test/extensions/sessions/SessionTestBase.sol";
import { MockImplicitContract, MockInvalidImplicitContract } from "test/mocks/MockImplicitContract.sol";
import { PrimitivesRPC } from "test/utils/PrimitivesRPC.sol";

contract ImplicitSessionManagerTest is SessionTestBase {

  using LibAttestation for Attestation;

  ImplicitSessionManagerHarness public sessionManager;
  MockImplicitContract public mockImplicit;
  address public wallet;
  Vm.Wallet public sessionWallet;
  Vm.Wallet public identityWallet;

  function setUp() public {
    sessionManager = new ImplicitSessionManagerHarness();
    mockImplicit = new MockImplicitContract();
    wallet = vm.createWallet("wallet").addr;
    sessionWallet = vm.createWallet("session");
    identityWallet = vm.createWallet("identity");
  }

  /// @dev Helper to create a Payload.Call.
  function _createCall(
    address to,
    bool delegateCall,
    uint256 value,
    bytes memory data
  ) internal pure returns (Payload.Call memory call) {
    call = Payload.Call({
      to: to,
      value: value,
      data: data,
      gasLimit: 0,
      delegateCall: delegateCall,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_IGNORE_ERROR
    });
  }

  function test_validImplicitCall(Attestation memory attestation, address[] memory blacklist) public view {
    // Ensure the blacklist doesn't contain the signer or call target
    for (uint256 i = 0; i < blacklist.length; i++) {
      vm.assume(blacklist[i] != sessionWallet.addr);
      vm.assume(blacklist[i] != address(mockImplicit));
    }

    attestation.approvedSigner = sessionWallet.addr;
    Payload.Call memory call = _createCall(address(mockImplicit), false, 0, "");

    // Validate the call
    sessionManager.validateImplicitCall(call, wallet, sessionWallet.addr, attestation, blacklist);
  }

  function test_validImplicitCall_invalidSessionSigner(
    Attestation memory attestation
  ) public {
    vm.assume(attestation.approvedSigner != sessionWallet.addr);
    address[] memory blacklist = new address[](0);
    Payload.Call memory call = _createCall(address(mockImplicit), false, 0, "");

    // Validate the call
    vm.expectRevert(abi.encodeWithSelector(SessionErrors.InvalidSessionSigner.selector, sessionWallet.addr));
    sessionManager.validateImplicitCall(call, wallet, sessionWallet.addr, attestation, blacklist);
  }

  function test_blacklistedSessionSignerNotAllowed(
    uint256 randomIdx,
    Attestation memory attestation,
    address[] memory blacklist
  ) public {
    // Blacklist the session signer
    vm.assume(blacklist.length > 0);
    // Ensure blacklist doesn't contain the mockImplicitContract
    for (uint256 i = 0; i < blacklist.length; i++) {
      vm.assume(blacklist[i] != address(mockImplicit));
    }
    // Blacklist the session signer
    randomIdx = bound(randomIdx, 0, blacklist.length - 1);
    blacklist[randomIdx] = sessionWallet.addr;
    // Sort the blacklist
    blacklist = _sortAddressesMemory(blacklist);

    attestation.approvedSigner = sessionWallet.addr;
    Payload.Call memory call = _createCall(address(mockImplicit), false, 0, "");

    vm.expectRevert(abi.encodeWithSelector(SessionErrors.BlacklistedAddress.selector, sessionWallet.addr));
    sessionManager.validateImplicitCall(call, wallet, sessionWallet.addr, attestation, blacklist);
  }

  /// @notice Test for delegateCall not allowed.
  function test_delegateCallNotAllowed(
    Attestation memory attestation
  ) public {
    attestation.approvedSigner = sessionWallet.addr;
    Payload.Call memory call = _createCall(address(mockImplicit), true, 0, "");
    address[] memory emptyBlacklist = new address[](0);

    vm.expectRevert(abi.encodeWithSelector(SessionErrors.InvalidDelegateCall.selector));
    sessionManager.validateImplicitCall(call, wallet, sessionWallet.addr, attestation, emptyBlacklist);
  }

  function test_nonZeroValueNotAllowed(Attestation memory attestation, uint256 nonZeroValue) public {
    vm.assume(nonZeroValue > 0);
    attestation.approvedSigner = sessionWallet.addr;
    Payload.Call memory call = _createCall(address(mockImplicit), false, nonZeroValue, "");
    address[] memory emptyBlacklist = new address[](0);

    vm.expectRevert(abi.encodeWithSelector(SessionErrors.InvalidValue.selector));
    sessionManager.validateImplicitCall(call, wallet, sessionWallet.addr, attestation, emptyBlacklist);
  }

  function test_blacklistedAddressNotAllowed(
    uint256 randomIdx,
    Attestation memory attestation,
    address[] memory blacklist
  ) public {
    // Force the blacklist to contain the call target.
    vm.assume(blacklist.length > 0);
    randomIdx = bound(randomIdx, 0, blacklist.length - 1);
    blacklist[randomIdx] = address(mockImplicit);
    // Ensure the signer isn't blacklisted
    for (uint256 i = 0; i < blacklist.length; i++) {
      vm.assume(blacklist[i] != sessionWallet.addr);
    }
    // Sort the blacklist so that binary search in the contract works correctly.
    blacklist = _sortAddressesMemory(blacklist);

    attestation.approvedSigner = sessionWallet.addr;
    Payload.Call memory call = _createCall(address(mockImplicit), false, 0, "");

    vm.expectRevert(abi.encodeWithSelector(SessionErrors.BlacklistedAddress.selector, address(mockImplicit)));
    sessionManager.validateImplicitCall(call, wallet, sessionWallet.addr, attestation, blacklist);
  }

  function test_invalidImplicitResult(
    Attestation memory attestation
  ) public {
    // Deploy a contract that returns an incorrect implicit result.
    MockInvalidImplicitContract invalidContract = new MockInvalidImplicitContract();
    vm.label(address(invalidContract), "invalidContract");

    attestation.approvedSigner = sessionWallet.addr;
    Payload.Call memory call = _createCall(address(invalidContract), false, 0, "");
    address[] memory emptyBlacklist = new address[](0);

    vm.expectRevert(abi.encodeWithSelector(SessionErrors.InvalidImplicitResult.selector));
    sessionManager.validateImplicitCall(call, wallet, sessionWallet.addr, attestation, emptyBlacklist);
  }

  // Helpers

  /// @notice Sorts an array of addresses in memory.
  /// @param addresses The array of addresses to sort.
  /// @return sortedAddresses The sorted array of addresses.
  function _sortAddressesMemory(
    address[] memory addresses
  ) internal pure returns (address[] memory) {
    // Sort the addresses using bubble sort.
    for (uint256 i = 0; i < addresses.length; i++) {
      for (uint256 j = 0; j < addresses.length - i - 1; j++) {
        if (addresses[j] > addresses[j + 1]) {
          address temp = addresses[j];
          addresses[j] = addresses[j + 1];
          addresses[j + 1] = temp;
        }
      }
    }
    return addresses;
  }

}

contract ImplicitSessionManagerHarness is ImplicitSessionManager {

  /// @notice Exposes the internal _validateImplicitCall function.
  function validateImplicitCall(
    Payload.Call calldata call,
    address wallet,
    address sessionSigner,
    Attestation memory attestation,
    address[] memory blacklist
  ) public view {
    _validateImplicitCall(call, wallet, sessionSigner, attestation, blacklist);
  }

  /// @notice Exposes the internal _isAddressBlacklisted function.
  function isAddressBlacklisted(address target, address[] memory blacklist) public pure returns (bool) {
    return _isAddressBlacklisted(target, blacklist);
  }

}
