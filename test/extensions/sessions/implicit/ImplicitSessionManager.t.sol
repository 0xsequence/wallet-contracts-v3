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
import { Emitter } from "test/mocks/Emitter.sol";
import { PrimitivesRPC } from "test/utils/PrimitivesRPC.sol";

contract ImplicitSessionManagerTest is SessionTestBase {

  using LibAttestation for Attestation;

  ImplicitSessionManagerHarness public sessionManager;
  Emitter public emitter;
  address public wallet;
  Vm.Wallet public sessionWallet;
  Vm.Wallet public identityWallet;

  function setUp() public {
    sessionManager = new ImplicitSessionManagerHarness();
    emitter = new Emitter();
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

  function test_validImplicitCall(
    Attestation memory attestation,
    address[] memory blacklist
  ) public view {
    // Ensure the blacklist doesn't contain the signer or call target
    for (uint256 i = 0; i < blacklist.length; i++) {
      vm.assume(blacklist[i] != sessionWallet.addr);
      vm.assume(blacklist[i] != address(emitter));
    }

    attestation.approvedSigner = sessionWallet.addr;
    Payload.Call memory call =
      _createCall(address(emitter), false, 0, abi.encodeWithSelector(Emitter.implicitEmit.selector));

    // Validate the call
    sessionManager.validateImplicitCall(call, wallet, sessionWallet.addr, attestation, blacklist);
  }

  function test_validImplicitCall_invalidSessionSigner(
    Attestation memory attestation
  ) public {
    vm.assume(attestation.approvedSigner != sessionWallet.addr);
    address[] memory blacklist = new address[](0);
    Payload.Call memory call =
      _createCall(address(emitter), false, 0, abi.encodeWithSelector(Emitter.implicitEmit.selector));

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
    // Ensure blacklist doesn't contain the emitter
    for (uint256 i = 0; i < blacklist.length; i++) {
      vm.assume(blacklist[i] != address(emitter));
    }
    // Blacklist the session signer
    randomIdx = bound(randomIdx, 0, blacklist.length - 1);
    blacklist[randomIdx] = sessionWallet.addr;
    // Sort the blacklist
    _sortAddressesMemory(blacklist);

    attestation.approvedSigner = sessionWallet.addr;
    Payload.Call memory call =
      _createCall(address(emitter), false, 0, abi.encodeWithSelector(Emitter.implicitEmit.selector));

    vm.expectRevert(abi.encodeWithSelector(SessionErrors.BlacklistedAddress.selector, sessionWallet.addr));
    sessionManager.validateImplicitCall(call, wallet, sessionWallet.addr, attestation, blacklist);
  }

  /// @notice Test for an unsorted blacklist skipping the binary search.
  function test_blacklist_unsortedSkipsBinarySearch(
    address[] memory blacklist
  ) public view {
    // Ensure not sorted
    bool isSorted = true;
    for (uint256 i = 0; i < blacklist.length; i++) {
      for (uint256 j = 0; j < blacklist.length - i - 1; j++) {
        if (blacklist[j] > blacklist[j + 1]) {
          isSorted = false;
          break;
        }
      }
    }
    vm.assume(!isSorted);

    bool missedBlacklist = false;
    for (uint256 i = 0; i < blacklist.length; i++) {
      if (sessionManager.isAddressBlacklisted(blacklist[i], blacklist)) {
        missedBlacklist = true;
        break;
      }
    }
    // Any unsorted blacklist WILL result in missed detection of a blacklisted address in the list
    assertEq(missedBlacklist, true);

    // Sorting the blacklist will result in all blacklisted addresses being detected
    _sortAddressesMemory(blacklist);
    for (uint256 i = 0; i < blacklist.length; i++) {
      assertEq(sessionManager.isAddressBlacklisted(blacklist[i], blacklist), true);
    }
  }

  /// @notice Test for delegateCall not allowed.
  function test_delegateCallNotAllowed(
    Attestation memory attestation
  ) public {
    attestation.approvedSigner = sessionWallet.addr;
    Payload.Call memory call =
      _createCall(address(emitter), true, 0, abi.encodeWithSelector(Emitter.implicitEmit.selector));
    address[] memory emptyBlacklist = new address[](0);

    vm.expectRevert(abi.encodeWithSelector(SessionErrors.InvalidDelegateCall.selector));
    sessionManager.validateImplicitCall(call, wallet, sessionWallet.addr, attestation, emptyBlacklist);
  }

  function test_nonZeroValueNotAllowed(
    Attestation memory attestation,
    uint256 nonZeroValue
  ) public {
    vm.assume(nonZeroValue > 0);
    attestation.approvedSigner = sessionWallet.addr;
    Payload.Call memory call =
      _createCall(address(emitter), false, nonZeroValue, abi.encodeWithSelector(Emitter.implicitEmit.selector));
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
    blacklist[randomIdx] = address(emitter);
    // Ensure the signer isn't blacklisted
    for (uint256 i = 0; i < blacklist.length; i++) {
      vm.assume(blacklist[i] != sessionWallet.addr);
    }
    // Sort the blacklist so that binary search in the contract works correctly.
    _sortAddressesMemory(blacklist);

    attestation.approvedSigner = sessionWallet.addr;
    Payload.Call memory call =
      _createCall(address(emitter), false, 0, abi.encodeWithSelector(Emitter.implicitEmit.selector));

    vm.expectRevert(abi.encodeWithSelector(SessionErrors.BlacklistedAddress.selector, address(emitter)));
    sessionManager.validateImplicitCall(call, wallet, sessionWallet.addr, attestation, blacklist);
  }

  function test_invalidImplicitResult(
    Attestation memory attestation
  ) public {
    attestation.approvedSigner = sessionWallet.addr;

    // Explicit emit is not approved
    Payload.Call memory call =
      _createCall(address(emitter), false, 0, abi.encodeWithSelector(Emitter.explicitEmit.selector));
    address[] memory emptyBlacklist = new address[](0);

    vm.expectRevert(abi.encodeWithSelector(SessionErrors.InvalidImplicitResult.selector));
    sessionManager.validateImplicitCall(call, wallet, sessionWallet.addr, attestation, emptyBlacklist);
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
  function isAddressBlacklisted(
    address target,
    address[] memory blacklist
  ) public pure returns (bool) {
    return _isAddressBlacklisted(target, blacklist);
  }

}
