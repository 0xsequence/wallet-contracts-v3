// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { ERC20 } from "../../../lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import { Test } from "forge-std/Test.sol";

import { RecurringSessionSapientSigner } from "src/extensions/sessions/RecurringSessionSapientSigner.sol";
import { SessionErrors } from "src/extensions/sessions/SessionErrors.sol";
import { Calls } from "src/modules/Calls.sol";
import { Payload } from "src/modules/Payload.sol";

contract RecurringSessionWallet is Calls {

  bytes32 public imageHash;

  function setImageHash(
    bytes32 value
  ) external {
    imageHash = value;
  }

  function _isValidImage(
    bytes32 value
  ) internal view override returns (bool) {
    return value == imageHash;
  }

  function _updateImageHash(
    bytes32 value
  ) internal override {
    imageHash = value;
  }

}

contract RecurringSessionToken is ERC20 {

  constructor(
    address wallet
  ) ERC20("Test USDC", "USDC") {
    _mint(wallet, 1000e6);
  }

}

contract RecurringSessionSapientSignerTest is Test {

  RecurringSessionSapientSigner internal signer;
  RecurringSessionWallet internal wallet;
  RecurringSessionToken internal token;
  RecurringSessionSapientSigner.Policy internal policy;
  address internal constant RECIPIENT = address(0xBEEF);
  uint256 internal constant SESSION_KEY = 123;

  function setUp() public {
    signer = new RecurringSessionSapientSigner();
    wallet = new RecurringSessionWallet();
    token = new RecurringSessionToken(address(wallet));
    vm.warp(_timestamp(2026, 1));
    policy = RecurringSessionSapientSigner.Policy({
      signer: vm.addr(SESSION_KEY),
      chainId: block.chainid,
      token: address(token),
      recipient: RECIPIENT,
      limit: 100e6,
      start: uint64(block.timestamp),
      deadline: 0
    });
    _configure();
  }

  function test_execute_monthlySubscription(
    uint256 firstAmount,
    uint256 nextAmount,
    bool native
  ) public {
    policy.start = uint64(_timestamp(2026, 1) + 30 days + 10 hours + 23 minutes);
    if (native) {
      policy.token = address(0);
      policy.limit = 1 ether;
      vm.deal(address(wallet), 3 ether);
    }
    firstAmount = bound(firstAmount, 1, policy.limit);
    nextAmount = bound(nextAmount, 1, policy.limit);
    vm.warp(policy.start);
    _configure();
    _execute(_payload(firstAmount));
    assertEq(_usage(), firstAmount);

    Payload.Decoded memory payload = _payload(1);
    vm.expectRevert(RecurringSessionSapientSigner.SubscriptionAlreadyUsed.selector);
    _execute(payload);

    uint256 reset = _timestamp(2026, 2);
    vm.warp(reset - 1);
    vm.expectRevert(RecurringSessionSapientSigner.SubscriptionAlreadyUsed.selector);
    _execute(payload);
    vm.warp(reset);
    assertEq(_usage(), 0);
    _execute(_payload(nextAmount));
    assertEq(_usage(), nextAmount);
    assertEq(native ? RECIPIENT.balance : token.balanceOf(RECIPIENT), firstAmount + nextAmount);
  }

  function test_execute_unusedCapacityExpires() public {
    _execute(_payload(63e6));
    Payload.Decoded memory payload = _payload(37e6);
    vm.expectRevert(RecurringSessionSapientSigner.SubscriptionAlreadyUsed.selector);
    _execute(payload);

    vm.warp(_timestamp(2026, 6));
    assertEq(_usage(), 0);
    payload = _payload(100e6 + 1);
    vm.expectPartialRevert(RecurringSessionSapientSigner.SpendLimitExceeded.selector);
    _execute(payload);
    _execute(_payload(100e6));
    assertEq(_usage(), 100e6);
  }

  function test_execute_rejectsZeroOverCapAndMultiplePayments(
    bool native
  ) public {
    if (native) {
      policy.token = address(0);
      vm.deal(address(wallet), policy.limit);
      _configure();
    }
    Payload.Decoded memory payload = _payload(0);
    vm.expectRevert(RecurringSessionSapientSigner.InvalidPayment.selector);
    _execute(payload);

    payload = _payload(policy.limit + 1);
    vm.expectPartialRevert(RecurringSessionSapientSigner.SpendLimitExceeded.selector);
    _execute(payload);

    payload = _payload(63e6);
    Payload.Call[] memory calls = new Payload.Call[](3);
    calls[0] = payload.calls[0];
    calls[1] = _payment(30e6);
    calls[2] = _payment(33e6);
    payload.calls = calls;
    vm.expectRevert(SessionErrors.InvalidCallsLength.selector);
    _execute(payload);

    assertEq(_usage(), 0);
    _execute(_payload(63e6));
    assertEq(_usage(), 63e6);
  }

  function test_execute_rejectsIncorrectAccounting(
    uint8 variant
  ) public {
    variant = uint8(bound(variant, 0, 5));
    Payload.Decoded memory payload = _payload(10e6);
    if (variant == 0) {
      payload.calls[0].data = abi.encodeCall(signer.consumeUsage, (_policyHash(), signer.currentPeriod(policy), 1));
    } else if (variant == 1) {
      payload.calls[0].data =
        abi.encodeCall(signer.consumeUsage, (_policyHash(), signer.currentPeriod(policy) + 1, 10e6));
    } else if (variant == 2) {
      payload.calls[0].data = abi.encodeCall(signer.consumeUsage, (bytes32(0), signer.currentPeriod(policy), 10e6));
    } else if (variant == 3) {
      payload.calls[0].to = RECIPIENT;
    } else if (variant == 4) {
      payload.calls[0].value = 1;
    } else {
      payload.calls[0].data = "";
    }
    vm.expectRevert(SessionErrors.InvalidLimitUsageIncrement.selector);
    _execute(payload);
    assertEq(_usage(), 0);
    assertEq(token.balanceOf(RECIPIENT), 0);
  }

  function test_execute_rejectsUnsafeCalls(
    uint8 variant,
    bool accountingCall
  ) public {
    variant = uint8(bound(variant, 0, 4));
    Payload.Decoded memory payload = _payload(10e6);
    uint256 index = accountingCall ? 0 : 1;
    bytes4 expected = SessionErrors.InvalidBehavior.selector;
    if (variant == 0) {
      payload.calls[index].delegateCall = true;
      expected = SessionErrors.InvalidDelegateCall.selector;
    } else if (variant == 1) {
      payload.calls[index].onlyFallback = true;
    } else if (variant == 2) {
      payload.calls[index].behaviorOnError = Payload.BEHAVIOR_IGNORE_ERROR;
    } else if (variant == 3) {
      payload.calls[index].behaviorOnError = Payload.BEHAVIOR_ABORT_ON_ERROR;
    } else {
      payload.calls[index].to = address(wallet);
      expected = SessionErrors.InvalidSelfCall.selector;
    }
    vm.expectRevert(expected);
    _execute(payload);
  }

  function test_execute_rejectsPaymentsOutsidePolicy(
    uint8 variant
  ) public {
    variant = uint8(bound(variant, 0, 4));
    Payload.Decoded memory payload = _payload(10e6);
    if (variant == 0) {
      payload.calls[1].to = address(0xCAFE);
    } else if (variant == 1) {
      payload.calls[1].data = abi.encodeCall(token.transfer, (address(0xCAFE), 10e6));
    } else if (variant == 2) {
      payload.calls[1].data = abi.encodeCall(token.approve, (RECIPIENT, 10e6));
    } else if (variant == 3) {
      payload.calls[1].value = 1;
    } else {
      payload.calls[1].data = hex"a9059cbb";
    }
    vm.expectRevert(RecurringSessionSapientSigner.InvalidPayment.selector);
    _execute(payload);
  }

  function test_execute_rejectsExtraAccountingCall() public {
    Payload.Decoded memory payload = _payload(10e6);
    payload.calls[1] = payload.calls[0];
    vm.expectRevert(SessionErrors.InvalidSelfCall.selector);
    _execute(payload);
  }

  function test_execute_rejectsOldPeriodSignature() public {
    Payload.Decoded memory payload = _payload(10e6);
    bytes memory signature = _signature(payload);
    vm.warp(_timestamp(2026, 2));
    vm.expectRevert(SessionErrors.InvalidLimitUsageIncrement.selector);
    wallet.execute(_pack(payload), signature);
    assertEq(_usage(), 0);
  }

  function test_execute_rollsBackUsageWhenPaymentReverts() public {
    uint256 balance = token.balanceOf(address(wallet));
    vm.prank(address(wallet));
    token.transfer(RECIPIENT, balance);
    Payload.Decoded memory payload = _payload(10e6);
    vm.expectPartialRevert(Calls.Reverted.selector);
    _execute(payload);
    assertEq(_usage(), 0);
    assertEq(wallet.readNonce(0), 0);
    vm.prank(RECIPIENT);
    token.transfer(address(wallet), balance);
    _execute(payload);
    assertEq(_usage(), 10e6);
  }

  function test_execute_requiresConfiguredPolicyAndSupportsRevocation() public {
    _execute(_payload(10e6));
    policy.limit = 200e6;
    Payload.Decoded memory payload = _payload(150e6);
    vm.expectPartialRevert(Calls.InvalidSignature.selector);
    _execute(payload);
    policy.limit = 100e6;
    vm.warp(_timestamp(2026, 2));
    wallet.setImageHash(bytes32(0));
    payload = _payload(10e6);
    vm.expectPartialRevert(Calls.InvalidSignature.selector);
    _execute(payload);
  }

  function test_execute_checksStartExpiryAndChain() public {
    policy.deadline = policy.start + 1 days;
    _configure();
    Payload.Decoded memory payload = _payload(10e6);
    vm.warp(uint256(policy.start) - 1);
    vm.expectPartialRevert(RecurringSessionSapientSigner.SessionNotStarted.selector);
    _execute(payload);
    vm.warp(policy.deadline);
    _execute(payload);
    payload = _payload(10e6);
    vm.warp(uint256(policy.deadline) + 1);
    vm.expectPartialRevert(SessionErrors.SessionExpired.selector);
    _execute(payload);
    vm.warp(policy.start);
    vm.chainId(block.chainid + 1);
    vm.expectPartialRevert(SessionErrors.InvalidChainId.selector);
    _execute(payload);
  }

  function test_execute_rejectsReplayAndTamperedPayment() public {
    Payload.Decoded memory payload = _payload(10e6);
    bytes memory signature = _signature(payload);
    wallet.execute(_pack(payload), signature);
    vm.expectRevert();
    wallet.execute(_pack(payload), signature);

    vm.warp(_timestamp(2026, 2));
    payload = _payload(10e6);
    signature = _signature(payload);
    payload.calls[1].gasLimit = 123456;
    vm.prank(address(wallet));
    vm.expectPartialRevert(SessionErrors.InvalidSessionSigner.selector);
    signer.recoverSapientSignature(payload, _innerSignature(signature));
  }

  function test_signature_bindsWalletAndParents() public {
    Payload.Decoded memory payload = _payload(10e6);
    bytes memory innerSignature = _innerSignature(_signature(payload));
    vm.prank(address(0xCAFE));
    vm.expectPartialRevert(SessionErrors.InvalidSessionSigner.selector);
    signer.recoverSapientSignature(payload, innerSignature);

    payload.parentWallets = new address[](1);
    payload.parentWallets[0] = address(0xCAFE);
    vm.prank(address(wallet));
    vm.expectPartialRevert(SessionErrors.InvalidSessionSigner.selector);
    signer.recoverSapientSignature(payload, innerSignature);
  }

  function test_usage_isIsolatedByWalletAndPolicy() public {
    _execute(_payload(60e6));
    bytes32 originalPolicy = _policyHash();
    uint256 period = signer.currentPeriod(policy);
    vm.prank(RECIPIENT);
    signer.consumeUsage(originalPolicy, period, 100e6);
    assertEq(_usage(), 60e6);

    policy.recipient = address(0xCAFE);
    _configure();
    assertEq(_usage(), 0);
    _execute(_payload(100e6));
    assertEq(signer.usage(address(wallet), originalPolicy, period), 60e6);
    assertEq(_usage(), 100e6);
  }

  function test_execute_nestedWalletAccountsAgainstExecutor() public {
    RecurringSessionWallet parent = new RecurringSessionWallet();
    parent.setImageHash(_walletImageHash(address(wallet), bytes32(uint256(1))));
    vm.prank(address(wallet));
    token.transfer(address(parent), 200e6);

    Payload.Decoded memory payload = _payload(100e6);
    payload.parentWallets = new address[](1);
    payload.parentWallets[0] = address(parent);
    bytes memory signature = _signature(payload);
    bytes memory parentSignature = abi.encodePacked(hex"000199", address(wallet), uint16(signature.length), signature);
    parent.execute(_pack(payload), parentSignature);
    assertEq(token.balanceOf(RECIPIENT), 100e6);
    assertEq(signer.usage(address(parent), _policyHash(), signer.currentPeriod(policy)), 100e6);
    assertEq(_usage(), 0);

    payload.nonce = parent.readNonce(0);
    signature = _signature(payload);
    parentSignature = abi.encodePacked(hex"000199", address(wallet), uint16(signature.length), signature);
    vm.expectRevert(RecurringSessionSapientSigner.SubscriptionAlreadyUsed.selector);
    parent.execute(_pack(payload), parentSignature);
    assertEq(token.balanceOf(RECIPIENT), 100e6);
  }

  function test_rejectsDigestAndMissingPaymentAndReservedSpace() public {
    Payload.Decoded memory payload = _payload(10e6);
    bytes memory signature = _innerSignature(_signature(payload));
    payload.kind = Payload.KIND_DIGEST;
    vm.expectRevert(SessionErrors.InvalidPayloadKind.selector);
    signer.recoverSapientSignature(payload, signature);
    payload.kind = Payload.KIND_TRANSACTIONS;
    payload.space = signer.MAX_SPACE() + 1;
    vm.expectPartialRevert(SessionErrors.InvalidSpace.selector);
    signer.recoverSapientSignature(payload, signature);
    payload.space = 0;
    payload.calls = new Payload.Call[](1);
    vm.expectRevert(SessionErrors.InvalidCallsLength.selector);
    signer.recoverSapientSignature(payload, signature);
  }

  function test_currentPeriod_calendarBoundaries(
    uint256 year,
    uint256 month
  ) public {
    year = bound(year, 1970, 2500);
    month = bound(month, 1, 12);
    policy.start = 0;
    uint256 start = _timestamp(year, month);
    vm.warp(start);
    assertEq(signer.currentPeriod(policy), year * 12 + month - 1);
    if (start != 0) {
      vm.warp(start - 1);
      assertEq(signer.currentPeriod(policy), year * 12 + month - 2);
    }
  }

  function test_currentPeriod_leapAndCenturyBoundaries() public {
    policy.start = 0;
    uint256[5] memory yearsToCheck = [uint256(2000), 2024, 2026, 2100, 2400];
    for (uint256 i = 0; i < yearsToCheck.length; i++) {
      uint256 march = _timestamp(yearsToCheck[i], 3);
      vm.warp(march - 1);
      assertEq(signer.currentPeriod(policy), yearsToCheck[i] * 12 + 1);
      vm.warp(march);
      assertEq(signer.currentPeriod(policy), yearsToCheck[i] * 12 + 2);
    }
  }

  function test_currentPeriod_atEpoch() public {
    policy.start = 0;
    vm.warp(0);
    assertEq(signer.currentPeriod(policy), 1970 * 12);
    vm.warp(31 days - 1);
    assertEq(signer.currentPeriod(policy), 1970 * 12);
    vm.warp(31 days);
    assertEq(signer.currentPeriod(policy), 1970 * 12 + 1);
  }

  function _configure() internal {
    wallet.setImageHash(_walletImageHash(address(signer), _policyHash()));
  }

  function _walletImageHash(
    address sapient,
    bytes32 policyHash
  ) internal pure returns (bytes32) {
    bytes32 imageHash = keccak256(abi.encodePacked("Sequence sapient config:\n", sapient, uint256(1), policyHash));
    imageHash = keccak256(abi.encode(imageHash, uint256(1)));
    imageHash = keccak256(abi.encode(imageHash, uint256(0)));
    return keccak256(abi.encode(imageHash, uint256(0)));
  }

  function _policyHash() internal view returns (bytes32) {
    return keccak256(abi.encode(policy));
  }

  function _usage() internal view returns (uint256) {
    return signer.usage(address(wallet), _policyHash(), signer.currentPeriod(policy));
  }

  function _payload(
    uint256 amount
  ) internal view returns (Payload.Decoded memory payload) {
    payload.kind = Payload.KIND_TRANSACTIONS;
    payload.nonce = wallet.readNonce(0);
    payload.calls = new Payload.Call[](2);
    payload.calls[0].to = address(signer);
    payload.calls[0].behaviorOnError = Payload.BEHAVIOR_REVERT_ON_ERROR;
    payload.calls[0].data = abi.encodeCall(signer.consumeUsage, (_policyHash(), signer.currentPeriod(policy), amount));
    payload.calls[1] = _payment(amount);
  }

  function _payment(
    uint256 amount
  ) internal view returns (Payload.Call memory call) {
    call.behaviorOnError = Payload.BEHAVIOR_REVERT_ON_ERROR;
    if (policy.token == address(0)) {
      call.to = policy.recipient;
      call.value = amount;
    } else {
      call.to = policy.token;
      call.data = abi.encodeCall(token.transfer, (policy.recipient, amount));
    }
  }

  function _signature(
    Payload.Decoded memory payload
  ) internal view returns (bytes memory) {
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(SESSION_KEY, Payload.hashFor(payload, address(wallet)));
    bytes memory signature = abi.encode(RecurringSessionSapientSigner.Signature(policy, abi.encodePacked(r, s, v)));
    // Normal signature, threshold 1, sapient leaf of weight 1 with a two-byte signature length.
    return abi.encodePacked(hex"000199", address(signer), uint16(signature.length), signature);
  }

  function _innerSignature(
    bytes memory signature
  ) internal pure returns (bytes memory inner) {
    inner = new bytes(signature.length - 25);
    for (uint256 i = 0; i < inner.length; i++) {
      inner[i] = signature[i + 25];
    }
  }

  function _execute(
    Payload.Decoded memory payload
  ) internal {
    wallet.execute(_pack(payload), _signature(payload));
  }

  function _pack(
    Payload.Decoded memory payload
  ) internal pure returns (bytes memory packed) {
    // Zero nonce space, seven-byte nonce and one-byte call count.
    packed = abi.encodePacked(uint8(0x0f), uint56(payload.nonce), uint8(payload.calls.length));
    for (uint256 i = 0; i < payload.calls.length; i++) {
      Payload.Call memory call = payload.calls[i];
      uint8 flags = 0x06 | uint8(call.behaviorOnError << 6);
      if (call.delegateCall) {
        flags |= 0x10;
      }
      if (call.onlyFallback) {
        flags |= 0x20;
      }
      packed = abi.encodePacked(packed, flags, call.to, call.value, uint24(call.data.length), call.data);
    }
  }

  // Independent, simple Gregorian reference for the production constant-time month calculation.
  function _timestamp(
    uint256 year,
    uint256 month
  ) internal pure returns (uint256) {
    uint256 daysSinceEpoch;
    for (uint256 y = 1970; y < year; y++) {
      daysSinceEpoch += _leapYear(y) ? 366 : 365;
    }
    for (uint256 m = 1; m < month; m++) {
      daysSinceEpoch += _daysInMonth(year, m);
    }
    return daysSinceEpoch * 1 days;
  }

  function _daysInMonth(
    uint256 year,
    uint256 month
  ) internal pure returns (uint256) {
    uint256[12] memory monthDays = [uint256(31), 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    return monthDays[month - 1] + (month == 2 && _leapYear(year) ? 1 : 0);
  }

  function _leapYear(
    uint256 year
  ) internal pure returns (bool) {
    return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
  }

}
