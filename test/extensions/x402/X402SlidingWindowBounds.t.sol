// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Test, Vm } from "forge-std/Test.sol";

import { X402SessionSapientSigner } from "src/extensions/x402/X402SessionSapientSigner.sol";
import { Calls } from "src/modules/Calls.sol";
import { Payload } from "src/modules/Payload.sol";

contract X402SlidingWindowHarness is Calls {

  bytes32 public imageHash;

  function setImageHash(
    bytes32 newImageHash
  ) external {
    imageHash = newImageHash;
  }

  function _isValidImage(
    bytes32 candidate
  ) internal view override returns (bool) {
    return candidate != bytes32(0) && candidate == imageHash;
  }

  function _updateImageHash(
    bytes32 newImageHash
  ) internal override {
    imageHash = newImageHash;
  }

}

/// @notice Pins the exact number of Permit2 tape positions the sliding mask admits inside one `windowDuration`.
/// @dev The mask starts full at `windowStart` and its lower edge advances by `maxPayments` over one `windowDuration`,
///      so a single window admits up to `2 * maxPayments - 1` distinct positions even though only `maxPayments` are
///      live at any instant. Documented in docs/X402_SMART_SESSIONS.md sections 4 and 10.
contract X402SlidingWindowBoundsTest is Test {

  X402SessionSapientSigner internal signer;
  X402SlidingWindowHarness internal wallet;
  Vm.Wallet internal sessionKey;

  address internal constant PERMIT2 = address(0x000000000022D473030F116dDEE9F6B43aC78BA3);
  address internal constant X402_PERMIT2_PROXY = address(0x402085c248EeA27D92E8b30b2C58ed07f9E20001);
  address internal constant TOKEN = address(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
  address internal constant PAY_TO = address(0x209693Bc6afc0C5328bA36FaF03C514EF312287C);

  uint64 internal constant WINDOW_START = 1000;
  uint64 internal constant WINDOW_DURATION = 30 days;
  uint16 internal constant MAX_PAYMENTS = 5;

  function setUp() external {
    signer = new X402SessionSapientSigner(PERMIT2, X402_PERMIT2_PROXY);
    wallet = new X402SlidingWindowHarness();
    sessionKey = vm.createWallet("x402-sliding-window-key");
    vm.warp(WINDOW_START);
  }

  function test_currentNonceTapeRange_startsFullAtWindowStart() external view {
    (uint256 min, uint256 max) = signer.currentNonceTapeRange(_policy());

    assertEq(min, 0);
    assertEq(max, uint256(MAX_PAYMENTS) - 1);
  }

  /// @dev (a) exactly `maxPayments` positions validate at `windowStart`, and the next one is rejected.
  function test_recoverSapientSignature_admitsExactlyMaxPaymentsAtWindowStart() external {
    X402SessionSapientSigner.Policy memory policy = _policy();

    for (uint256 i = 0; i < MAX_PAYMENTS; i++) {
      assertTrue(_accepts(policy, i), "position inside the initial mask should be accepted");
    }

    _assertRejected(policy, MAX_PAYMENTS, 0, uint256(MAX_PAYMENTS) - 1);
  }

  /// @dev (b) and (c) one second before the first window closes the mask has slid by `maxPayments - 1`.
  function test_recoverSapientSignature_admitsShiftedMaskAtEndOfFirstWindow() external {
    X402SessionSapientSigner.Policy memory policy = _policy();
    vm.warp(uint256(WINDOW_START) + uint256(WINDOW_DURATION) - 1);

    (uint256 min, uint256 max) = signer.currentNonceTapeRange(policy);
    assertEq(min, 4, "lower edge advances by maxPayments - 1 within the first window");
    assertEq(max, 8, "upper edge is the lower edge plus maxPayments - 1");

    for (uint256 i = min; i <= max; i++) {
      assertTrue(_accepts(policy, i), "position inside the slid mask should be accepted");
    }

    assertFalse(_accepts(policy, min - 1), "position below the slid mask should be rejected");

    _assertRejected(policy, max + 1, min, max);
  }

  /// @dev (d) the union of the two instants is `2 * maxPayments - 1` distinct positions, not `maxPayments`.
  function test_recoverSapientSignature_admitsTwiceMaxPaymentsMinusOnePerWindow() external {
    X402SessionSapientSigner.Policy memory policy = _policy();
    uint256 probe = 3 * uint256(MAX_PAYMENTS);
    bool[] memory admitted = new bool[](probe);

    for (uint256 i = 0; i < probe; i++) {
      admitted[i] = _accepts(policy, i);
    }

    vm.warp(uint256(WINDOW_START) + uint256(WINDOW_DURATION) - 1);
    for (uint256 i = 0; i < probe; i++) {
      admitted[i] = admitted[i] || _accepts(policy, i);
    }

    uint256 distinct;
    for (uint256 i = 0; i < probe; i++) {
      if (admitted[i]) {
        distinct++;
      }
    }

    assertEq(distinct, 2 * uint256(MAX_PAYMENTS) - 1, "one window admits 2 * maxPayments - 1 distinct positions");
    for (uint256 i = 0; i < distinct; i++) {
      assertTrue(admitted[i], "the admitted positions are the contiguous prefix 0..2 * maxPayments - 2");
    }
  }

  // --- helpers ---------------------------------------------------------------------------------------------------

  function _policy() internal view returns (X402SessionSapientSigner.Policy memory policy) {
    policy.sessionKey = sessionKey.addr;
    policy.chainId = block.chainid;
    policy.token = TOKEN;
    policy.maxAmountPerPayment = 1e6;
    policy.windowStart = WINDOW_START;
    policy.windowDuration = WINDOW_DURATION;
    policy.maxWindows = 0; // unbounded lifetime, so only the sliding mask gates the tape
    policy.maxPayments = MAX_PAYMENTS;
    policy.validBefore = uint256(WINDOW_START) + uint256(WINDOW_DURATION) * 4;
  }

  function _payloadAndSignature(
    X402SessionSapientSigner.Policy memory policy,
    uint256 nonceIndex
  ) internal view returns (Payload.Decoded memory payload, bytes memory encoded) {
    bytes32 policyRoot = signer.hashPolicy(policy);

    X402SessionSapientSigner.Permit2Payment memory payment;
    payment.amount = policy.maxAmountPerPayment;
    payment.nonce = signer.permit2Nonce(policyRoot, nonceIndex);
    payment.deadline = type(uint256).max;
    payment.witnessTo = PAY_TO;
    payment.witnessValidAfter = uint256(policy.windowStart);

    bytes32 externalDigest = signer.hashPermit2Payment(policy, payment);
    payload = Payload.fromDigest(externalDigest);

    bytes32 authDigest = signer.hashSessionAuthorization(address(wallet), policyRoot, externalDigest);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionKey.privateKey, authDigest);

    encoded = abi.encode(
      X402SessionSapientSigner.X402Signature({
        policy: policy, payment: payment, sessionKeySignature: abi.encodePacked(r, s, v)
      })
    );
  }

  /// @dev Calls the signer as the wallet and reports whether the tape position was accepted. Nothing is consumed
  ///      here: `recoverSapientSignature` is a view and Permit2 owns the one-time-use bitmap.
  function _accepts(
    X402SessionSapientSigner.Policy memory policy,
    uint256 nonceIndex
  ) internal returns (bool) {
    (Payload.Decoded memory payload, bytes memory encoded) = _payloadAndSignature(policy, nonceIndex);

    vm.prank(address(wallet));
    (bool ok, bytes memory ret) =
      address(signer).call(abi.encodeCall(X402SessionSapientSigner.recoverSapientSignature, (payload, encoded)));

    if (ok) {
      assertEq(abi.decode(ret, (bytes32)), signer.hashPolicy(policy), "accepted payment must return the policy root");
    }
    return ok;
  }

  /// @dev The payload is built first so `vm.expectRevert` applies to the signer call and not to a helper view call.
  function _assertRejected(
    X402SessionSapientSigner.Policy memory policy,
    uint256 nonceIndex,
    uint256 minNonceIndex,
    uint256 maxNonceIndex
  ) internal {
    (Payload.Decoded memory payload, bytes memory encoded) = _payloadAndSignature(policy, nonceIndex);

    vm.expectRevert(
      abi.encodeWithSelector(
        X402SessionSapientSigner.InvalidNonceTapeIndex.selector, nonceIndex, minNonceIndex, maxNonceIndex
      )
    );
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

}
