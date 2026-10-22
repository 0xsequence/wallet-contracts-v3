// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Test, Vm } from "forge-std/Test.sol";

import { MockERC20 } from "test/mocks/MockERC20.sol";

import { X402SessionSapientSigner } from "src/extensions/x402/X402SessionSapientSigner.sol";
import { Calls } from "src/modules/Calls.sol";
import { Payload } from "src/modules/Payload.sol";
import { IERC1271_MAGIC_VALUE_HASH } from "src/modules/interfaces/IERC1271.sol";

contract X402AuthHarness is Calls {

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

contract X402SessionSapientSignerTest is Test {

  X402SessionSapientSigner internal signer;
  X402AuthHarness internal wallet;
  Vm.Wallet internal sessionKey;

  address internal constant PERMIT2 = address(0x000000000022D473030F116dDEE9F6B43aC78BA3);
  address internal constant X402_PERMIT2_PROXY = address(0x402085c248EeA27D92E8b30b2C58ed07f9E20001);
  address internal constant TOKEN = address(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
  address internal constant PAY_TO = address(0x209693Bc6afc0C5328bA36FaF03C514EF312287C);
  bytes4 internal constant APPROVE_SELECTOR = bytes4(keccak256("approve(address,uint256)"));

  uint64 internal constant WINDOW_START = 1000;
  uint64 internal constant WINDOW_DURATION = 30 days;
  uint32 internal constant MAX_WINDOWS = 12;

  bytes32 internal constant CANONICAL_TOKEN_PERMISSIONS_TYPEHASH =
    keccak256("TokenPermissions(address token,uint256 amount)");
  bytes32 internal constant CANONICAL_WITNESS_TYPEHASH = keccak256("Witness(address to,uint256 validAfter)");
  bytes32 internal constant CANONICAL_PERMIT2_WITNESS_TRANSFER_TYPEHASH = keccak256(
    "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,Witness witness)TokenPermissions(address token,uint256 amount)Witness(address to,uint256 validAfter)"
  );
  bytes32 internal constant CANONICAL_PERMIT2_DOMAIN_TYPEHASH =
    keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");
  bytes32 internal constant CANONICAL_PERMIT2_NAME_HASH = keccak256("Permit2");

  function setUp() external {
    signer = new X402SessionSapientSigner(PERMIT2, X402_PERMIT2_PROXY);
    wallet = new X402AuthHarness();
    sessionKey = vm.createWallet("x402-session-key");
    vm.warp(WINDOW_START); // start at the beginning of window 0
  }

  function test_recoverSapientSignature_acceptsValidPermit2Payment() external {
    (Payload.Decoded memory payload, bytes memory encoded, bytes32 policyRoot) = _validPayloadAndSignature();

    vm.prank(address(wallet));
    bytes32 recovered = signer.recoverSapientSignature(payload, encoded);

    assertEq(recovered, policyRoot);
  }

  function test_isValidSignature_acceptsValidPermit2PaymentThroughBaseAuth() external {
    (Payload.Decoded memory payload, bytes memory encoded, bytes32 policyRoot) = _validPayloadAndSignature();
    wallet.setImageHash(_sequenceImageHash(address(signer), 1, policyRoot));

    bytes memory sequenceSignature = _encodeSequenceSapientSignature(address(signer), 1, encoded);

    assertEq(wallet.isValidSignature(payload.digest, sequenceSignature), IERC1271_MAGIC_VALUE_HASH);
  }

  /// A payment authorized for the wallet itself must not be replayable through a parent wallet that lists the
  /// wallet as a sapient signer. Permit2 nonces are per owner, so a replay would settle a second transfer from
  /// the parent off a single authorization.
  function test_isValidSignature_rejectsPaymentReplayThroughParentWallet() external {
    X402AuthHarness parent = new X402AuthHarness();
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    X402SessionSapientSigner.Permit2Payment memory payment = _validPayment(policy);
    bytes32 policyRoot = signer.hashPolicy(policy);
    bytes32 externalDigest = signer.hashPermit2Payment(policy, payment);

    // The session key signs for a direct payment from `wallet`, so `parentWallets` is empty.
    bytes memory sessionKeySignature =
      _sign(sessionKey.privateKey, _paymentAuthDigest(policyRoot, externalDigest, _noParents()));
    bytes memory x402Signature = _encode(policy, payment, sessionKeySignature);

    wallet.setImageHash(_sequenceImageHash(address(signer), 1, policyRoot));
    parent.setImageHash(_sequenceImageHash(address(wallet), 1, bytes32(uint256(1))));

    bytes memory walletSignature = _encodeSequenceSapientSignature(address(signer), 1, x402Signature);
    assertEq(wallet.isValidSignature(externalDigest, walletSignature), IERC1271_MAGIC_VALUE_HASH);

    // The same x402 signature bytes, rewrapped for the parent, now recover a different address because the
    // authorization commits to `parentWallets`.
    bytes memory parentSignature = _encodeSequenceSapientSignature(address(wallet), 1, walletSignature);
    address recovered =
      _recover(_paymentAuthDigest(policyRoot, externalDigest, _oneParent(address(parent))), sessionKeySignature);

    vm.expectRevert(
      abi.encodeWithSelector(X402SessionSapientSigner.InvalidSessionKeySignature.selector, recovered, policy.sessionKey)
    );
    parent.isValidSignature(externalDigest, parentSignature);
  }

  /// Nesting is still usable when the session key intends it: signing with the parent in `parentWallets` validates
  /// through the parent, and that same signature no longer validates for a direct payment from the wallet.
  function test_isValidSignature_acceptsPaymentAuthorizedForParentWallet() external {
    X402AuthHarness parent = new X402AuthHarness();
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    X402SessionSapientSigner.Permit2Payment memory payment = _validPayment(policy);
    bytes32 policyRoot = signer.hashPolicy(policy);
    bytes32 externalDigest = signer.hashPermit2Payment(policy, payment);

    bytes memory sessionKeySignature =
      _sign(sessionKey.privateKey, _paymentAuthDigest(policyRoot, externalDigest, _oneParent(address(parent))));
    bytes memory x402Signature = _encode(policy, payment, sessionKeySignature);

    wallet.setImageHash(_sequenceImageHash(address(signer), 1, policyRoot));
    parent.setImageHash(_sequenceImageHash(address(wallet), 1, bytes32(uint256(1))));

    bytes memory walletSignature = _encodeSequenceSapientSignature(address(signer), 1, x402Signature);
    bytes memory parentSignature = _encodeSequenceSapientSignature(address(wallet), 1, walletSignature);

    assertEq(parent.isValidSignature(externalDigest, parentSignature), IERC1271_MAGIC_VALUE_HASH);

    address recovered = _recover(_paymentAuthDigest(policyRoot, externalDigest, _noParents()), sessionKeySignature);

    vm.expectRevert(
      abi.encodeWithSelector(X402SessionSapientSigner.InvalidSessionKeySignature.selector, recovered, policy.sessionKey)
    );
    wallet.isValidSignature(externalDigest, walletSignature);
  }

  function test_hashPermit2Payment_matchesCanonicalX402ProxyDigest() external view {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    X402SessionSapientSigner.Permit2Payment memory payment = _validPayment(policy);

    assertEq(signer.hashPermit2Payment(policy, payment), _canonicalX402ProxyDigest(policy, payment));
  }

  // --- sliding, auto-renewing Permit2 nonce tape ---------------------------------------------------------------

  function test_recoverSapientSignature_slidesAcceptedNonceRangeWithoutReconfiguring() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    bytes32 policyRoot = signer.hashPolicy(policy);

    (uint256 min0, uint256 max0) = signer.currentNonceTapeRange(policy);
    assertEq(min0, 0);
    assertEq(max0, policy.maxPayments - 1);

    // At the policy start, the full initial mask is live.
    (Payload.Decoded memory p0, bytes memory s0,) = _payloadAndSignature(policy, _paymentAtIndex(policy, 0));
    vm.prank(address(wallet));
    assertEq(signer.recoverSapientSignature(p0, s0), policyRoot, "oldest live position should be accepted");

    (Payload.Decoded memory p4, bytes memory s4,) = _payloadAndSignature(policy, _paymentAtIndex(policy, 4));
    vm.prank(address(wallet));
    assertEq(signer.recoverSapientSignature(p4, s4), policyRoot, "newest live position should be accepted");

    // The first not-yet-live tape position is rejected.
    (Payload.Decoded memory p5, bytes memory s5,) = _payloadAndSignature(policy, _paymentAtIndex(policy, 5));
    vm.expectRevert(
      abi.encodeWithSelector(
        X402SessionSapientSigner.InvalidNonceTapeIndex.selector, uint256(5), uint256(0), uint256(4)
      )
    );
    vm.prank(address(wallet));
    signer.recoverSapientSignature(p5, s5);

    // Advance by one refill quantum. The accepted mask moves from [0..4] to [1..5].
    vm.warp(WINDOW_START + WINDOW_DURATION / policy.maxPayments);
    (uint256 min1, uint256 max1) = signer.currentNonceTapeRange(policy);
    assertEq(min1, 1);
    assertEq(max1, 5);

    vm.prank(address(wallet));
    assertEq(signer.recoverSapientSignature(p5, s5), policyRoot, "new tape position should now be accepted");

    // The oldest position fell out of the mask.
    vm.expectRevert(
      abi.encodeWithSelector(
        X402SessionSapientSigner.InvalidNonceTapeIndex.selector, uint256(0), uint256(1), uint256(5)
      )
    );
    vm.prank(address(wallet));
    signer.recoverSapientSignature(p0, s0);
  }

  function test_permit2Nonce_sameBitDifferentTapeWordsYieldDistinctNonces() external view {
    bytes32 policyRoot = signer.hashPolicy(_validPolicy());
    uint256 firstNonce = signer.permit2Nonce(policyRoot, 2);
    uint256 secondNonce = signer.permit2Nonce(policyRoot, 258);

    assertEq(uint8(firstNonce), uint8(2));
    assertEq(uint8(secondNonce), uint8(2));
    assertTrue(firstNonce != secondNonce);

    uint256 wordBase = signer.permit2NonceWordBase(policyRoot);
    assertEq(firstNonce >> signer.PERMIT2_NONCE_BIT_INDEX_BITS(), wordBase);
    assertEq(secondNonce >> signer.PERMIT2_NONCE_BIT_INDEX_BITS(), wordBase + 1);
    assertEq(signer.decodePermit2Nonce(policyRoot, firstNonce), 2);
    assertEq(signer.decodePermit2Nonce(policyRoot, secondNonce), 258);
  }

  function test_recoverSapientSignature_rejectsPaymentBeforeWindowStart() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    (Payload.Decoded memory payload, bytes memory encoded,) = _payloadAndSignature(policy, _paymentAtIndex(policy, 0));

    vm.warp(WINDOW_START - 1);
    vm.expectRevert(
      abi.encodeWithSelector(X402SessionSapientSigner.WindowNotStarted.selector, WINDOW_START, WINDOW_START - 1)
    );
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

  function test_recoverSapientSignature_rejectsOnceWindowsAreExhausted() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    uint256 firstExpiredIndex = uint256(policy.maxWindows) * uint256(policy.maxPayments);
    (Payload.Decoded memory payload, bytes memory encoded,) =
      _payloadAndSignature(policy, _paymentAtIndex(policy, firstExpiredIndex));

    // Jump to the first full refill window after the lifetime cap.
    vm.warp(WINDOW_START + uint256(WINDOW_DURATION) * MAX_WINDOWS);
    vm.expectRevert(
      abi.encodeWithSelector(X402SessionSapientSigner.RefillWindowsExhausted.selector, MAX_WINDOWS, MAX_WINDOWS)
    );
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

  function test_recoverSapientSignature_acceptsPaymentInLastAllowedWindow() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    bytes32 policyRoot = signer.hashPolicy(policy);
    uint256 lastWindow = MAX_WINDOWS - 1;
    uint256 lastAllowedIndex = uint256(policy.maxWindows) * uint256(policy.maxPayments) - 1;
    (Payload.Decoded memory payload, bytes memory encoded,) =
      _payloadAndSignature(policy, _paymentAtIndex(policy, lastAllowedIndex));

    vm.warp(WINDOW_START + uint256(WINDOW_DURATION) * lastWindow);
    vm.prank(address(wallet));
    assertEq(signer.recoverSapientSignature(payload, encoded), policyRoot);
  }

  function test_recoverSapientSignature_allowsMultiplePaymentsWithinSlidingMaskUpToCap() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    policy.maxPayments = 3;
    bytes32 policyRoot = signer.hashPolicy(policy);

    for (uint256 nonceIndex = 0; nonceIndex < 3; nonceIndex++) {
      (Payload.Decoded memory payload, bytes memory encoded,) =
        _payloadAndSignature(policy, _paymentAtIndex(policy, nonceIndex));
      vm.prank(address(wallet));
      assertEq(signer.recoverSapientSignature(payload, encoded), policyRoot, "index within mask should be accepted");
    }

    (Payload.Decoded memory overPayload, bytes memory overEncoded,) =
      _payloadAndSignature(policy, _paymentAtIndex(policy, 3));
    vm.expectRevert(
      abi.encodeWithSelector(
        X402SessionSapientSigner.InvalidNonceTapeIndex.selector, uint256(3), uint256(0), uint256(2)
      )
    );
    vm.prank(address(wallet));
    signer.recoverSapientSignature(overPayload, overEncoded);
  }

  function test_recoverSapientSignature_slidingMaskCanSpanPermit2Words() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    policy.maxPayments = 300;
    bytes32 policyRoot = signer.hashPolicy(policy);

    (Payload.Decoded memory payload, bytes memory encoded,) = _payloadAndSignature(policy, _paymentAtIndex(policy, 299));

    vm.prank(address(wallet));
    assertEq(signer.recoverSapientSignature(payload, encoded), policyRoot);

    (Payload.Decoded memory overPayload, bytes memory overEncoded,) =
      _payloadAndSignature(policy, _paymentAtIndex(policy, 300));
    vm.expectRevert(
      abi.encodeWithSelector(
        X402SessionSapientSigner.InvalidNonceTapeIndex.selector, uint256(300), uint256(0), uint256(299)
      )
    );
    vm.prank(address(wallet));
    signer.recoverSapientSignature(overPayload, overEncoded);
  }

  function test_recoverSapientSignature_allowsVariableAmountUnderCap() external {
    // "utility bill" case: a different (smaller) amount is fine, as long as it is <= the cap.
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    bytes32 policyRoot = signer.hashPolicy(policy);
    X402SessionSapientSigner.Permit2Payment memory payment = _paymentAtIndex(policy, 0);
    payment.amount = policy.maxAmountPerPayment / 3;
    (Payload.Decoded memory payload, bytes memory encoded,) = _payloadAndSignature(policy, payment);

    vm.prank(address(wallet));
    assertEq(signer.recoverSapientSignature(payload, encoded), policyRoot);
  }

  // --- approval setup path -------------------------------------------------------------------------------------

  function test_recoverSapientSignature_acceptsPermit2ApprovalTransaction() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    (Payload.Decoded memory payload, bytes memory encoded, bytes32 policyRoot) =
      _approvalPayloadAndSignature(policy, TOKEN, PERMIT2, type(uint256).max);

    vm.prank(address(wallet));
    bytes32 recovered = signer.recoverSapientSignature(payload, encoded);

    assertEq(recovered, policyRoot);
  }

  function test_recoverSapientSignature_acceptsPermit2ApprovalForPolicyToken() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    policy.token = address(0xBEEF);
    (Payload.Decoded memory payload, bytes memory encoded, bytes32 policyRoot) =
      _approvalPayloadAndSignature(policy, policy.token, PERMIT2, type(uint256).max);

    vm.prank(address(wallet));
    bytes32 recovered = signer.recoverSapientSignature(payload, encoded);

    assertEq(recovered, policyRoot);
  }

  function test_recoverSapientSignature_rejectsApprovalForTokenOutsidePolicy() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    (Payload.Decoded memory payload, bytes memory encoded,) =
      _approvalPayloadAndSignature(policy, address(0xBEEF), PERMIT2, type(uint256).max);

    vm.expectRevert(abi.encodeWithSelector(X402SessionSapientSigner.InvalidToken.selector, address(0xBEEF), TOKEN));
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

  function test_recoverSapientSignature_rejectsApprovalWrongSpender() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    (Payload.Decoded memory payload, bytes memory encoded,) =
      _approvalPayloadAndSignature(policy, TOKEN, address(0xBEEF), type(uint256).max);

    vm.expectRevert(
      abi.encodeWithSelector(X402SessionSapientSigner.InvalidApprovalSpender.selector, address(0xBEEF), PERMIT2)
    );
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

  function test_recoverSapientSignature_rejectsApprovalAmountBelowMax() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    (Payload.Decoded memory payload, bytes memory encoded,) = _approvalPayloadAndSignature(policy, TOKEN, PERMIT2, 1);

    vm.expectRevert(
      abi.encodeWithSelector(X402SessionSapientSigner.InvalidApprovalAmount.selector, 1, type(uint256).max)
    );
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

  function test_recoverSapientSignature_rejectsApprovalRevocation() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    (Payload.Decoded memory payload, bytes memory encoded,) = _approvalPayloadAndSignature(policy, TOKEN, PERMIT2, 0);

    vm.expectRevert(
      abi.encodeWithSelector(X402SessionSapientSigner.InvalidApprovalAmount.selector, 0, type(uint256).max)
    );
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

  function test_recoverSapientSignature_rejectsApprovalOutsideSessionNonceSpace() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    Payload.Decoded memory payload = _approvalPayload(TOKEN, PERMIT2, type(uint256).max);
    payload.space = signer.MAX_SPACE() + 1;
    bytes memory encoded = _approvalSignature(policy, payload);

    vm.expectRevert(abi.encodeWithSelector(X402SessionSapientSigner.InvalidSpace.selector, payload.space));
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

  function test_recoverSapientSignature_rejectsInvalidApprovalSessionSignature() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    Payload.Decoded memory payload = _approvalPayload(TOKEN, PERMIT2, type(uint256).max);
    bytes32 policyRoot = signer.hashPolicy(policy);
    bytes32 payloadDigest = Payload.hashFor(payload, address(wallet));
    bytes32 authDigest = signer.hashSessionAuthorization(address(wallet), policyRoot, payloadDigest);

    Vm.Wallet memory wrongKey = vm.createWallet("wrong-approval-key");
    bytes memory badSignature = _sign(wrongKey.privateKey, authDigest);
    bytes memory encoded = _encodeApproval(policy, badSignature);
    address recovered = _recover(authDigest, badSignature);

    vm.expectRevert(
      abi.encodeWithSelector(X402SessionSapientSigner.InvalidSessionKeySignature.selector, recovered, policy.sessionKey)
    );
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

  function test_execute_runsPermit2ApprovalEndToEnd() external {
    MockERC20 token = new MockERC20();
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    policy.token = address(token);

    Payload.Decoded memory payload = _approvalPayload(address(token), PERMIT2, type(uint256).max);
    bytes memory approvalSignature = _approvalSignature(policy, payload);
    bytes32 policyRoot = signer.hashPolicy(policy);
    wallet.setImageHash(_sequenceImageHash(address(signer), 1, policyRoot));

    bytes memory packed = _packApproval(address(token), PERMIT2, type(uint256).max);
    bytes memory sequenceSignature = _encodeSequenceSapientSignature(address(signer), 1, approvalSignature);

    assertEq(token.allowance(address(wallet), PERMIT2), 0);

    wallet.execute(packed, sequenceSignature);

    assertEq(token.allowance(address(wallet), PERMIT2), type(uint256).max);
  }

  function test_execute_rejectsTamperedApprovalPayload() external {
    MockERC20 token = new MockERC20();
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    policy.token = address(token);

    // The session key signs an approval in nonce space 0...
    Payload.Decoded memory payload = _approvalPayload(address(token), PERMIT2, type(uint256).max);
    bytes memory approvalSignature = _approvalSignature(policy, payload);
    wallet.setImageHash(_sequenceImageHash(address(signer), 1, signer.hashPolicy(policy)));
    bytes memory sequenceSignature = _encodeSequenceSapientSignature(address(signer), 1, approvalSignature);

    // ...but the submitted transaction is executed in a different nonce space.
    // The space is still in policy and passes structural checks, yet the op hash
    // changes, so the session-key signature no longer recovers, and execute reverts.
    bytes memory packed = _packApprovalInSpace(address(token), PERMIT2, type(uint256).max, 7);

    vm.expectRevert();
    wallet.execute(packed, sequenceSignature);

    assertEq(token.allowance(address(wallet), PERMIT2), 0);
  }

  // --- structural validation -----------------------------------------------------------------------------------

  function test_constructor_rejectsZeroPermit2() external {
    vm.expectRevert(X402SessionSapientSigner.InvalidPermit2.selector);
    new X402SessionSapientSigner(address(0), X402_PERMIT2_PROXY);
  }

  function test_constructor_rejectsZeroProxy() external {
    vm.expectRevert(X402SessionSapientSigner.InvalidPermit2.selector);
    new X402SessionSapientSigner(PERMIT2, address(0));
  }

  function test_recoverSapientSignature_rejectsUnsupportedPayloadKind() external {
    Payload.Decoded memory payload = Payload.fromMessage(bytes("x402"));

    vm.expectRevert(abi.encodeWithSelector(X402SessionSapientSigner.InvalidPayloadKind.selector, Payload.KIND_MESSAGE));
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, "");
  }

  function test_recoverSapientSignature_rejectsZeroSessionKey() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    policy.sessionKey = address(0);
    X402SessionSapientSigner.Permit2Payment memory payment = _validPayment(policy);
    (Payload.Decoded memory payload, bytes memory encoded,) = _payloadAndSignature(policy, payment);

    vm.expectRevert(X402SessionSapientSigner.InvalidSessionKey.selector);
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

  function test_recoverSapientSignature_rejectsZeroToken() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    policy.token = address(0);
    X402SessionSapientSigner.Permit2Payment memory payment = _validPayment(policy);
    (Payload.Decoded memory payload, bytes memory encoded,) = _payloadAndSignature(policy, payment);

    vm.expectRevert(X402SessionSapientSigner.InvalidSessionToken.selector);
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

  function test_recoverSapientSignature_rejectsExpiredSession() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    policy.validBefore = block.timestamp - 1;
    X402SessionSapientSigner.Permit2Payment memory payment = _validPayment(policy);
    (Payload.Decoded memory payload, bytes memory encoded,) = _payloadAndSignature(policy, payment);

    vm.expectRevert(
      abi.encodeWithSelector(X402SessionSapientSigner.SessionExpired.selector, policy.validBefore, block.timestamp)
    );
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

  function test_recoverSapientSignature_rejectsZeroWindowDuration() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    policy.windowDuration = 0;
    X402SessionSapientSigner.Permit2Payment memory payment = _validPayment(policy);
    (Payload.Decoded memory payload, bytes memory encoded,) = _payloadAndSignature(policy, payment);

    vm.expectRevert(X402SessionSapientSigner.InvalidWindowDuration.selector);
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

  function test_recoverSapientSignature_rejectsZeroMaxPayments() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    policy.maxPayments = 0;
    X402SessionSapientSigner.Permit2Payment memory payment = _validPayment(policy);
    (Payload.Decoded memory payload, bytes memory encoded,) = _payloadAndSignature(policy, payment);

    vm.expectRevert(
      abi.encodeWithSelector(
        X402SessionSapientSigner.InvalidMaxPayments.selector, uint16(0), signer.MAX_SLIDING_WINDOW_PAYMENTS()
      )
    );
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

  function test_recoverSapientSignature_acceptsMaxPaymentsBoundaryIndex() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    policy.maxPayments = signer.MAX_SLIDING_WINDOW_PAYMENTS();
    bytes32 policyRoot = signer.hashPolicy(policy);
    X402SessionSapientSigner.Permit2Payment memory payment = _paymentAtIndex(policy, policy.maxPayments - 1);
    (Payload.Decoded memory payload, bytes memory encoded,) = _payloadAndSignature(policy, payment);

    vm.prank(address(wallet));
    assertEq(signer.recoverSapientSignature(payload, encoded), policyRoot);
  }

  function test_recoverSapientSignature_rejectsZeroPaymentAmount() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    X402SessionSapientSigner.Permit2Payment memory payment = _validPayment(policy);
    payment.amount = 0;
    (Payload.Decoded memory payload, bytes memory encoded,) = _payloadAndSignature(policy, payment);

    vm.expectRevert(
      abi.encodeWithSelector(
        X402SessionSapientSigner.InvalidPaymentAmount.selector, uint256(0), policy.maxAmountPerPayment
      )
    );
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

  function test_recoverSapientSignature_rejectsApprovalWithMultipleCalls() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    Payload.Decoded memory payload = _approvalPayload(TOKEN, PERMIT2, type(uint256).max);
    Payload.Call memory approveCall = payload.calls[0];
    payload.calls = new Payload.Call[](2);
    payload.calls[0] = approveCall;
    payload.calls[1] = approveCall;
    bytes memory encoded = _approvalSignature(policy, payload);

    vm.expectRevert(abi.encodeWithSelector(X402SessionSapientSigner.InvalidApprovalCallsLength.selector, uint256(2)));
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

  function test_recoverSapientSignature_rejectsApprovalWithValue() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    Payload.Decoded memory payload = _approvalPayload(TOKEN, PERMIT2, type(uint256).max);
    payload.calls[0].value = 1;
    bytes memory encoded = _approvalSignature(policy, payload);

    vm.expectRevert(X402SessionSapientSigner.InvalidApprovalCall.selector);
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

  function test_recoverSapientSignature_rejectsApprovalWithDelegateCall() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    Payload.Decoded memory payload = _approvalPayload(TOKEN, PERMIT2, type(uint256).max);
    payload.calls[0].delegateCall = true;
    bytes memory encoded = _approvalSignature(policy, payload);

    vm.expectRevert(X402SessionSapientSigner.InvalidApprovalCall.selector);
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

  function test_recoverSapientSignature_rejectsApprovalOnlyFallback() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    Payload.Decoded memory payload = _approvalPayload(TOKEN, PERMIT2, type(uint256).max);
    payload.calls[0].onlyFallback = true;
    bytes memory encoded = _approvalSignature(policy, payload);

    vm.expectRevert(X402SessionSapientSigner.InvalidApprovalCall.selector);
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

  function test_recoverSapientSignature_rejectsApprovalNonRevertBehavior() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    Payload.Decoded memory payload = _approvalPayload(TOKEN, PERMIT2, type(uint256).max);
    payload.calls[0].behaviorOnError = Payload.BEHAVIOR_IGNORE_ERROR;
    bytes memory encoded = _approvalSignature(policy, payload);

    vm.expectRevert(X402SessionSapientSigner.InvalidApprovalCall.selector);
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

  function test_recoverSapientSignature_rejectsApprovalWrongDataLength() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    Payload.Decoded memory payload = _approvalPayload(TOKEN, PERMIT2, type(uint256).max);
    payload.calls[0].data = abi.encodePacked(APPROVE_SELECTOR);
    bytes memory encoded = _approvalSignature(policy, payload);

    vm.expectRevert(X402SessionSapientSigner.InvalidApprovalCall.selector);
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

  function test_recoverSapientSignature_rejectsApprovalWrongSelector() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    Payload.Decoded memory payload = _approvalPayload(TOKEN, PERMIT2, type(uint256).max);
    bytes4 transferSelector = bytes4(keccak256("transfer(address,uint256)"));
    payload.calls[0].data = abi.encodeWithSelector(transferSelector, PERMIT2, type(uint256).max);
    bytes memory encoded = _approvalSignature(policy, payload);

    vm.expectRevert(abi.encodeWithSelector(X402SessionSapientSigner.InvalidApprovalSelector.selector, transferSelector));
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

  function test_recoverSapientSignature_rejectsAmountAbovePerPaymentLimit() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    X402SessionSapientSigner.Permit2Payment memory payment = _validPayment(policy);
    payment.amount = policy.maxAmountPerPayment + 1;
    (Payload.Decoded memory payload, bytes memory encoded,) = _payloadAndSignature(policy, payment);

    vm.expectRevert(
      abi.encodeWithSelector(
        X402SessionSapientSigner.InvalidPaymentAmount.selector, payment.amount, policy.maxAmountPerPayment
      )
    );
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

  function test_recoverSapientSignature_rejectsNonceOutsidePolicyWordBase() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    bytes32 policyRoot = signer.hashPolicy(policy);
    X402SessionSapientSigner.Permit2Payment memory payment = _paymentAtIndex(policy, 1);
    payment.nonce ^= uint256(1) << (signer.PERMIT2_NONCE_BIT_INDEX_BITS() + signer.NONCE_TAPE_WORD_OFFSET_BITS());
    (Payload.Decoded memory payload, bytes memory encoded,) = _payloadAndSignature(policy, payment);

    uint256 word = payment.nonce >> signer.PERMIT2_NONCE_BIT_INDEX_BITS();
    uint256 minWord = signer.permit2NonceWordBase(policyRoot);
    uint256 maxWord = minWord + signer.NONCE_TAPE_WORD_OFFSET_MASK();
    vm.expectRevert(abi.encodeWithSelector(X402SessionSapientSigner.InvalidNonceWord.selector, word, minWord, maxWord));
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

  function test_recoverSapientSignature_rejectsNonceIndexOutsideSlidingMask() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    X402SessionSapientSigner.Permit2Payment memory payment = _paymentAtIndex(policy, policy.maxPayments);
    (Payload.Decoded memory payload, bytes memory encoded,) = _payloadAndSignature(policy, payment);

    vm.expectRevert(
      abi.encodeWithSelector(
        X402SessionSapientSigner.InvalidNonceTapeIndex.selector,
        uint256(policy.maxPayments),
        uint256(0),
        uint256(policy.maxPayments) - 1
      )
    );
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

  function test_recoverSapientSignature_acceptsArbitraryRecipient() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    X402SessionSapientSigner.Permit2Payment memory payment = _validPayment(policy);
    payment.witnessTo = address(0xBEEF);
    (Payload.Decoded memory payload, bytes memory encoded,) = _payloadAndSignature(policy, payment);

    vm.prank(address(wallet));
    bytes32 recovered = signer.recoverSapientSignature(payload, encoded);

    assertEq(recovered, signer.hashPolicy(policy));
  }

  function test_isValidSignature_rejectsPolicyTokenOutsideConfiguredImage() external {
    X402SessionSapientSigner.Policy memory configuredPolicy = _validPolicy();
    wallet.setImageHash(_sequenceImageHash(address(signer), 1, signer.hashPolicy(configuredPolicy)));

    X402SessionSapientSigner.Policy memory submittedPolicy = configuredPolicy;
    submittedPolicy.token = address(0xBEEF);
    X402SessionSapientSigner.Permit2Payment memory payment = _validPayment(submittedPolicy);
    (Payload.Decoded memory payload, bytes memory encoded,) = _payloadAndSignature(submittedPolicy, payment);
    bytes memory sequenceSignature = _encodeSequenceSapientSignature(address(signer), 1, encoded);

    assertEq(wallet.isValidSignature(payload.digest, sequenceSignature), bytes4(0));
  }

  function test_recoverSapientSignature_rejectsMismatchedExternalDigest() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    X402SessionSapientSigner.Permit2Payment memory payment = _validPayment(policy);
    (, bytes memory encoded,) = _payloadAndSignature(policy, payment);

    bytes32 wrongDigest = keccak256("wrong digest");
    Payload.Decoded memory payload = Payload.fromDigest(wrongDigest);
    bytes32 expectedDigest = signer.hashPermit2Payment(policy, payment);

    vm.expectRevert(
      abi.encodeWithSelector(X402SessionSapientSigner.InvalidDigest.selector, expectedDigest, wrongDigest)
    );
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

  function test_recoverSapientSignature_acceptsAnyChainPolicy() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    policy.chainId = 0;
    X402SessionSapientSigner.Permit2Payment memory payment = _validPayment(policy);
    (Payload.Decoded memory payload, bytes memory encoded,) = _payloadAndSignature(policy, payment);

    vm.prank(address(wallet));
    bytes32 recovered = signer.recoverSapientSignature(payload, encoded);

    assertEq(recovered, signer.hashPolicy(policy));
  }

  function test_recoverSapientSignature_rejectsWrongChainPolicy() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    policy.chainId = block.chainid + 1;
    X402SessionSapientSigner.Permit2Payment memory payment = _validPayment(policy);
    (Payload.Decoded memory payload, bytes memory encoded,) = _payloadAndSignature(policy, payment);

    vm.expectRevert(
      abi.encodeWithSelector(X402SessionSapientSigner.InvalidChainId.selector, policy.chainId, block.chainid)
    );
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

  function test_recoverSapientSignature_rejectsInvalidSessionSignature() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    X402SessionSapientSigner.Permit2Payment memory payment = _validPayment(policy);
    bytes32 externalDigest = signer.hashPermit2Payment(policy, payment);
    Payload.Decoded memory payload = Payload.fromDigest(externalDigest);
    bytes32 policyRoot = signer.hashPolicy(policy);

    Vm.Wallet memory wrongKey = vm.createWallet("wrong-key");
    bytes32 payloadDigest = Payload.hashFor(payload, address(wallet));
    bytes32 authDigest = signer.hashSessionAuthorization(address(wallet), policyRoot, payloadDigest);
    bytes memory badSignature = _sign(wrongKey.privateKey, authDigest);
    bytes memory encoded = _encode(policy, payment, badSignature);
    address recovered = _recover(authDigest, badSignature);

    vm.expectRevert(
      abi.encodeWithSelector(X402SessionSapientSigner.InvalidSessionKeySignature.selector, recovered, policy.sessionKey)
    );
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

  // --- helpers -------------------------------------------------------------------------------------------------

  function _validPayloadAndSignature()
    internal
    view
    returns (Payload.Decoded memory payload, bytes memory encoded, bytes32 policyRoot)
  {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    X402SessionSapientSigner.Permit2Payment memory payment = _validPayment(policy);
    return _payloadAndSignature(policy, payment);
  }

  function _approvalPayload(
    address token,
    address spender,
    uint256 amount
  ) internal pure returns (Payload.Decoded memory payload) {
    payload.kind = Payload.KIND_TRANSACTIONS;
    payload.calls = new Payload.Call[](1);
    payload.calls[0] = Payload.Call({
      to: token,
      value: 0,
      data: abi.encodeWithSelector(APPROVE_SELECTOR, spender, amount),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });
  }

  function _packApproval(
    address token,
    address spender,
    uint256 amount
  ) internal pure returns (bytes memory) {
    bytes memory data = abi.encodeWithSelector(APPROVE_SELECTOR, spender, amount);
    return abi.encodePacked(
      uint8(0x11), // global flag: space is zero (0x01) | single call (0x10)
      uint8(0x44), // call flags: has data (0x04) | behavior revert-on-error (0x01 << 6)
      token, // call target
      uint24(data.length), // 3-byte calldata size
      data
    );
  }

  function _packApprovalInSpace(
    address token,
    address spender,
    uint256 amount,
    uint160 space
  ) internal pure returns (bytes memory) {
    bytes memory data = abi.encodeWithSelector(APPROVE_SELECTOR, spender, amount);
    return abi.encodePacked(
      uint8(0x10), // global flag: single call (0x10), space is non-zero (bit 0 clear)
      space, // uint160 nonce space
      uint8(0x44), // call flags: has data (0x04) | behavior revert-on-error (0x01 << 6)
      token, // call target
      uint24(data.length), // 3-byte calldata size
      data
    );
  }

  function _approvalPayloadAndSignature(
    X402SessionSapientSigner.Policy memory policy,
    address token,
    address spender,
    uint256 amount
  ) internal view returns (Payload.Decoded memory payload, bytes memory encoded, bytes32 policyRoot) {
    payload = _approvalPayload(token, spender, amount);
    encoded = _approvalSignature(policy, payload);
    policyRoot = signer.hashPolicy(policy);
  }

  function _approvalSignature(
    X402SessionSapientSigner.Policy memory policy,
    Payload.Decoded memory payload
  ) internal view returns (bytes memory encoded) {
    bytes32 policyRoot = signer.hashPolicy(policy);
    bytes32 payloadDigest = Payload.hashFor(payload, address(wallet));
    bytes32 authDigest = signer.hashSessionAuthorization(address(wallet), policyRoot, payloadDigest);
    encoded = _encodeApproval(policy, _sign(sessionKey.privateKey, authDigest));
  }

  function _payloadAndSignature(
    X402SessionSapientSigner.Policy memory policy,
    X402SessionSapientSigner.Permit2Payment memory payment
  ) internal view returns (Payload.Decoded memory payload, bytes memory encoded, bytes32 policyRoot) {
    bytes32 externalDigest = signer.hashPermit2Payment(policy, payment);
    payload = Payload.fromDigest(externalDigest);
    policyRoot = signer.hashPolicy(policy);
    bytes32 payloadDigest = Payload.hashFor(payload, address(wallet));
    bytes32 authDigest = signer.hashSessionAuthorization(address(wallet), policyRoot, payloadDigest);
    encoded = _encode(policy, payment, _sign(sessionKey.privateKey, authDigest));
  }

  /// The session-key authorization digest for a payment validated by `wallet` under the given parent chain.
  /// `noChainId` stays false to match the `0x00` leading signature flag the sequence signature helpers emit.
  function _paymentAuthDigest(
    bytes32 policyRoot,
    bytes32 externalDigest,
    address[] memory parentWallets
  ) internal view returns (bytes32) {
    Payload.Decoded memory payload = Payload.fromDigest(externalDigest);
    payload.parentWallets = parentWallets;
    return signer.hashSessionAuthorization(address(wallet), policyRoot, Payload.hashFor(payload, address(wallet)));
  }

  function _noParents() internal pure returns (address[] memory) {
    return new address[](0);
  }

  function _oneParent(
    address parent
  ) internal pure returns (address[] memory parents) {
    parents = new address[](1);
    parents[0] = parent;
  }

  function _validPolicy() internal view returns (X402SessionSapientSigner.Policy memory policy) {
    policy.sessionKey = sessionKey.addr;
    policy.chainId = block.chainid;
    policy.token = TOKEN;
    policy.maxAmountPerPayment = 1e6;
    policy.windowStart = WINDOW_START;
    policy.windowDuration = WINDOW_DURATION;
    policy.maxWindows = MAX_WINDOWS;
    policy.maxPayments = 5;
    // Backstop expiry comfortably beyond the lifetime cap so exhaustion tests do not hit SessionExpired first.
    policy.validBefore = uint256(WINDOW_START) + uint256(WINDOW_DURATION) * (uint256(MAX_WINDOWS) + 2);
  }

  function _validPayment(
    X402SessionSapientSigner.Policy memory policy
  ) internal view returns (X402SessionSapientSigner.Permit2Payment memory payment) {
    return _paymentAtIndex(policy, 2);
  }

  function _paymentAtIndex(
    X402SessionSapientSigner.Policy memory policy,
    uint256 nonceIndex
  ) internal view returns (X402SessionSapientSigner.Permit2Payment memory payment) {
    payment.amount = policy.maxAmountPerPayment;
    payment.nonce = signer.permit2Nonce(signer.hashPolicy(policy), nonceIndex);
    payment.deadline = uint256(policy.windowStart) + uint256(policy.windowDuration);
    payment.witnessTo = PAY_TO;
    payment.witnessValidAfter = uint256(policy.windowStart);
  }

  function _canonicalX402ProxyDigest(
    X402SessionSapientSigner.Policy memory policy,
    X402SessionSapientSigner.Permit2Payment memory payment
  ) internal view returns (bytes32) {
    bytes32 tokenPermissionsHash =
      keccak256(abi.encode(CANONICAL_TOKEN_PERMISSIONS_TYPEHASH, policy.token, payment.amount));
    bytes32 witnessHash =
      keccak256(abi.encode(CANONICAL_WITNESS_TYPEHASH, payment.witnessTo, payment.witnessValidAfter));
    bytes32 structHash = keccak256(
      abi.encode(
        CANONICAL_PERMIT2_WITNESS_TRANSFER_TYPEHASH,
        tokenPermissionsHash,
        X402_PERMIT2_PROXY,
        payment.nonce,
        payment.deadline,
        witnessHash
      )
    );
    bytes32 domainSeparator =
      keccak256(abi.encode(CANONICAL_PERMIT2_DOMAIN_TYPEHASH, CANONICAL_PERMIT2_NAME_HASH, block.chainid, PERMIT2));
    return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
  }

  function _encode(
    X402SessionSapientSigner.Policy memory policy,
    X402SessionSapientSigner.Permit2Payment memory payment,
    bytes memory sessionKeySignature
  ) internal pure returns (bytes memory) {
    X402SessionSapientSigner.X402Signature memory sig = X402SessionSapientSigner.X402Signature({
      policy: policy, payment: payment, sessionKeySignature: sessionKeySignature
    });
    return abi.encode(sig);
  }

  function _encodeApproval(
    X402SessionSapientSigner.Policy memory policy,
    bytes memory sessionKeySignature
  ) internal pure returns (bytes memory) {
    X402SessionSapientSigner.ApprovalSignature memory sig =
      X402SessionSapientSigner.ApprovalSignature({ policy: policy, sessionKeySignature: sessionKeySignature });
    return abi.encode(sig);
  }

  function _sign(
    uint256 privateKey,
    bytes32 digest
  ) internal pure returns (bytes memory) {
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
    return abi.encodePacked(r, s, v);
  }

  function _recover(
    bytes32 digest,
    bytes memory signature
  ) internal pure returns (address recovered) {
    bytes32 r;
    bytes32 s;
    uint8 v;
    assembly {
      r := mload(add(signature, 0x20))
      s := mload(add(signature, 0x40))
      v := byte(0, mload(add(signature, 0x60)))
    }
    recovered = ecrecover(digest, v, r, s);
  }

  function _sequenceImageHash(
    address sapient,
    uint256 weight,
    bytes32 sapientImageHash
  ) internal pure returns (bytes32 imageHash) {
    bytes32 root = keccak256(abi.encodePacked("Sequence sapient config:\n", sapient, weight, sapientImageHash));
    imageHash = _fkeccak256(root, bytes32(uint256(1)));
    imageHash = _fkeccak256(imageHash, bytes32(0));
    imageHash = _fkeccak256(imageHash, bytes32(0));
  }

  function _encodeSequenceSapientSignature(
    address sapient,
    uint8 weight,
    bytes memory sapientSignature
  ) internal pure returns (bytes memory) {
    require(weight > 0 && weight < 4, "unsupported weight");
    bytes1 sapientItemFlag = bytes1(uint8(0x90 | 0x08 | weight));
    return abi.encodePacked(
      bytes1(0x00), bytes1(0x01), sapientItemFlag, sapient, uint16(sapientSignature.length), sapientSignature
    );
  }

  function _fkeccak256(
    bytes32 a,
    bytes32 b
  ) internal pure returns (bytes32 c) {
    assembly {
      mstore(0, a)
      mstore(32, b)
      c := keccak256(0, 64)
    }
  }

}
