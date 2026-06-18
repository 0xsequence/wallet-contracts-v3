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
    vm.warp(1000);
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

  function test_hashPermit2Payment_matchesCanonicalX402ProxyDigest() external view {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    X402SessionSapientSigner.Permit2Payment memory payment = _validPayment(policy);

    assertEq(signer.hashPermit2Payment(policy, payment), _canonicalX402ProxyDigest(policy, payment));
  }

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

  function test_recoverSapientSignature_rejectsZeroMaxPayments() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    policy.maxPayments = 0;
    X402SessionSapientSigner.Permit2Payment memory payment = _validPayment(policy);
    (Payload.Decoded memory payload, bytes memory encoded,) = _payloadAndSignature(policy, payment);

    vm.expectRevert(
      abi.encodeWithSelector(
        X402SessionSapientSigner.InvalidMaxPayments.selector, uint16(0), signer.MAX_PERMIT2_NONCE_SLOTS()
      )
    );
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

  function test_recoverSapientSignature_rejectsMaxPaymentsAboveLimit() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    policy.maxPayments = signer.MAX_PERMIT2_NONCE_SLOTS() + 1;
    X402SessionSapientSigner.Permit2Payment memory payment = _validPayment(policy);
    (Payload.Decoded memory payload, bytes memory encoded,) = _payloadAndSignature(policy, payment);

    vm.expectRevert(
      abi.encodeWithSelector(
        X402SessionSapientSigner.InvalidMaxPayments.selector, policy.maxPayments, signer.MAX_PERMIT2_NONCE_SLOTS()
      )
    );
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

  function test_recoverSapientSignature_acceptsMaxPaymentsBoundarySlot() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    policy.maxPayments = signer.MAX_PERMIT2_NONCE_SLOTS();
    bytes32 policyRoot = signer.hashPolicy(policy);
    uint256 nonceWord = signer.permit2NonceWord(address(wallet), policyRoot);
    X402SessionSapientSigner.Permit2Payment memory payment = _validPayment(policy);
    payment.nonce = (nonceWord << 8) | 255;
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

  function test_recoverSapientSignature_rejectsNonceOutsideSessionWord() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    bytes32 policyRoot = signer.hashPolicy(policy);
    uint256 nonceWord = signer.permit2NonceWord(address(wallet), policyRoot);
    X402SessionSapientSigner.Permit2Payment memory payment = _validPayment(policy);
    payment.nonce = ((nonceWord + 1) << 8) | 1;
    (Payload.Decoded memory payload, bytes memory encoded,) = _payloadAndSignature(policy, payment);

    vm.expectRevert(
      abi.encodeWithSelector(X402SessionSapientSigner.InvalidNonceWord.selector, nonceWord + 1, nonceWord)
    );
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

  function test_recoverSapientSignature_rejectsNonceSlotAbovePaymentLimit() external {
    X402SessionSapientSigner.Policy memory policy = _validPolicy();
    bytes32 policyRoot = signer.hashPolicy(policy);
    uint256 nonceWord = signer.permit2NonceWord(address(wallet), policyRoot);
    X402SessionSapientSigner.Permit2Payment memory payment = _validPayment(policy);
    payment.nonce = (nonceWord << 8) | policy.maxPayments;
    (Payload.Decoded memory payload, bytes memory encoded,) = _payloadAndSignature(policy, payment);

    vm.expectRevert(
      abi.encodeWithSelector(
        X402SessionSapientSigner.InvalidNonceSlot.selector, uint256(policy.maxPayments), policy.maxPayments
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
    bytes32 authDigest = signer.hashSessionAuthorization(address(wallet), policyRoot, externalDigest);
    bytes memory badSignature = _sign(wrongKey.privateKey, authDigest);
    bytes memory encoded = _encode(policy, payment, badSignature);
    address recovered = _recover(authDigest, badSignature);

    vm.expectRevert(
      abi.encodeWithSelector(X402SessionSapientSigner.InvalidSessionKeySignature.selector, recovered, policy.sessionKey)
    );
    vm.prank(address(wallet));
    signer.recoverSapientSignature(payload, encoded);
  }

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
    bytes32 authDigest = signer.hashSessionAuthorization(address(wallet), policyRoot, externalDigest);
    encoded = _encode(policy, payment, _sign(sessionKey.privateKey, authDigest));
  }

  function _validPolicy() internal view returns (X402SessionSapientSigner.Policy memory policy) {
    policy.sessionKey = sessionKey.addr;
    policy.chainId = block.chainid;
    policy.token = TOKEN;
    policy.maxAmountPerPayment = 1e6;
    policy.maxPayments = 5;
    policy.validBefore = 2000;
  }

  function _validPayment(
    X402SessionSapientSigner.Policy memory policy
  ) internal view returns (X402SessionSapientSigner.Permit2Payment memory payment) {
    uint256 nonceWord = signer.permit2NonceWord(address(wallet), signer.hashPolicy(policy));
    payment.amount = 1e6;
    payment.nonce = (nonceWord << 8) | 2;
    payment.deadline = 1800;
    payment.witnessTo = PAY_TO;
    payment.witnessValidAfter = 1000;
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
