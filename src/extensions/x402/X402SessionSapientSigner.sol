// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { ECDSA } from "../../../lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

import { Payload } from "../../modules/Payload.sol";
import { ISapient } from "../../modules/interfaces/ISapient.sol";

/// @title X402SessionSapientSigner
/// @notice Digest-aware sapient signer for x402 exact Permit2 payments.
/// @dev The returned sapient image hash is the policy root committed in the wallet config.
contract X402SessionSapientSigner is ISapient {

  bytes4 public constant APPROVE_SELECTOR = bytes4(keccak256("approve(address,uint256)"));
  uint256 public constant MAX_SPACE = type(uint80).max - 1;
  uint16 public constant MAX_PERMIT2_NONCE_SLOTS = 256;

  bytes32 public constant X402_POLICY_TYPEHASH = keccak256(
    "X402SessionPolicy(address sessionKey,uint256 chainId,address token,uint256 maxAmountPerPayment,uint16 maxPayments,uint256 validBefore)"
  );
  bytes32 public constant PERMIT2_NONCE_WORD_TYPEHASH =
    keccak256("SequenceX402Permit2NonceWord(address signer,address wallet,bytes32 policyRoot)");

  bytes32 public constant PERMIT2_DOMAIN_TYPEHASH =
    keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");
  bytes32 public constant PERMIT2_NAME_HASH = keccak256("Permit2");
  bytes32 public constant TOKEN_PERMISSIONS_TYPEHASH = keccak256("TokenPermissions(address token,uint256 amount)");
  bytes32 public constant WITNESS_TYPEHASH = keccak256("Witness(address to,uint256 validAfter)");
  bytes32 public constant PERMIT2_WITNESS_TRANSFER_TYPEHASH = keccak256(
    "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,Witness witness)TokenPermissions(address token,uint256 amount)Witness(address to,uint256 validAfter)"
  );

  bytes32 public constant SESSION_DOMAIN_TYPEHASH =
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
  bytes32 public constant SESSION_DOMAIN_NAME_HASH = keccak256("Sequence X402 Session");
  bytes32 public constant SESSION_DOMAIN_VERSION_HASH = keccak256("1");
  bytes32 public constant SESSION_AUTHORIZATION_TYPEHASH =
    keccak256("X402SessionAuthorization(address wallet,bytes32 policyRoot,bytes32 payloadDigest)");

  address public immutable PERMIT2;
  address public immutable X402_PERMIT2_PROXY;

  struct Policy {
    address sessionKey;
    uint256 chainId;
    address token;
    uint256 maxAmountPerPayment;
    uint16 maxPayments;
    uint256 validBefore;
  }

  struct Permit2Payment {
    uint256 amount;
    uint256 nonce;
    uint256 deadline;
    address witnessTo;
    uint256 witnessValidAfter;
  }

  struct X402Signature {
    Policy policy;
    Permit2Payment payment;
    bytes sessionKeySignature;
  }

  struct ApprovalSignature {
    Policy policy;
    bytes sessionKeySignature;
  }

  error InvalidPayloadKind(uint8 kind);
  error InvalidSessionKey();
  error InvalidSessionToken();
  error InvalidChainId(uint256 chainId, uint256 expected);
  error SessionExpired(uint256 validBefore, uint256 currentTime);
  error InvalidPermit2();
  error InvalidApprovalCallsLength(uint256 length);
  error InvalidApprovalCall();
  error InvalidApprovalSelector(bytes4 selector);
  error InvalidApprovalSpender(address spender, address expected);
  error InvalidApprovalAmount(uint256 amount, uint256 expected);
  error InvalidSpace(uint256 space);
  error InvalidPaymentAmount(uint256 amount, uint256 maxAmount);
  error InvalidMaxPayments(uint16 maxPayments, uint16 maxAllowed);
  error InvalidNonceWord(uint256 word, uint256 expected);
  error InvalidNonceSlot(uint256 slot, uint16 maxPayments);
  error InvalidToken(address token, address expected);
  error InvalidDigest(bytes32 expected, bytes32 actual);
  error InvalidSessionKeySignature(address recovered, address expected);

  constructor(
    address permit2,
    address x402Permit2Proxy
  ) {
    if (permit2 == address(0) || x402Permit2Proxy == address(0)) {
      revert InvalidPermit2();
    }
    PERMIT2 = permit2;
    X402_PERMIT2_PROXY = x402Permit2Proxy;
  }

  /// @inheritdoc ISapient
  function recoverSapientSignature(
    Payload.Decoded calldata payload,
    bytes calldata signature
  ) external view returns (bytes32 imageHash) {
    if (payload.kind == Payload.KIND_DIGEST) {
      return _recoverPaymentSignature(payload, signature);
    }
    if (payload.kind == Payload.KIND_TRANSACTIONS) {
      return _recoverApprovalSignature(payload, signature);
    }

    revert InvalidPayloadKind(payload.kind);
  }

  function _recoverPaymentSignature(
    Payload.Decoded calldata payload,
    bytes calldata signature
  ) internal view returns (bytes32 imageHash) {
    X402Signature memory sig = abi.decode(signature, (X402Signature));
    bytes32 policyRoot = hashPolicy(sig.policy);
    address wallet = msg.sender;
    _validatePolicy(sig.policy);
    _validatePermit2Payment(sig.policy, sig.payment, wallet, policyRoot);

    bytes32 expectedDigest = hashPermit2Payment(sig.policy, sig.payment);
    if (expectedDigest != payload.digest) {
      revert InvalidDigest(expectedDigest, payload.digest);
    }

    bytes32 authDigest = hashSessionAuthorization(wallet, policyRoot, payload.digest);
    address recovered = ECDSA.recover(authDigest, sig.sessionKeySignature);
    if (recovered != sig.policy.sessionKey) {
      revert InvalidSessionKeySignature(recovered, sig.policy.sessionKey);
    }

    return policyRoot;
  }

  function _recoverApprovalSignature(
    Payload.Decoded calldata payload,
    bytes calldata signature
  ) internal view returns (bytes32 imageHash) {
    ApprovalSignature memory sig = abi.decode(signature, (ApprovalSignature));
    bytes32 policyRoot = hashPolicy(sig.policy);
    address wallet = msg.sender;
    _validatePolicy(sig.policy);
    _validateApprovalPayload(sig.policy, payload);

    bytes32 payloadDigest = _payloadHashFor(payload, wallet);
    bytes32 authDigest = hashSessionAuthorization(wallet, policyRoot, payloadDigest);
    address recovered = ECDSA.recover(authDigest, sig.sessionKeySignature);
    if (recovered != sig.policy.sessionKey) {
      revert InvalidSessionKeySignature(recovered, sig.policy.sessionKey);
    }

    return policyRoot;
  }

  /// @notice Hashes an x402 session policy into the sapient image hash committed by the wallet config.
  function hashPolicy(
    Policy memory policy
  ) public pure returns (bytes32) {
    return keccak256(
      abi.encode(
        X402_POLICY_TYPEHASH,
        policy.sessionKey,
        policy.chainId,
        policy.token,
        policy.maxAmountPerPayment,
        policy.maxPayments,
        policy.validBefore
      )
    );
  }

  /// @notice Deterministically derives the Permit2 unordered nonce word reserved for a wallet and policy.
  function permit2NonceWord(
    address wallet,
    bytes32 policyRoot
  ) public view returns (uint256) {
    return uint256(keccak256(abi.encode(PERMIT2_NONCE_WORD_TYPEHASH, address(this), wallet, policyRoot))) >> 8;
  }

  /// @notice Hashes a Permit2 witness transfer payment as the external digest checked by ERC-1271.
  function hashPermit2Payment(
    Policy memory policy,
    Permit2Payment memory payment
  ) public view returns (bytes32) {
    bytes32 tokenPermissionsHash = keccak256(abi.encode(TOKEN_PERMISSIONS_TYPEHASH, policy.token, payment.amount));
    bytes32 witness = keccak256(abi.encode(WITNESS_TYPEHASH, payment.witnessTo, payment.witnessValidAfter));
    bytes32 structHash = keccak256(
      abi.encode(
        PERMIT2_WITNESS_TRANSFER_TYPEHASH,
        tokenPermissionsHash,
        X402_PERMIT2_PROXY,
        payment.nonce,
        payment.deadline,
        witness
      )
    );
    return keccak256(abi.encodePacked("\x19\x01", _permit2DomainSeparator(), structHash));
  }

  /// @notice Hashes the session-key authorization over the already reconstructed external payment digest.
  function hashSessionAuthorization(
    address wallet,
    bytes32 policyRoot,
    bytes32 payloadDigest
  ) public view returns (bytes32) {
    bytes32 structHash = keccak256(abi.encode(SESSION_AUTHORIZATION_TYPEHASH, wallet, policyRoot, payloadDigest));
    return keccak256(abi.encodePacked("\x19\x01", _sessionDomainSeparator(), structHash));
  }

  function _validatePolicy(
    Policy memory policy
  ) internal view {
    if (policy.sessionKey == address(0)) {
      revert InvalidSessionKey();
    }
    if (policy.token == address(0)) {
      revert InvalidSessionToken();
    }
    if (policy.chainId != 0 && policy.chainId != block.chainid) {
      revert InvalidChainId(policy.chainId, block.chainid);
    }
    if (block.timestamp > policy.validBefore) {
      revert SessionExpired(policy.validBefore, block.timestamp);
    }
    if (policy.maxPayments == 0 || policy.maxPayments > MAX_PERMIT2_NONCE_SLOTS) {
      revert InvalidMaxPayments(policy.maxPayments, MAX_PERMIT2_NONCE_SLOTS);
    }
  }

  function _validateApprovalPayload(
    Policy memory policy,
    Payload.Decoded calldata payload
  ) internal view {
    if (payload.space > MAX_SPACE) {
      revert InvalidSpace(payload.space);
    }
    if (payload.calls.length != 1) {
      revert InvalidApprovalCallsLength(payload.calls.length);
    }

    Payload.Call calldata call = payload.calls[0];
    if (call.to != policy.token) {
      revert InvalidToken(call.to, policy.token);
    }
    if (
      call.value != 0 || call.delegateCall || call.onlyFallback
        || call.behaviorOnError != Payload.BEHAVIOR_REVERT_ON_ERROR
    ) {
      revert InvalidApprovalCall();
    }

    (address spender, uint256 amount) = _decodeApproveCall(call.data);
    if (spender != PERMIT2) {
      revert InvalidApprovalSpender(spender, PERMIT2);
    }
    if (amount != type(uint256).max) {
      revert InvalidApprovalAmount(amount, type(uint256).max);
    }
  }

  function _payloadHashFor(
    Payload.Decoded calldata payload,
    address wallet
  ) internal view returns (bytes32) {
    Payload.Decoded memory payloadMemory = payload;
    return Payload.hashFor(payloadMemory, wallet);
  }

  function _validatePermit2Payment(
    Policy memory policy,
    Permit2Payment memory payment,
    address wallet,
    bytes32 policyRoot
  ) internal view {
    if (payment.amount == 0 || payment.amount > policy.maxAmountPerPayment) {
      revert InvalidPaymentAmount(payment.amount, policy.maxAmountPerPayment);
    }

    uint256 nonceWord = payment.nonce >> 8;
    uint256 expectedNonceWord = permit2NonceWord(wallet, policyRoot);
    if (nonceWord != expectedNonceWord) {
      revert InvalidNonceWord(nonceWord, expectedNonceWord);
    }

    uint256 nonceSlot = uint8(payment.nonce);
    if (nonceSlot >= policy.maxPayments) {
      revert InvalidNonceSlot(nonceSlot, policy.maxPayments);
    }
  }

  function _decodeApproveCall(
    bytes calldata data
  ) internal pure returns (address spender, uint256 amount) {
    if (data.length != 68) {
      revert InvalidApprovalCall();
    }
    bytes4 selector = bytes4(data[:4]);
    if (selector != APPROVE_SELECTOR) {
      revert InvalidApprovalSelector(selector);
    }
    (spender, amount) = abi.decode(data[4:], (address, uint256));
  }

  function _permit2DomainSeparator() internal view returns (bytes32) {
    return keccak256(abi.encode(PERMIT2_DOMAIN_TYPEHASH, PERMIT2_NAME_HASH, block.chainid, PERMIT2));
  }

  function _sessionDomainSeparator() internal view returns (bytes32) {
    return keccak256(
      abi.encode(
        SESSION_DOMAIN_TYPEHASH, SESSION_DOMAIN_NAME_HASH, SESSION_DOMAIN_VERSION_HASH, block.chainid, address(this)
      )
    );
  }

}
