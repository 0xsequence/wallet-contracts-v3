// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { ECDSA } from "../../../lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

import { Payload } from "../../modules/Payload.sol";
import { ISapient } from "../../modules/interfaces/ISapient.sol";

/// @title X402SessionSapientSigner
/// @notice Digest-aware sapient signer for x402 exact Permit2 payments with a sliding Permit2 nonce window.
/// @dev The returned sapient image hash is the policy root committed in the wallet config.
///      The signer is stateless (`recoverSapientSignature` is `view`): the moving mask comes from `block.timestamp`
///      and one-time use comes from Permit2's nonce bitmap. The Permit2 nonce is treated as a policy-specific tape:
///      the Permit2 word starts from a policy-specific hash base, and the linear tape index is an offset from it.
///      For both payload kinds the session key signs over `Payload.hashFor(payload, wallet)`, so an authorization is
///      bound to the wallet that validates it and to the `parentWallets` chain that reached it.
contract X402SessionSapientSigner is ISapient {

  bytes4 public constant APPROVE_SELECTOR = bytes4(keccak256("approve(address,uint256)"));
  uint256 public constant MAX_SPACE = type(uint80).max - 1;
  uint16 public constant MAX_SLIDING_WINDOW_PAYMENTS = type(uint16).max;
  uint256 public constant PERMIT2_NONCE_BIT_INDEX_BITS = 8;
  uint256 public constant PERMIT2_BITS_PER_WORD = 256;
  uint256 public constant NONCE_TAPE_WORD_OFFSET_BITS = 64;
  uint256 public constant NONCE_TAPE_WORD_BASE_BITS = 184; // Permit2 word bits (248) - word offset bits (64)
  uint256 public constant NONCE_TAPE_WORD_OFFSET_MASK = uint256(type(uint64).max);
  uint256 public constant MAX_NONCE_TAPE_INDEX =
    uint256(type(uint64).max) * PERMIT2_BITS_PER_WORD + (PERMIT2_BITS_PER_WORD - 1);

  bytes32 public constant X402_POLICY_TYPEHASH = keccak256(
    "X402SessionPolicy(address sessionKey,uint256 chainId,address token,uint256 maxAmountPerPayment,uint64 windowStart,uint64 windowDuration,uint32 maxWindows,uint16 maxPayments,uint256 validBefore)"
  );
  bytes32 public constant PERMIT2_NONCE_WORD_BASE_TYPEHASH =
    keccak256("SequenceX402Permit2NonceWordBase(address signer,bytes32 policyRoot)");

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
    uint64 windowStart; // anchor for tape position 0; also acts as validFrom
    uint64 windowDuration; // time over which the full maxPayments capacity refills
    uint32 maxWindows; // hard cap in full refill windows; 0 means unbounded (until validBefore)
    uint16 maxPayments; // live tape positions in the sliding acceptance mask
    uint256 validBefore; // hard backstop expiry for the whole policy
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
  error InvalidWindowDuration();
  error InvalidMaxPayments(uint16 maxPayments, uint16 maxAllowed);
  error WindowNotStarted(uint256 windowStart, uint256 currentTime);
  error RefillWindowsExhausted(uint256 refillWindowIndex, uint256 maxWindows);
  error InvalidNonceWord(uint256 word, uint256 minWord, uint256 maxWord);
  error InvalidNonceTapeIndex(uint256 nonceIndex, uint256 minNonceIndex, uint256 maxNonceIndex);
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
    _validatePermit2Payment(sig.policy, sig.payment, policyRoot);

    bytes32 expectedDigest = hashPermit2Payment(sig.policy, sig.payment);
    if (expectedDigest != payload.digest) {
      revert InvalidDigest(expectedDigest, payload.digest);
    }

    bytes32 payloadDigest = _payloadHashFor(payload, wallet);
    bytes32 authDigest = hashSessionAuthorization(wallet, policyRoot, payloadDigest);
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
        policy.windowStart,
        policy.windowDuration,
        policy.maxWindows,
        policy.maxPayments,
        policy.validBefore
      )
    );
  }

  /// @notice The full refill-window index at the current block timestamp.
  /// @dev This is used only for the optional lifetime cap. Payments are authorized by the finer sliding tape range.
  function currentRefillWindowIndex(
    Policy memory policy
  ) public view returns (uint256) {
    if (block.timestamp < policy.windowStart) {
      revert WindowNotStarted(policy.windowStart, block.timestamp);
    }
    if (policy.windowDuration == 0) {
      revert InvalidWindowDuration();
    }
    return (block.timestamp - policy.windowStart) / policy.windowDuration;
  }

  /// @notice The inclusive linear Permit2 nonce tape range accepted at the current block timestamp.
  /// @dev At `windowStart`, the full initial mask `[0, maxPayments - 1]` is live. As time advances, the mask slides
  ///      by `maxPayments` tape positions per `windowDuration`, with integer rounding toward zero.
  function currentNonceTapeRange(
    Policy memory policy
  ) public view returns (uint256 minNonceIndex, uint256 maxNonceIndex) {
    if (block.timestamp < policy.windowStart) {
      revert WindowNotStarted(policy.windowStart, block.timestamp);
    }
    if (policy.windowDuration == 0) {
      revert InvalidWindowDuration();
    }
    if (policy.maxPayments == 0) {
      revert InvalidMaxPayments(policy.maxPayments, MAX_SLIDING_WINDOW_PAYMENTS);
    }

    uint256 elapsed = block.timestamp - policy.windowStart;
    minNonceIndex = elapsed * uint256(policy.maxPayments) / uint256(policy.windowDuration);
    maxNonceIndex = minNonceIndex + uint256(policy.maxPayments) - 1;

    if (policy.maxWindows != 0) {
      uint256 maxLifetimeNonceIndex = uint256(policy.maxWindows) * uint256(policy.maxPayments) - 1;
      if (minNonceIndex > maxLifetimeNonceIndex) {
        revert RefillWindowsExhausted(currentRefillWindowIndex(policy), policy.maxWindows);
      }
      if (maxNonceIndex > maxLifetimeNonceIndex) {
        maxNonceIndex = maxLifetimeNonceIndex;
      }
    }
  }

  /// @notice Deterministically derives the first Permit2 word reserved for a policy's nonce tape.
  /// @dev The hash prefix is shifted left by 64 bits so the tape can add a 64-bit word offset without wrapping.
  function permit2NonceWordBase(
    bytes32 policyRoot
  ) public view returns (uint256) {
    uint256 hashPrefix = uint256(keccak256(abi.encode(PERMIT2_NONCE_WORD_BASE_TYPEHASH, address(this), policyRoot)))
      >> (256 - NONCE_TAPE_WORD_BASE_BITS);
    return hashPrefix << NONCE_TAPE_WORD_OFFSET_BITS;
  }

  /// @notice Returns the Permit2 word for a linear tape index.
  /// @dev The low 8 bits of `nonceIndex` become the Permit2 bit index. The higher bits become the word offset.
  function permit2NonceWord(
    bytes32 policyRoot,
    uint256 nonceIndex
  ) public view returns (uint256) {
    uint256 wordOffset = _nonceIndexToPermit2WordOffset(nonceIndex);
    return permit2NonceWordBase(policyRoot) + wordOffset;
  }

  /// @notice Returns the full Permit2 nonce for a linear tape index.
  function permit2Nonce(
    bytes32 policyRoot,
    uint256 nonceIndex
  ) public view returns (uint256) {
    return _packPermit2Nonce(permit2NonceWord(policyRoot, nonceIndex), uint8(nonceIndex));
  }

  /// @notice Decodes a full Permit2 nonce into a linear tape index for the given policy.
  function decodePermit2Nonce(
    bytes32 policyRoot,
    uint256 nonce
  ) public view returns (uint256 nonceIndex) {
    return _nonceIndexFromPermit2Nonce(policyRoot, nonce);
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

  /// @notice Hashes the session-key authorization over a wallet-scoped payload hash.
  /// @dev `payloadDigest` is always `Payload.hashFor(payload, wallet)`, for both payload kinds. For a payment the
  ///      payload is `Payload.fromDigest(permit2Digest)`, so the authorization commits to the Permit2 digest plus the
  ///      validating wallet, its `parentWallets` and the `noChainId` flag. Note that without the `parentWallets`
  ///      commitment a payment signed for one wallet could be replayed against another wallet that delegates to it.
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
    if (policy.windowDuration == 0) {
      revert InvalidWindowDuration();
    }
    if (policy.maxPayments == 0) {
      revert InvalidMaxPayments(policy.maxPayments, MAX_SLIDING_WINDOW_PAYMENTS);
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
    bytes32 policyRoot
  ) internal view {
    if (payment.amount == 0 || payment.amount > policy.maxAmountPerPayment) {
      revert InvalidPaymentAmount(payment.amount, policy.maxAmountPerPayment);
    }

    (uint256 minNonceIndex, uint256 maxNonceIndex) = currentNonceTapeRange(policy);

    uint256 nonceIndex = decodePermit2Nonce(policyRoot, payment.nonce);
    if (nonceIndex < minNonceIndex || nonceIndex > maxNonceIndex) {
      revert InvalidNonceTapeIndex(nonceIndex, minNonceIndex, maxNonceIndex);
    }
  }

  function _nonceIndexToPermit2WordOffset(
    uint256 nonceIndex
  ) internal pure returns (uint256 wordOffset) {
    wordOffset = nonceIndex >> PERMIT2_NONCE_BIT_INDEX_BITS;
    if (wordOffset > NONCE_TAPE_WORD_OFFSET_MASK) {
      revert InvalidNonceTapeIndex(nonceIndex, 0, MAX_NONCE_TAPE_INDEX);
    }
  }

  function _nonceIndexFromPermit2Nonce(
    bytes32 policyRoot,
    uint256 nonce
  ) internal view returns (uint256) {
    uint256 word = nonce >> PERMIT2_NONCE_BIT_INDEX_BITS;
    uint256 minWord = permit2NonceWordBase(policyRoot);
    uint256 maxWord = minWord + NONCE_TAPE_WORD_OFFSET_MASK;
    if (word < minWord || word > maxWord) {
      revert InvalidNonceWord(word, minWord, maxWord);
    }

    uint256 wordOffset = word - minWord;
    return wordOffset * PERMIT2_BITS_PER_WORD + uint8(nonce);
  }

  function _packPermit2Nonce(
    uint256 word,
    uint8 bitIndex
  ) internal pure returns (uint256) {
    return (word << PERMIT2_NONCE_BIT_INDEX_BITS) | bitIndex;
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
