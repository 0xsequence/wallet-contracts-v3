// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { IERC20 } from "../../../lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import { ECDSA } from "../../../lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

import { Payload } from "../../modules/Payload.sol";
import { ISapient } from "../../modules/interfaces/ISapient.sol";
import { SessionErrors } from "./SessionErrors.sol";

/// @notice One payment up to a cap per UTC calendar month, committed as a sapient leaf in the wallet configuration.
/// @dev The first call consumes usage before the payment executes. Unused capacity does not carry over.
contract RecurringSessionSapientSigner is ISapient {

  uint256 public constant MAX_SPACE = type(uint80).max - 1;

  struct Policy {
    address signer;
    uint256 chainId; // 0 = any chain; usage is always local to each chain
    address token; // address(0) = native token
    address recipient;
    uint256 limit;
    uint64 start;
    uint64 deadline; // 0 = no expiry
  }

  struct Signature {
    Policy policy;
    bytes signature; // ECDSA over Payload.hashFor(payload, wallet), including the accounting call
  }

  /// @notice Wallet -> policy hash -> period -> consumed amount in token base units.
  mapping(address => mapping(bytes32 => mapping(uint256 => uint256))) public usage;

  event UsageConsumed(address indexed wallet, bytes32 indexed policyHash, uint256 period, uint256 amount);

  error InvalidPolicy();
  error SessionNotStarted(uint256 start);
  error InvalidPayment();
  error SpendLimitExceeded(uint256 amount, uint256 limit);
  error SubscriptionAlreadyUsed();

  /// @notice Consumes the caller's budget. Session validation requires this as the first call of the batch.
  /// @dev Like existing session accounting, a wallet may consume its own budget through another authorized path.
  function consumeUsage(
    bytes32 policyHash,
    uint256 period,
    uint256 amount
  ) external {
    usage[msg.sender][policyHash][period] += amount;
    emit UsageConsumed(msg.sender, policyHash, period, amount);
  }

  /// @notice The image hash to commit alongside this signer in the wallet configuration.
  function hashPolicy(
    Policy memory policy
  ) public pure returns (bytes32) {
    return keccak256(abi.encode(policy));
  }

  /// @notice The current UTC calendar month as year * 12 + month - 1. Resets on the first at 00:00 UTC.
  function currentPeriod(
    Policy memory policy
  ) public view returns (uint256) {
    if (block.timestamp < policy.start) {
      revert SessionNotStarted(policy.start);
    }
    return _calendarMonth(block.timestamp);
  }

  /// @inheritdoc ISapient
  function recoverSapientSignature(
    Payload.Decoded calldata payload,
    bytes calldata signature
  ) external view returns (bytes32 policyHash) {
    if (payload.kind != Payload.KIND_TRANSACTIONS) {
      revert SessionErrors.InvalidPayloadKind();
    }
    if (payload.space > MAX_SPACE) {
      revert SessionErrors.InvalidSpace(payload.space);
    }
    if (payload.calls.length != 2) {
      revert SessionErrors.InvalidCallsLength();
    }

    Signature memory sig = abi.decode(signature, (Signature));
    Policy memory policy = sig.policy;
    if (policy.signer == address(0) || policy.recipient == address(0) || policy.limit == 0) {
      revert InvalidPolicy();
    }
    if (policy.chainId != 0 && policy.chainId != block.chainid) {
      revert SessionErrors.InvalidChainId(policy.chainId);
    }
    if (policy.deadline != 0 && block.timestamp > policy.deadline) {
      revert SessionErrors.SessionExpired(policy.deadline);
    }

    uint256 period = currentPeriod(policy);
    policyHash = hashPolicy(policy);
    address wallet = msg.sender;
    // Parent wallets are ordered from the outer executor to the innermost validating wallet.
    address executor = payload.parentWallets.length == 0 ? wallet : payload.parentWallets[0];
    for (uint256 i = 0; i < payload.calls.length; i++) {
      Payload.Call calldata call = payload.calls[i];
      if (call.delegateCall) {
        revert SessionErrors.InvalidDelegateCall();
      }
      if (call.onlyFallback || call.behaviorOnError != Payload.BEHAVIOR_REVERT_ON_ERROR) {
        revert SessionErrors.InvalidBehavior();
      }
      if (call.to == wallet || call.to == executor) {
        revert SessionErrors.InvalidSelfCall();
      }
    }

    Payload.Call calldata payment = payload.calls[1];
    if (payment.to == address(this)) {
      revert SessionErrors.InvalidSelfCall();
    }
    uint256 amount;
    if (policy.token == address(0)) {
      if (payment.to != policy.recipient || payment.data.length != 0) {
        revert InvalidPayment();
      }
      amount = payment.value;
    } else {
      if (
        payment.to != policy.token || payment.value != 0 || payment.data.length != 68
          || bytes4(payment.data[:4]) != IERC20.transfer.selector
      ) {
        revert InvalidPayment();
      }
      address recipient;
      (recipient, amount) = abi.decode(payment.data[4:], (address, uint256));
      if (recipient != policy.recipient) {
        revert InvalidPayment();
      }
    }

    if (amount == 0) {
      revert InvalidPayment();
    }
    if (usage[executor][policyHash][period] != 0) {
      revert SubscriptionAlreadyUsed();
    }
    if (amount > policy.limit) {
      revert SpendLimitExceeded(amount, policy.limit);
    }

    // The signed call binds the policy, period and payment amount, preventing delayed settlement into another period.
    Payload.Call calldata firstCall = payload.calls[0];
    bytes memory expectedData = abi.encodeCall(this.consumeUsage, (policyHash, period, amount));
    if (firstCall.to != address(this) || firstCall.value != 0 || keccak256(firstCall.data) != keccak256(expectedData)) {
      revert SessionErrors.InvalidLimitUsageIncrement();
    }

    address recovered = ECDSA.recover(Payload.hashFor(payload, wallet), sig.signature);
    if (recovered != policy.signer) {
      revert SessionErrors.InvalidSessionSigner(recovered);
    }
  }

  /// @dev Gregorian civil-from-days arithmetic, with March as the first month of each 400-year era.
  ///      https://howardhinnant.github.io/date_algorithms.html#civil_from_days
  function _calendarMonth(
    uint256 timestamp
  ) internal pure returns (uint256) {
    uint256 daysSinceMarch = timestamp / 1 days + 719468;
    uint256 era = daysSinceMarch / 146097;
    uint256 dayOfEra = daysSinceMarch % 146097;
    uint256 yearOfEra = (dayOfEra - dayOfEra / 1460 + dayOfEra / 36524 - dayOfEra / 146096) / 365;
    uint256 year = yearOfEra + era * 400;
    uint256 dayOfYear = dayOfEra - (365 * yearOfEra + yearOfEra / 4 - yearOfEra / 100);
    uint256 marchMonth = (5 * dayOfYear + 2) / 153;
    uint256 month = marchMonth < 10 ? marchMonth + 3 : marchMonth - 9;
    if (month <= 2) {
      year++;
    }
    return year * 12 + month - 1;
  }

}
