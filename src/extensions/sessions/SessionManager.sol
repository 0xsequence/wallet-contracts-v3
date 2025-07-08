// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../../modules/Payload.sol";
import { ISapient } from "../../modules/interfaces/ISapient.sol";
import { LibBytes } from "../../utils/LibBytes.sol";

import { SessionErrors } from "./SessionErrors.sol";
import { SessionSig } from "./SessionSig.sol";
import {
  ExplicitSessionManager,
  IExplicitSessionManager,
  SessionPermissions,
  SessionUsageLimits
} from "./explicit/ExplicitSessionManager.sol";
import { Permission, UsageLimit } from "./explicit/Permission.sol";
import { ImplicitSessionManager } from "./implicit/ImplicitSessionManager.sol";

using LibBytes for bytes;

/// @title SessionManager
/// @author Michael Standen, Agustin Aguilar
/// @notice Manager for smart sessions
contract SessionManager is ISapient, ImplicitSessionManager, ExplicitSessionManager {

  /// @notice Error thrown when the payload kind is invalid
  error InvalidPayloadKind();
  /// @notice Error thrown when the calls length is invalid
  error InvalidCallsLength();

  /// @inheritdoc ISapient
  function recoverSapientSignature(
    Payload.Decoded calldata payload,
    bytes calldata encodedSignature
  ) external view returns (bytes32) {
    // Validate outer Payload
    if (payload.kind != Payload.KIND_TRANSACTIONS) {
      revert InvalidPayloadKind();
    }
    if (payload.calls.length == 0) {
      revert InvalidCallsLength();
    }

    // Decode signature
    SessionSig.DecodedSignature memory sig = SessionSig.recoverSignature(payload, encodedSignature);

    address wallet = msg.sender;

    // Initialize session usage limits for explicit session
    SessionUsageLimits[] memory sessionUsageLimits = new SessionUsageLimits[](payload.calls.length);

    for (uint256 i = 0; i < payload.calls.length; i++) {
      // General validation
      Payload.Call calldata call = payload.calls[i];
      if (call.delegateCall) {
        revert SessionErrors.InvalidDelegateCall();
      }

      // Validate call signature
      SessionSig.CallSignature memory callSignature = sig.callSignatures[i];
      if (callSignature.isImplicit) {
        // Validate implicit calls
        _validateImplicitCall(
          call, wallet, callSignature.sessionSigner, callSignature.attestation, sig.implicitBlacklist
        );
      } else {
        // Find the session usage limits for the current call
        SessionUsageLimits memory limits;
        uint256 limitsIdx;
        for (limitsIdx = 0; limitsIdx < sessionUsageLimits.length; limitsIdx++) {
          if (sessionUsageLimits[limitsIdx].signer == address(0)) {
            // Initialize new session usage limits
            limits.signer = callSignature.sessionSigner;
            limits.limits = new UsageLimit[](0);
            bytes32 usageHash = keccak256(abi.encode(callSignature.sessionSigner, VALUE_TRACKING_ADDRESS));
            limits.totalValueUsed = getLimitUsage(wallet, usageHash);
            break;
          }
          if (sessionUsageLimits[limitsIdx].signer == callSignature.sessionSigner) {
            limits = sessionUsageLimits[limitsIdx];
            break;
          }
        }
        // Validate explicit calls. Obtain usage limits for increment validation.
        (limits) = _validateExplicitCall(
          payload,
          i,
          wallet,
          callSignature.sessionSigner,
          sig.sessionPermissions,
          callSignature.sessionPermission,
          limits
        );
        sessionUsageLimits[limitsIdx] = limits;
      }
    }

    {
      // Reduce the size of the sessionUsageLimits array
      SessionUsageLimits[] memory actualSessionUsageLimits = new SessionUsageLimits[](sessionUsageLimits.length);
      uint256 actualSize;
      for (uint256 i = 0; i < sessionUsageLimits.length; i++) {
        if (sessionUsageLimits[i].limits.length > 0 || sessionUsageLimits[i].totalValueUsed > 0) {
          actualSessionUsageLimits[actualSize] = sessionUsageLimits[i];
          actualSize++;
        }
      }
      assembly {
        mstore(actualSessionUsageLimits, actualSize)
      }

      // Bulk validate the updated usage limits
      Payload.Call calldata lastCall = payload.calls[payload.calls.length - 1];
      _validateLimitUsageIncrement(lastCall, actualSessionUsageLimits);
    }

    // Return the image hash
    return sig.imageHash;
  }

}
