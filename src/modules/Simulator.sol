// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

import { LibOptim } from "../utils/LibOptim.sol";
import { Calls } from "./Calls.sol";
import { Payload } from "./Payload.sol";
import { BaseAuth } from "./auth/BaseAuth.sol";

/**
 * @notice Contains an alternative implementation of the MainModules that skips validation of
 *   signatures, this implementation SHOULD NOT be used directly on a wallet.
 *
 *   Intended to be used only for gas estimation, using eth_call and overrides.
 */
abstract contract Simulator is BaseAuth {

  enum Status {
    Skipped,
    Success,
    Failed,
    Reverted,
    Aborted,
    NotEnoughGas
  }

  struct Result {
    Status status;
    bytes result;
    uint256 gasUsed;
  }

  /**
   * @notice Simulates a payload, bypassing nonce, signature, or replay protection.
   * @param _payload The payload to simulate
   * @param _signature The signature of the payload
   * @return results The results of the simulated calls.
   */
  function simulate(
    bytes calldata _payload,
    bytes calldata _signature
  ) external payable virtual returns (Result[] memory results) {
    Payload.Decoded memory decoded = Payload.fromPackedCalls(_payload);

    bytes32 opHash = Payload.hash(decoded);

    return _simulate(opHash, decoded);
  }

  /**
   * @notice Simulate each transaction in a bundle for gas usage and execution result
   * @param _opHash The hash of the operation
   * @param _decoded The decoded payload
   * @return results The results of the simulated calls.
   */
  function _simulate(bytes32 _opHash, Payload.Decoded memory _decoded) private returns (Result[] memory results) {
    bool errorFlag = false;

    uint256 numCalls = _decoded.calls.length;
    results = new Result[](numCalls);
    for (uint256 i = 0; i < numCalls; i++) {
      Payload.Call memory call = _decoded.calls[i];

      // If the call is of fallback kind, and errorFlag is set to false
      // then we can skip the call
      if (call.onlyFallback && !errorFlag) {
        errorFlag = false;
        emit Calls.CallSkipped(_opHash, i);
        continue;
      }

      uint256 gasLimit = call.gasLimit;
      if (gasLimit != 0 && gasleft() < gasLimit) {
        results[i].status = Status.NotEnoughGas;
        results[i].result = abi.encode(gasleft());
        return results;
      }

      bool success;
      if (call.delegateCall) {
        uint256 initial = gasleft();
        (success) = LibOptim.delegatecall(call.to, gasLimit == 0 ? gasleft() : gasLimit, call.data);
        results[i].gasUsed = initial - gasleft();
      } else {
        uint256 initial = gasleft();
        (success) = LibOptim.call(call.to, call.value, gasLimit == 0 ? gasleft() : gasLimit, call.data);
        results[i].gasUsed = initial - gasleft();
      }

      if (!success) {
        if (call.behaviorOnError == Payload.BEHAVIOR_IGNORE_ERROR) {
          errorFlag = true;
          emit Calls.CallFailed(_opHash, i);
          results[i].status = Status.Failed;
          results[i].result = LibOptim.returnData();
          continue;
        }

        if (call.behaviorOnError == Payload.BEHAVIOR_REVERT_ON_ERROR) {
          results[i].status = Status.Reverted;
          results[i].result = LibOptim.returnData();
          return results;
        }

        if (call.behaviorOnError == Payload.BEHAVIOR_ABORT_ON_ERROR) {
          emit Calls.CallAborted(_opHash, i);
          results[i].status = Status.Aborted;
          results[i].result = LibOptim.returnData();
          break;
        }
      }

      emit Calls.CallSuccess(_opHash, i);
      results[i].status = Status.Success;
      results[i].result = LibOptim.returnData();
    }
  }

  /**
   * @notice Validates any signature image, because the wallet is public and has no owner.
   * @return true, all signatures are valid.
   */
  function _isValidImage(
    bytes32 _imageHash
  ) internal view virtual override returns (bool) {
    return true;
  }

}
