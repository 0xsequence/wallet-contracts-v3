// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "./modules/Payload.sol";
import { IDelegatedExtension } from "./modules/interfaces/IDelegatedExtension.sol";
import { LibOptim } from "./utils/LibOptim.sol";

contract Simulator {

  enum Status {
    Skipped,
    Succeeded,
    Failed,
    Aborted,
    Reverted,
    NotEnoughGas
  }

  struct Result {
    Status status;
    bytes result;
    uint256 gasUsed;
  }

  function simulate(
    Payload.Call[] calldata _calls
  ) external returns (Result[] memory results) {
    uint256 startingGas = gasleft();
    bool errorFlag = false;

    uint256 numCalls = _calls.length;
    results = new Result[](numCalls);
    for (uint256 i = 0; i < numCalls; i++) {
      Payload.Call memory call = _calls[i];

      if (errorFlag) {
        // Always reset the error flag so that
        // onlyFallback calls only apply when the immediately preceding transaction fails
        errorFlag = false;
      } else if (call.onlyFallback) {
        // If the call is of fallback kind and errorFlag is set to false,
        // then we can skip the call
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
        (success) = LibOptim.delegatecall(
          call.to,
          gasLimit == 0 ? gasleft() : gasLimit,
          abi.encodeWithSelector(
            IDelegatedExtension.handleSequenceDelegateCall.selector, 0, startingGas, i, numCalls, 0, call.data
          )
        );
        results[i].gasUsed = initial - gasleft();
      } else {
        uint256 initial = gasleft();
        (success) = LibOptim.call(call.to, call.value, gasLimit == 0 ? gasleft() : gasLimit, call.data);
        results[i].gasUsed = initial - gasleft();
      }

      if (!success) {
        if (call.behaviorOnError == Payload.BEHAVIOR_IGNORE_ERROR) {
          errorFlag = true;
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
          results[i].status = Status.Aborted;
          results[i].result = LibOptim.returnData();
          break;
        }
      }

      results[i].status = Status.Succeeded;
      results[i].result = LibOptim.returnData();
    }
  }

}
