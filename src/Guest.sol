// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Calls } from "./modules/Calls.sol";
import { Payload } from "./modules/Payload.sol";

import { IAuth } from "./modules/interfaces/IAuth.sol";
import { LibBytesPointer } from "./utils/LibBytesPointer.sol";
import { LibOptim } from "./utils/LibOptim.sol";

contract Guest {

  using LibBytesPointer for bytes;

  error DelegateCallNotAllowed(uint256 index);

  fallback() external {
    bytes calldata calls;

    // Check if the first byte is 0x1f (same as on the `execute` structure)
    if (msg.data[0] == 0x1f) {
      // Interpret the data as if it were a call
      // to the `execute` function of the `Calls` module
      uint256 callsOffset;
      uint256 callsLength;
      assembly {
        calls.offset := 0x64
        calls.length := calldataload(0x24)
      }

      assembly {
        callsOffset := calls.offset
        callsLength := calls.length
      }
    } else {
      // Fallback to reading the data as a packed payload directly
      // this should not be a problem since `0x1f` does not make sense
      // as a global flag for the Guest Module
      calls = msg.data;
    }

    Payload.Decoded memory decoded = Payload.fromPackedCalls(calls);
    bytes32 opHash = Payload.hash(decoded);
    _dispatchGuest(decoded, opHash);
  }

  function _dispatchGuest(Payload.Decoded memory _decoded, bytes32 _opHash) internal {
    bool errorFlag = false;

    uint256 numCalls = _decoded.calls.length;
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
        revert Calls.NotEnoughGas(_decoded, i, gasleft());
      }

      if (call.delegateCall) {
        revert DelegateCallNotAllowed(i);
      }

      bool success = LibOptim.call(call.to, call.value, gasLimit == 0 ? gasleft() : gasLimit, call.data);
      if (!success) {
        if (call.behaviorOnError == Payload.BEHAVIOR_IGNORE_ERROR) {
          errorFlag = true;
          emit Calls.CallFailed(_opHash, i);
          continue;
        }

        if (call.behaviorOnError == Payload.BEHAVIOR_REVERT_ON_ERROR) {
          revert Calls.Reverted(_decoded, i, LibOptim.returnData());
        }

        if (call.behaviorOnError == Payload.BEHAVIOR_ABORT_ON_ERROR) {
          emit Calls.CallAborted(_opHash, i);
          break;
        }
      }

      emit Calls.CallSuccess(_opHash, i);
    }
  }

}
