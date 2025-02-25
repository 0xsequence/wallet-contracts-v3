// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { LibOptim } from "../utils/LibOptim.sol";
import { Nonce } from "./Nonce.sol";
import { Payload } from "./Payload.sol";
import { BaseAuth } from "./auth/BaseAuth.sol";
import { SelfAuth } from "./auth/SelfAuth.sol";

abstract contract Calls is BaseAuth, Nonce {

  event Success(bytes32 _opHash, uint256 _index);
  event Failed(bytes32 _opHash, uint256 _index);
  event Aborted(bytes32 _opHash, uint256 _index);
  event Skipped(bytes32 _opHash, uint256 _index);

  error Reverted(Payload.Decoded _payload, uint256 _index, bytes _returnData);
  error InvalidSignature(Payload.Decoded _payload, bytes _signature);
  error NotEnoughGas(Payload.Decoded _payload, uint256 _index, uint256 _gasLeft);

  function execute(bytes calldata _payload, bytes calldata _signature) external payable virtual {
    Payload.Decoded memory decoded = Payload.fromPackedCalls(_payload);

    _consumeNonce(decoded.space, decoded.nonce);
    (bool isValid, bytes32 opHash) = signatureValidation(decoded, _signature);

    if (!isValid) {
      revert InvalidSignature(decoded, _signature);
    }

    _execute(opHash, decoded);
  }

  function selfExecute(
    bytes calldata _payload
  ) external payable virtual onlySelf {
    Payload.Decoded memory decoded = Payload.fromPackedCalls(_payload);
    bytes32 opHash = Payload.hash(decoded);
    _execute(opHash, decoded);
  }

  function _execute(bytes32 _opHash, Payload.Decoded memory _decoded) private {
    bool errorFlag = false;

    uint256 numCalls = _decoded.calls.length;
    for (uint256 i = 0; i < numCalls; i++) {
      Payload.Call memory call = _decoded.calls[i];

      // If the call is of fallback kind, and errorFlag is set to false
      // then we can skip the call
      if (call.onlyFallback && !errorFlag) {
        errorFlag = false;
        emit Skipped(_opHash, i);
        continue;
      }

      uint256 gasLimit = call.gasLimit;
      if (gasLimit != 0 && gasleft() < gasLimit) {
        revert NotEnoughGas(_decoded, i, gasleft());
      }

      bool success;
      if (call.delegateCall) {
        (success) = LibOptim.delegatecall(call.to, gasLimit, call.data);
      } else {
        (success) = LibOptim.call(call.to, call.value, gasLimit, call.data);
      }

      if (!success) {
        if (call.behaviorOnError == Payload.BEHAVIOR_IGNORE_ERROR) {
          errorFlag = true;
          emit Failed(_opHash, i);
          continue;
        }

        if (call.behaviorOnError == Payload.BEHAVIOR_REVERT_ON_ERROR) {
          revert Reverted(_decoded, i, LibOptim.returnData());
        }

        if (call.behaviorOnError == Payload.BEHAVIOR_ABORT_ON_ERROR) {
          emit Aborted(_opHash, i);
          break;
        }
      }

      emit Success(_opHash, i);
    }
  }

}
