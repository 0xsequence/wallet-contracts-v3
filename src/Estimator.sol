// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Stage2Module } from "./Stage2Module.sol";
import { Payload } from "./modules/Payload.sol";
import { LibOptim } from "./utils/LibOptim.sol";

contract Estimator is Stage2Module {

  function _isValidImage(
    bytes32 _imageHash
  ) internal view virtual override returns (bool) {
    super._isValidImage(_imageHash);
    return true;
  }

  function estimate(
    bytes calldata _payload,
    bytes calldata _signature
  ) external payable virtual returns (uint256 gasUsed) {
    uint256 initial = gasleft();

    Payload.Decoded memory decoded = Payload.fromPackedCalls(_payload);

    _consumeNonce(decoded.space, readNonce(decoded.space));
    (bool isValid, bytes32 opHash) = signatureValidation(decoded, _signature);

    if (!isValid) {
      revert InvalidSignature(decoded, _signature);
    }

    _estimate(opHash, decoded);

    return initial - gasleft();
  }

  function _estimate(bytes32 _opHash, Payload.Decoded memory _decoded) private {
    bool errorFlag = false;

    uint256 numCalls = _decoded.calls.length;
    for (uint256 i = 0; i < numCalls; i++) {
      Payload.Call memory call = _decoded.calls[i];

      // If the call is of fallback kind, and errorFlag is set to false
      // then we can skip the call
      if (call.onlyFallback && !errorFlag) {
        errorFlag = false;
        emit CallSkipped(_opHash, i);
        continue;
      }

      uint256 gasLimit = call.gasLimit;
      if (gasLimit != 0 && gasleft() < gasLimit) {
        revert NotEnoughGas(_decoded, i, gasleft());
      }

      bool success;
      if (call.delegateCall) {
        (success) = LibOptim.delegatecall(call.to, gasLimit == 0 ? gasleft() : gasLimit, call.data);
      } else {
        (success) = LibOptim.call(call.to, call.value, gasLimit == 0 ? gasleft() : gasLimit, call.data);
      }

      if (!success) {
        if (call.behaviorOnError == Payload.BEHAVIOR_IGNORE_ERROR) {
          errorFlag = true;
          emit CallFailed(_opHash, i, LibOptim.returnData());
          continue;
        }

        if (call.behaviorOnError == Payload.BEHAVIOR_REVERT_ON_ERROR) {
          revert Reverted(_decoded, i, LibOptim.returnData());
        }

        if (call.behaviorOnError == Payload.BEHAVIOR_ABORT_ON_ERROR) {
          emit CallAborted(_opHash, i, LibOptim.returnData());
          break;
        }
      }

      emit CallSuccess(_opHash, i);
    }
  }

}
