// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { ISapient } from "../../src/modules/interfaces/ISapient.sol";
import { ISapientCompact } from "../../src/modules/interfaces/ISapient.sol";
import { Payload } from "../../src/modules/Payload.sol";

/// @title MockSapient
/// @author Michael Standen
/// @notice A mock sapient signer that returns the signature as the image hash
contract MockSapient is ISapient, ISapientCompact {

  error InvalidSignatureLength();

  /// @inheritdoc ISapient
  function recoverSapientSignature(Payload.Decoded calldata, bytes calldata signature) external pure returns (bytes32) {
    if (signature.length != 32) {
      revert InvalidSignatureLength();
    }
    return bytes32(signature);
  }

  /// @inheritdoc ISapientCompact
  function recoverSapientSignatureCompact(bytes32, bytes calldata signature) external pure returns (bytes32) {
    if (signature.length != 32) {
      revert InvalidSignatureLength();
    }
    return bytes32(signature);
  }

}
