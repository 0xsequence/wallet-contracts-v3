// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../Payload.sol";

/**
 * @title ISapient
 * @author Agusx1211, Michael Standen
 * @notice Sapient signers take an explicit payload and return their own "imageHash" as result
 * @dev The consumer of this signer must validate if the imageHash is valid or not, for the desired configuration
 */
interface ISapient {
  function isValidSapientSignature(
    Payload.Decoded calldata _payload,
    bytes calldata _signature
  ) external view returns (bytes32);
}

/**
 * @title ISapient
 * @author Agusx1211, Michael Standen
 * @notice Sapient signers take a compacted payload and return their own "imageHash" as result
 * @dev The consumer of this signer must validate if the imageHash is valid or not, for the desired configuration
 */
interface ISapientCompact {
  function isValidSapientSignatureCompact(
    bytes32 _digest,
    bytes calldata _signature
  ) external view returns (bytes32);
}
