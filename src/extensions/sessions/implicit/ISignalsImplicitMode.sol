// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../../../modules/Payload.sol";
import { Attestation } from "./Attestation.sol";

bytes32 constant ACCEPT_IMPLICIT_REQUEST_MAGIC_PREFIX = keccak256(abi.encodePacked("acceptImplicitRequest"));

interface ISignalsImplicitMode {

  /// @notice Accepts an implicit request
  /// @param wallet The wallet's address
  /// @param attestation The attestation data
  /// @param call The call to validate
  /// @return The hash of the implicit request if valid
  function acceptImplicitRequest(
    address wallet,
    // Attestation data
    Attestation calldata attestation,
    // Transaction data
    Payload.Call calldata call
  ) external view returns (bytes32);

}
