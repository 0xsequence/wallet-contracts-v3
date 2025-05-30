// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Attestation, LibAttestation } from "src/extensions/sessions/implicit/Attestation.sol";

import { ISignalsImplicitMode } from "src/extensions/sessions/implicit/ISignalsImplicitMode.sol";
import { Payload } from "src/modules/Payload.sol";

using LibAttestation for Attestation;

contract MockImplicitContract is ISignalsImplicitMode {

  function acceptImplicitRequest(
    address wallet,
    Attestation calldata attestation,
    Payload.Call calldata
  ) external pure returns (bytes32) {
    return attestation.generateImplicitRequestMagic(wallet);
  }

}

contract MockInvalidImplicitContract is ISignalsImplicitMode {

  function acceptImplicitRequest(address, Attestation calldata, Payload.Call calldata) external pure returns (bytes32) {
    return bytes32(0);
  }

}
