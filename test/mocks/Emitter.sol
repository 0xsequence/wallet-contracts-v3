// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Attestation, LibAttestation } from "src/extensions/sessions/implicit/Attestation.sol";

import { ISignalsImplicitMode } from "src/extensions/sessions/implicit/ISignalsImplicitMode.sol";
import { Payload } from "src/modules/interfaces/ISapient.sol";

contract Emitter is ISignalsImplicitMode {

  using LibAttestation for Attestation;

  event Implicit(address sender);
  event Explicit(address sender);

  error InvalidCall(string reason);

  function implicitEmit() external {
    emit Implicit(msg.sender);
  }

  function explicitEmit() external {
    emit Explicit(msg.sender);
  }

  function acceptImplicitRequest(
    address wallet,
    Attestation calldata attestation,
    Payload.Call calldata call
  ) external pure returns (bytes32) {
    if (call.data.length != 4 || bytes4(call.data[:4]) != this.implicitEmit.selector) {
      return bytes32(0);
    }
    // WARNING: This contract does not validate the redirect URL.
    // All implicit requests are accepted from any project.
    return attestation.generateImplicitRequestMagic(wallet);
  }

}
