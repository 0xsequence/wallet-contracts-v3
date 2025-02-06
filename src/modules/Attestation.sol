// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { LibBytesPointer } from "../utils/LibBytesPointer.sol";
import { LibOptim } from "../utils/LibOptim.sol";
import { ACCEPT_IMPLICIT_REQUEST_MAGIC_PREFIX } from "./interfaces/ISignalsImplicitMode.sol";

using LibBytesPointer for bytes;
using LibOptim for bytes;

struct Attestation {
  address approvedSigner;
  bytes4 identityType;
  bytes32 issuerHash;
  bytes32 audienceHash;
  bytes authData;
  bytes applicationData;
}

library LibAttestation {

  function toHash(
    Attestation memory attestation
  ) internal pure returns (bytes32) { }

  function fromPacked(
    bytes calldata encoded,
    uint256 pointer
  ) internal pure returns (Attestation memory attestation, uint256 newPointer) {
    (attestation.approvedSigner, pointer) = encoded.readAddress(pointer);
    (attestation.identityType, pointer) = encoded.readBytes4(pointer);
    (attestation.issuerHash, pointer) = encoded.readBytes32(pointer);
    (attestation.audienceHash, pointer) = encoded.readBytes32(pointer);
    uint256 dataSize;
    (dataSize, pointer) = encoded.readUint24(pointer);
    attestation.authData = encoded[pointer:pointer + dataSize];
    pointer += dataSize;
    (dataSize, pointer) = encoded.readUint24(pointer);
    attestation.applicationData = encoded[pointer:pointer + dataSize];
    pointer += dataSize;
    return (attestation, pointer);
  }

  function toPacked(
    Attestation memory attestation
  ) internal pure returns (bytes memory) {
    return abi.encodePacked(
      attestation.approvedSigner,
      attestation.identityType,
      attestation.issuerHash,
      attestation.audienceHash,
      uint24(attestation.authData.length),
      attestation.authData,
      uint24(attestation.applicationData.length),
      attestation.applicationData
    );
  }

  function generateImplicitRequestMagic(Attestation memory attestation, address wallet) internal pure returns (bytes32) {
    return keccak256(
      abi.encodePacked(ACCEPT_IMPLICIT_REQUEST_MAGIC_PREFIX, wallet, attestation.audienceHash, attestation.issuerHash)
    );
  }

}
