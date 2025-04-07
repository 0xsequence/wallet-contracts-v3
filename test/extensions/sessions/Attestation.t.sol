// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Attestation, LibAttestation } from "src/extensions/sessions/implicit/Attestation.sol";

import { AdvTest } from "../../utils/TestUtils.sol";
import { Vm } from "forge-std/Test.sol";

contract AttestationImp {

  function fromPacked(
    bytes calldata encoded,
    uint256 pointer
  ) external pure returns (Attestation memory attestation, uint256 newPointer) {
    return LibAttestation.fromPacked(encoded, pointer);
  }

}

contract AttestationTest is AdvTest {

  AttestationImp public attestationImp;

  function setUp() public {
    attestationImp = new AttestationImp();
  }

  function test_unpackAttestation(
    Attestation memory attestation
  ) external view {
    bytes memory packed = LibAttestation.toPacked(attestation);
    (Attestation memory unpacked, uint256 pointer) = attestationImp.fromPacked(packed, 0);

    assertEq(pointer, packed.length, "pointer");

    assertEq(attestation.approvedSigner, unpacked.approvedSigner, "approvedSigner");
    assertEq(attestation.identityType, unpacked.identityType, "identityType");
    assertEq(attestation.issuerHash, unpacked.issuerHash, "issuerHash");
    assertEq(attestation.audienceHash, unpacked.audienceHash, "audienceHash");
    assertEq(attestation.applicationData, unpacked.applicationData, "applicationData");
    assertEq(attestation.authData.redirectUrl, unpacked.authData.redirectUrl, "authData.redirectUrl");
  }

}
