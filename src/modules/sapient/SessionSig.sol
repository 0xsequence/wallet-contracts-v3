// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { LibBytesPointer } from "../../utils/LibBytesPointer.sol";
import { LibOptim } from "../../utils/LibOptim.sol";

import { Attestation, LibAttestation } from "../Attestation.sol";

import { Payload } from "../Payload.sol";
import { LibPermission, Permission } from "../Permission.sol";
import { SessionManagerSignature, SessionPermissions } from "../interfaces/ISessionManager.sol";

contract SessionSig {

  using LibBytesPointer for bytes;
  using LibOptim for bytes;
  using LibAttestation for Attestation;
  using LibPermission for Permission;

  uint256 internal constant FLAG_PERMISSIONS = 0;
  uint256 internal constant FLAG_NODE = 1;
  uint256 internal constant FLAG_BRANCH = 2;

  error InvalidPayloadSigner(address expectedSigner, address recoveredSigner);
  error InvalidNodeType(uint256 flag);

  function recoverSignature(
    Payload.Decoded calldata payload,
    bytes calldata encodedSignature
  ) public pure returns (SessionManagerSignature memory signature) {
    uint256 pointer = 0;
    bytes32 r;
    bytes32 s;
    uint8 v;

    // Read session signature (r,sv)
    (r, s, v, pointer) = encodedSignature.readRSVCompact(pointer);

    // Recover the session signer from the session signature
    bytes32 payloadHash = keccak256(abi.encode(payload));
    address recoveredPayloadSigner = ecrecover(payloadHash, v, r, s);

    // Read attestation components
    (signature.attestation.approvedSigner, pointer) = encodedSignature.readAddress(pointer);
    if (recoveredPayloadSigner != signature.attestation.approvedSigner) {
      // Payload must be signed by the approved signer
      revert InvalidPayloadSigner(signature.attestation.approvedSigner, recoveredPayloadSigner);
    }
    (signature.attestation.identityType, pointer) = encodedSignature.readBytes4(pointer);
    (signature.attestation.issuerHash, pointer) = encodedSignature.readBytes32(pointer);
    (signature.attestation.audienceHash, pointer) = encodedSignature.readBytes32(pointer);
    uint256 dataSize;
    (dataSize, pointer) = encodedSignature.readUint24(pointer);
    signature.attestation.authData = encodedSignature[pointer:pointer + dataSize];
    pointer += dataSize;
    (dataSize, pointer) = encodedSignature.readUint24(pointer);
    signature.attestation.applicationData = encodedSignature[pointer:pointer + dataSize];
    pointer += dataSize;

    // Read global signature (r,sv)
    (r, s, v, pointer) = encodedSignature.readRSVCompact(pointer);

    // Recover the global signer from the global signature
    bytes32 attestationHash = signature.attestation.toHash();
    signature.globalSigner = ecrecover(attestationHash, v, r, s);

    // Read encoded permissions size and data
    (dataSize, pointer) = encodedSignature.readUint24(pointer);
    bytes calldata encodedPermissions = encodedSignature[pointer:pointer + dataSize];
    pointer += dataSize;

    // Recover permissions tree and find signer's permissions
    (signature.permissionsRoot, signature.sessionPermissions) =
      recoverPermissionsTree(encodedPermissions, recoveredPayloadSigner);

    // Read blacklist length and addresses
    (dataSize, pointer) = encodedSignature.readUint24(pointer);
    signature.implicitBlacklist = new address[](dataSize);
    for (uint256 i = 0; i < dataSize; i++) {
      (signature.implicitBlacklist[i], pointer) = encodedSignature.readAddress(pointer);
    }

    // Read permission indices length and values
    (dataSize, pointer) = encodedSignature.readUint24(pointer);
    signature.permissionIdxPerCall = new uint8[](dataSize);
    for (uint256 i = 0; i < dataSize; i++) {
      (signature.permissionIdxPerCall[i], pointer) = encodedSignature.readUint8(pointer);
    }

    // Construct and return the signature struct
    signature.isImplicit = signature.sessionPermissions.signer == address(0);
    return signature;
  }

  function recoverPermissionsTree(
    bytes calldata encodedSessions,
    address sessionSigner
  ) public pure returns (bytes32 root, SessionPermissions memory permissions) {
    uint256 rindex;

    while (rindex < encodedSessions.length) {
      // First byte is the flag (top 4 bits) and additional data (bottom 4 bits)
      (uint256 firstByte, uint256 tmpIndex) = encodedSessions.readUint8(rindex);
      rindex = tmpIndex;

      // The top 4 bits are the flag
      uint256 flag = (firstByte & 0xf0) >> 4;

      // Permissions configuration (0x00)
      if (flag == FLAG_PERMISSIONS) {
        // Read signer
        address signer;
        (signer, rindex) = encodedSessions.readAddress(rindex);

        // Read value limit
        uint256 valueLimit;
        (valueLimit, rindex) = encodedSessions.readUint256(rindex);

        // Read deadline
        uint256 deadline;
        (deadline, rindex) = encodedSessions.readUint256(rindex);

        // Read permissions array size
        uint256 permSize;
        (permSize, rindex) = encodedSessions.readUint24(rindex);

        // Read permissions array
        bytes calldata permData = encodedSessions[rindex:rindex + permSize];
        rindex += permSize;
        Permission[] memory perms;
        (perms, rindex) = _decodePermissions(permData, rindex);

        SessionPermissions memory nodePermissions =
          SessionPermissions({ signer: signer, valueLimit: valueLimit, deadline: deadline, permissions: perms });

        // Compute node hash
        bytes32 node = _leafForPermissions(nodePermissions);
        root = root != bytes32(0) ? LibOptim.fkeccak256(root, node) : node;

        if (nodePermissions.signer == sessionSigner) {
          permissions = nodePermissions;
        }
        continue;
      }

      // Node (0x01)
      if (flag == FLAG_NODE) {
        // Read pre-hashed node
        bytes32 node;
        (node, rindex) = encodedSessions.readBytes32(rindex);
        root = root != bytes32(0) ? LibOptim.fkeccak256(root, node) : node;
        continue;
      }

      // Branch (0x02)
      if (flag == FLAG_BRANCH) {
        // Read branch size
        uint256 size;
        (size, rindex) = encodedSessions.readUint24(rindex);

        // Process branch
        uint256 nrindex = rindex + size;
        (bytes32 branchRoot, SessionPermissions memory branchPermissions) =
          recoverPermissionsTree(encodedSessions[rindex:nrindex], sessionSigner);

        if (branchPermissions.signer == sessionSigner) {
          permissions = branchPermissions;
        }

        root = root != bytes32(0) ? LibOptim.fkeccak256(root, branchRoot) : branchRoot;
        rindex = nrindex;
        continue;
      }

      revert InvalidNodeType(flag);
    }

    return (root, permissions);
  }

  function _leafForPermissions(
    SessionPermissions memory permissions
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        "Session permissions leaf:\n",
        permissions.signer,
        permissions.valueLimit,
        permissions.deadline,
        permissions.permissions
      )
    );
  }

  function _decodePermissions(
    bytes calldata encoded,
    uint256 pointer
  ) internal pure returns (Permission[] memory permissions, uint256 newPointer) {
    uint256 length;
    (length, newPointer) = encoded.readUint24(pointer);
    permissions = new Permission[](length);
    for (uint256 i = 0; i < length; i++) {
      (permissions[i], pointer) = LibPermission.readPermission(encoded, pointer);
    }
    return (permissions, pointer);
  }

  function _encodePermissions(
    Permission[] calldata permissions
  ) internal pure returns (bytes memory packed) {
    bytes memory encoded = abi.encodePacked(uint24(permissions.length));
    for (uint256 i = 0; i < permissions.length; i++) {
      encoded = abi.encodePacked(encoded, permissions[i].toPacked());
    }
    return encoded;
  }

}
