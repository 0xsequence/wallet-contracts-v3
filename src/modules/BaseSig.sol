// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { LibBytesPointer } from "../utils/LibBytesPointer.sol";
import { LibOptim } from "../utils/LibOptim.sol";
import { Payload } from "./Payload.sol";
import { IERC1271, IERC1271_MAGIC_VALUE } from "./interfaces/IERC1271.sol";
import { ISapient, ISapientCompact } from "./interfaces/ISapient.sol";

using LibBytesPointer for bytes;
using LibOptim for bytes;

contract BaseSig {
  uint256 internal constant FLAG_SIGNATURE_HASH = 0;
  uint256 internal constant FLAG_ADDRESS = 1;
  uint256 internal constant FLAG_SIGNATURE_ERC1271 = 2;
  uint256 internal constant FLAG_NODE = 3;
  uint256 internal constant FLAG_BRANCH = 4;
  uint256 internal constant FLAG_SUBDIGEST = 5;
  uint256 internal constant FLAG_NESTED = 6;
  uint256 internal constant FLAG_SIGNATURE_ETH_SIGN = 7;
  uint256 internal constant FLAG_SIGNATURE_EIP712 = 8;
  uint256 internal constant FLAG_SIGNATURE_SAPIENT = 9;
  uint256 internal constant FLAG_SIGNATURE_SAPIENT_COMPACT = 10;

  error InvalidNestedSignature(Payload.Decoded _payload, bytes32 _subdigest, address _signer, bytes _signature);

  function _leafForAddressAndWeight(
    address _addr,
    uint96 _weight
  ) internal pure returns (bytes32) {
    unchecked {
      return bytes32(uint256(_weight) << 160 | uint256(uint160(_addr)));
    }
  }

  function _leafForNested(
    bytes32 _node,
    uint256 _threshold,
    uint256 _weight
  ) internal pure returns (bytes32) {
    return keccak256(abi.encodePacked('Sequence nested config:\n', _node, _threshold, _weight));
  }

  function _leafForSapient(
    address _addr,
    uint96 _weight,
    bytes32 _imageHash
  ) internal pure returns (bytes32) {
    return keccak256(abi.encodePacked('Sequence sapient config:\n', _addr, _weight, _imageHash));
  }

  function _leafForHardcodedSubdigest(
    bytes32 _subdigest
  ) internal pure returns (bytes32) {
    return keccak256(abi.encodePacked('Sequence static digest:\n', _subdigest));
  }

  function recoverBranch(
    Payload.Decoded memory _payload,
    bytes32 _subdigest,
    bytes calldata _signature
  ) internal view returns (
    uint256 weight,
    bytes32 root
  ) {
    unchecked {
      uint256 rindex;

      // TODO: Organise flag checks by expected usage frequency

      // Iterate until the image is completed
      while (rindex < _signature.length) {
        // Read next item type
        uint256 flag;
        (flag, rindex) = _signature.readUint8(rindex);

        // Signature hash (0x00)
        if (flag == FLAG_SIGNATURE_HASH) {
          // Read weight
          uint8 addrWeight;
          (addrWeight, rindex) = _signature.readUint8(rindex);

          // Read r, s and v
          uint8 v;
          bytes32 r;
          bytes32 s;
          (r, rindex) = _signature.readBytes32(rindex);
          (s, rindex) = _signature.readBytes32(rindex);
          (v, rindex) = _signature.readUint8(rindex);

          // Recover signature
          address addr = ecrecover(_subdigest, v, r, s);

          // Add the weight and compute the merkle root
          weight += addrWeight;
          bytes32 node = _leafForAddressAndWeight(addr, addrWeight);
          root = root != bytes32(0) ? LibOptim.fkeccak256(root, node) : node;
          continue;
        }

        // Address (0x01) (without signature)
        if (flag == FLAG_ADDRESS) {
          uint8 addrWeight;
          address addr;
          (addrWeight, addr, rindex) = _signature.readUint8Address(rindex);

          // Compute the merkle root WITHOUT adding the weight
          bytes32 node = _leafForAddressAndWeight(addr, addrWeight);
          root = root != bytes32(0) ? LibOptim.fkeccak256(root, node) : node;
          continue;
        }

        // Signature ERC1271 (0x02)
        if (flag == FLAG_SIGNATURE_ERC1271) {
          // Read signer and weight
          uint8 addrWeight; address addr;
          (addrWeight, addr, rindex) = _signature.readUint8Address(rindex);

          // Read signature size
          uint256 size;
          (size, rindex) = _signature.readUint24(rindex);

          // Read dynamic size signature
          uint256 nrindex = rindex + size;

          // Call the ERC1271 contract to check if the signature is valid
          if (IERC1271(addr).isValidSignature(_subdigest, _signature[rindex:nrindex]) != IERC1271_MAGIC_VALUE) {
            revert InvalidNestedSignature(_payload, _subdigest, addr, _signature);
          }

          // Add the weight and compute the merkle root
          weight += addrWeight;
          bytes32 node = _leafForAddressAndWeight(addr, addrWeight);
          root = root != bytes32(0) ? LibOptim.fkeccak256(root, node) : node;
          continue;
        }

        // Node (0x03)
        if (flag == FLAG_NODE) {
          // Read node hash
          bytes32 node;
          (node, rindex) = _signature.readBytes32(rindex);
          root = root != bytes32(0) ? LibOptim.fkeccak256(root, node) : node;
          continue;
        }

        // Branch (0x04)
        if (flag == FLAG_BRANCH) {
          // Enter a branch of the signature merkle tree
          uint256 size;
          (size, rindex) = _signature.readUint24(rindex);
          uint256 nrindex = rindex + size;

          uint256 nweight; bytes32 node;
          (nweight, node) = recoverBranch(_payload, _subdigest, _signature[rindex:nrindex]);

          weight += nweight;
          root = LibOptim.fkeccak256(root, node);

          rindex = nrindex;
          continue;
        }

        // Nested (0x05)
        if (flag == FLAG_NESTED) {
          // Enter a branch of the signature merkle tree
          // but with an internal threshold and an external fixed weight
          uint256 externalWeight;
          (externalWeight, rindex) = _signature.readUint8(rindex);

          uint256 internalThreshold;
          (internalThreshold, rindex) = _signature.readUint16(rindex);

          uint256 size;
          (size, rindex) = _signature.readUint24(rindex);
          uint256 nrindex = rindex + size;

          uint256 internalWeight; bytes32 internalRoot;
          (internalWeight, internalRoot) = recoverBranch(_payload, _subdigest, _signature[rindex:nrindex]);
          rindex = nrindex;

          if (internalWeight >= internalThreshold) {
            weight += externalWeight;
          }

          bytes32 node = _leafForNested(internalRoot, internalThreshold, externalWeight);
          root = root != bytes32(0) ? LibOptim.fkeccak256(root, node) : node;

          continue;
        }

        // Subdigest (0x06)
        if (flag == FLAG_SUBDIGEST) {
          // A hardcoded always accepted digest
          // it pushes the weight to the maximum
          bytes32 hardcoded;
          (hardcoded, rindex) = _signature.readBytes32(rindex);
          if (hardcoded == _subdigest) {
            weight = type(uint256).max;
          }

          bytes32 node = _leafForHardcodedSubdigest(hardcoded);
          root = root != bytes32(0) ? LibOptim.fkeccak256(root, node) : node;
          continue;
        }

        // Signature ETH Sign (0x07)
        if (flag == FLAG_SIGNATURE_ETH_SIGN) {
          // Read weight
          uint8 addrWeight;
          (addrWeight, rindex) = _signature.readUint8(rindex);

          // Read r, s and v
          uint8 v;
          bytes32 r;
          bytes32 s;
          (r, rindex) = _signature.readBytes32(rindex);
          (s, rindex) = _signature.readBytes32(rindex);
          (v, rindex) = _signature.readUint8(rindex);

          // Recover signature
          address addr = ecrecover(
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _subdigest)),
            v,
            r,
            s
          );

          // Add the weight and compute the merkle root
          weight += addrWeight;
          bytes32 node = _leafForAddressAndWeight(addr, addrWeight);
          root = root != bytes32(0) ? LibOptim.fkeccak256(root, node) : node;
          continue;
        }

        // Signature EIP712 (0x08)
        if (flag == FLAG_SIGNATURE_EIP712) {
          // TODO: Implement EIP712 signature recovery
        }

        // Signature Sapient (0x09)
        if (flag == FLAG_SIGNATURE_SAPIENT) {
          // Read signer and weight
          uint8 addrWeight; address addr;
          (addrWeight, addr, rindex) = _signature.readUint8Address(rindex);

          // Read signature size
          uint256 size;
          (size, rindex) = _signature.readUint24(rindex);

          // Read dynamic size signature
          uint256 nrindex = rindex + size;

          // Call the ERC1271 contract to check if the signature is valid
          bytes32 sapientImageHash = ISapient(addr).isValidSapientSignature(_payload, _signature[rindex:nrindex]);

          // Add the weight and compute the merkle root
          weight += addrWeight;
          bytes32 node = _leafForSapient(addr, addrWeight, sapientImageHash);
          root = root != bytes32(0) ? LibOptim.fkeccak256(root, node) : node;
          continue;
        }

        // Signature Sapient Compact (0x0A)
        if (flag == FLAG_SIGNATURE_SAPIENT_COMPACT) {
          // Read signer and weight
          uint8 addrWeight; address addr;
          (addrWeight, addr, rindex) = _signature.readUint8Address(rindex);

          // Read signature size
          uint256 size;
          (size, rindex) = _signature.readUint24(rindex);

          // Read dynamic size signature
          uint256 nrindex = rindex + size;

          // Call the Sapient contract to check if the signature is valid
          bytes32 sapientImageHash = ISapientCompact(addr).isValidSapientSignatureCompact(_subdigest, _signature[rindex:nrindex]);

          // Add the weight and compute the merkle root
          weight += addrWeight;
          bytes32 node = _leafForSapient(addr, addrWeight, sapientImageHash);
          root = root != bytes32(0) ? LibOptim.fkeccak256(root, node) : node;
          continue;
        }
      }
    }
  }
}
