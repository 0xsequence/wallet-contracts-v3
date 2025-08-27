// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { AdvTest } from "../../utils/TestUtils.sol";
import { SequenceConfigLib } from "../utils/SequenceConfigLib.sol";
import { Payload } from "src/modules/Payload.sol";
import { BaseSig } from "src/modules/auth/BaseSig.sol";

contract ExternalBaseSig {

  function recoverBranch(
    Payload.Decoded memory _payload,
    bytes32 _opHash,
    bytes calldata _signature
  ) external view returns (uint256, bytes32) {
    return BaseSig.recoverBranch(_payload, _opHash, _signature);
  }

}

contract AddressToBooleanMap {

  mapping(address => bool) private _values;

  function set(address _addr, bool _val) external {
    _values[_addr] = _val;
  }

  function get(
    address _addr
  ) external view returns (bool) {
    return _values[_addr];
  }

}

contract BytesToBooleanMap {

  mapping(bytes => bool) private _values;

  function set(bytes calldata _bytes, bool _val) external {
    _values[_bytes] = _val;
  }

  function get(
    bytes calldata _bytes
  ) external view returns (bool) {
    return _values[_bytes];
  }

}

contract BaseSigTest is AdvTest {

  function test_recoverSingleAddressNoWeight(
    Payload.Decoded memory _payload,
    bytes32 _opHash,
    address _signer,
    uint8 _weight,
    bool _trim
  ) external {
    ExternalBaseSig externalBaseSig = new ExternalBaseSig();
    boundToLegalPayload(_payload);

    SequenceConfigLib.EncodedNode memory node = SequenceConfigLib.addressLeaf(_signer, _weight);
    bytes32 nodeHash = SequenceConfigLib.hashEncodedNode(node);

    // Encode empty signature
    (, bytes memory signature) =
      SequenceConfigLib.encodeSignature(node, new SequenceConfigLib.SignatureForNode[](0), _trim);

    (uint256 weight, bytes32 root) = externalBaseSig.recoverBranch(
      _payload, // In this case the payload and the hash do not neccesarily need to match
      _opHash,
      signature
    );
    assertEq(weight, 0);
    assertEq(root, nodeHash);
  }

  struct AddressWeight {
    address addr;
    uint8 weight;
  }

  function test_recoverMultipleAddressesNoWeight_unbalancedRight(
    Payload.Decoded memory _payload,
    bytes32 _opHash,
    AddressWeight[] memory _addressWeights,
    bool _trim
  ) external {
    vm.assume(_addressWeights.length > 0 && _addressWeights.length <= 32);

    ExternalBaseSig externalBaseSig = new ExternalBaseSig();
    boundToLegalPayload(_payload);

    SequenceConfigLib.EncodedNode memory encoded;
    for (uint256 i = 0; i < _addressWeights.length; i++) {
      if (i == 0) {
        encoded = SequenceConfigLib.addressLeaf(_addressWeights[i].addr, _addressWeights[i].weight);
      } else {
        encoded = SequenceConfigLib.node(
          encoded, SequenceConfigLib.addressLeaf(_addressWeights[i].addr, _addressWeights[i].weight)
        );
      }
    }

    bytes32 nodeHash = SequenceConfigLib.hashEncodedNode(encoded);

    // Encode empty signature
    (, bytes memory signature) =
      SequenceConfigLib.encodeSignature(encoded, new SequenceConfigLib.SignatureForNode[](0), _trim);

    (uint256 weight, bytes32 root) = externalBaseSig.recoverBranch(
      _payload, // In this case the payload and the hash do not neccesarily need to match
      _opHash,
      signature
    );
    assertEq(weight, 0);
    assertEq(root, nodeHash);
  }

  function test_recoverMultipleAddressesNoWeight_unbalancedLeft(
    Payload.Decoded memory _payload,
    bytes32 _opHash,
    AddressWeight[] memory _addressWeights,
    bool _trim
  ) external {
    vm.assume(_addressWeights.length > 0 && _addressWeights.length <= 32);

    ExternalBaseSig externalBaseSig = new ExternalBaseSig();
    boundToLegalPayload(_payload);

    SequenceConfigLib.EncodedNode memory encoded;
    for (uint256 i = 0; i < _addressWeights.length; i++) {
      if (i == 0) {
        encoded = SequenceConfigLib.addressLeaf(_addressWeights[i].addr, _addressWeights[i].weight);
      } else {
        encoded = SequenceConfigLib.node(
          SequenceConfigLib.addressLeaf(_addressWeights[i].addr, _addressWeights[i].weight), encoded
        );
      }
    }

    bytes32 nodeHash = SequenceConfigLib.hashEncodedNode(encoded);

    // Encode empty signature
    (, bytes memory signature) =
      SequenceConfigLib.encodeSignature(encoded, new SequenceConfigLib.SignatureForNode[](0), _trim);

    (uint256 weight, bytes32 root) = externalBaseSig.recoverBranch(
      _payload, // In this case the payload and the hash do not neccesarily need to match
      _opHash,
      signature
    );
    assertEq(weight, 0);
    assertEq(root, nodeHash);
  }

  function test_recoverMultipleAddressesNoWeight_balanced(
    Payload.Decoded memory _payload,
    bytes32 _opHash,
    AddressWeight[] memory _addressWeights,
    bool _trim
  ) external {
    vm.assume(_addressWeights.length > 0 && _addressWeights.length <= 32);

    ExternalBaseSig externalBaseSig = new ExternalBaseSig();
    boundToLegalPayload(_payload);

    // Build a balanced binary tree
    SequenceConfigLib.EncodedNode[] memory nodes = new SequenceConfigLib.EncodedNode[](_addressWeights.length);

    // Create leaf nodes for all addresses
    for (uint256 i = 0; i < _addressWeights.length; i++) {
      nodes[i] = SequenceConfigLib.addressLeaf(_addressWeights[i].addr, _addressWeights[i].weight);
    }

    // Build balanced tree bottom-up
    uint256 currentLength = _addressWeights.length;
    while (currentLength > 1) {
      uint256 newLength = (currentLength + 1) / 2;
      for (uint256 i = 0; i < newLength; i++) {
        if (i * 2 + 1 < currentLength) {
          // Pair exists, create internal node
          nodes[i] = SequenceConfigLib.node(nodes[i * 2], nodes[i * 2 + 1]);
        } else {
          // Odd node out, move it up
          nodes[i] = nodes[i * 2];
        }
      }
      currentLength = newLength;
    }

    SequenceConfigLib.EncodedNode memory encoded = nodes[0];
    bytes32 nodeHash = SequenceConfigLib.hashEncodedNode(encoded);

    // Encode empty signature
    (, bytes memory signature) =
      SequenceConfigLib.encodeSignature(encoded, new SequenceConfigLib.SignatureForNode[](0), _trim);

    (uint256 weight, bytes32 root) = externalBaseSig.recoverBranch(
      _payload, // In this case the payload and the hash do not neccesarily need to match
      _opHash,
      signature
    );
    assertEq(weight, 0);
    assertEq(root, nodeHash);
  }

  function test_recoverSingleECDSASignature(
    Payload.Decoded memory _payload,
    bytes32 _opHash,
    uint256 _pk,
    uint8 _weight,
    bool _trim
  ) external {
    ExternalBaseSig externalBaseSig = new ExternalBaseSig();
    boundToLegalPayload(_payload);
    _pk = boundPk(_pk);
    address signer = vm.addr(_pk);

    SequenceConfigLib.EncodedNode memory node = SequenceConfigLib.addressLeaf(signer, _weight);
    bytes32 nodeHash = SequenceConfigLib.hashEncodedNode(node);

    // Signt he payload hash
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(_pk, _opHash);
    bytes memory sig = abi.encodePacked(r, s, v);

    SequenceConfigLib.SignatureForNode[] memory signaturesForNode = new SequenceConfigLib.SignatureForNode[](1);
    signaturesForNode[0] = SequenceConfigLib.SignatureForNode({ node: node, signature: sig });

    // Encode empty signature
    (, bytes memory signature) = SequenceConfigLib.encodeSignature(node, signaturesForNode, _trim);

    (uint256 weight, bytes32 root) = externalBaseSig.recoverBranch(
      _payload, // In this case the payload and the hash do not neccesarily need to match
      _opHash,
      signature
    );
    assertEq(weight, _weight);
    assertEq(root, nodeHash);
  }

  struct SignerWeightMaySign {
    uint256 pk;
    uint8 weight;
    bool signs;
  }

  function test_recoverMixedECDSASignaturesAndAddress(
    Payload.Decoded memory _payload,
    bytes32 _opHash,
    SignerWeightMaySign[] memory _signers,
    bool _trim
  ) external {
    vm.assume(_signers.length > 0 && _signers.length <= 64);

    ExternalBaseSig externalBaseSig = new ExternalBaseSig();
    address[] memory addresses = new address[](_signers.length);
    boundToLegalPayload(_payload);

    uint256 expectedRecoveredWeight = 0;
    uint256 signCount = 0;
    BytesToBooleanMap bytesToBooleanMap = new BytesToBooleanMap();
    for (uint256 i = 0; i < _signers.length; i++) {
      _signers[i].pk = boundPk(_signers[i].pk);
      addresses[i] = vm.addr(_signers[i].pk);
      if (_signers[i].signs) {
        signCount++;
        bytesToBooleanMap.set(abi.encodePacked(addresses[i], _signers[i].weight), true);
      }
    }

    for (uint256 i = 0; i < _signers.length; i++) {
      if (bytesToBooleanMap.get(abi.encodePacked(addresses[i], _signers[i].weight))) {
        expectedRecoveredWeight += _signers[i].weight;
      }
    }

    SequenceConfigLib.EncodedNode[] memory nodes = new SequenceConfigLib.EncodedNode[](_signers.length);
    for (uint256 i = 0; i < _signers.length; i++) {
      nodes[i] = SequenceConfigLib.addressLeaf(addresses[i], _signers[i].weight);
    }

    SequenceConfigLib.EncodedNode[] memory originalNodes = nodes;

    // Binary encode: build tree bottom-up
    while (nodes.length > 1) {
      uint256 nextLength = (nodes.length + 1) / 2;
      SequenceConfigLib.EncodedNode[] memory nextNodes = new SequenceConfigLib.EncodedNode[](nextLength);

      for (uint256 i = 0; i < nextLength; i++) {
        uint256 leftIdx = i * 2;
        uint256 rightIdx = leftIdx + 1;

        if (rightIdx < nodes.length) {
          nextNodes[i] = SequenceConfigLib.node(nodes[leftIdx], nodes[rightIdx]);
        } else {
          nextNodes[i] = nodes[leftIdx];
        }
      }

      nodes = nextNodes;
    }

    SequenceConfigLib.EncodedNode memory encoded = nodes[0];
    bytes32 nodeHash = SequenceConfigLib.hashEncodedNode(encoded);

    SequenceConfigLib.SignatureForNode[] memory signaturesForNode = new SequenceConfigLib.SignatureForNode[](signCount);
    uint256 signatureIndex = 0;
    for (uint256 i = 0; i < _signers.length; i++) {
      if (_signers[i].signs) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_signers[i].pk, _opHash);
        bytes memory sig = abi.encodePacked(r, s, v);
        signaturesForNode[signatureIndex] =
          SequenceConfigLib.SignatureForNode({ node: originalNodes[i], signature: sig });
        signatureIndex++;
      }
    }
    assertEq(signatureIndex, signCount);

    // Encode signatures
    (, bytes memory signature) = SequenceConfigLib.encodeSignature(encoded, signaturesForNode, _trim);

    (uint256 weight, bytes32 root) = externalBaseSig.recoverBranch(
      _payload, // In this case the payload and the hash do not neccesarily need to match
      _opHash,
      signature
    );
    assertEq(weight, expectedRecoveredWeight);
    assertEq(root, nodeHash);
  }

}
