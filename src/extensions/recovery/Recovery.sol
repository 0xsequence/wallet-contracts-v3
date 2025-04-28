// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../../modules/Payload.sol";
import { IERC1271, IERC1271_MAGIC_VALUE } from "../../modules/interfaces/IERC1271.sol";
import { ISapientCompact } from "../../modules/interfaces/ISapient.sol";
import { LibBytesPointer } from "../../utils/LibBytesPointer.sol";
import { LibOptim } from "../../utils/LibOptim.sol";

using LibBytesPointer for bytes;

contract Recovery is ISapientCompact {

  bytes32 private constant EIP712_DOMAIN_TYPEHASH =
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

  bytes32 private constant EIP712_DOMAIN_NAME_SEQUENCE = keccak256("Sequence Wallet - Recovery Mode");
  bytes32 private constant EIP712_DOMAIN_VERSION_SEQUENCE = keccak256("1");

  // Make them similar to the flags in BaseSig.sol
  uint256 internal constant FLAG_RECOVERY_LEAF = 1;
  uint256 internal constant FLAG_NODE = 3;
  uint256 internal constant FLAG_BRANCH = 4;

  event NewQueuedPayload(address _wallet, address _signer, bytes32 _payloadHash, uint256 _timestamp);

  error InvalidSignature(address _wallet, address _signer, Payload.Decoded _payload, bytes _signature);
  error AlreadyQueued(address _wallet, address _signer, bytes32 _payloadHash);
  error QueueNotReady(address _wallet, bytes32 _payloadHash);
  error InvalidSignatureFlag(uint256 _flag);

  function domainSeparator(bool _noChainId, address _wallet) internal view returns (bytes32 _domainSeparator) {
    return keccak256(
      abi.encode(
        EIP712_DOMAIN_TYPEHASH,
        EIP712_DOMAIN_NAME_SEQUENCE,
        EIP712_DOMAIN_VERSION_SEQUENCE,
        _noChainId ? uint256(0) : uint256(block.chainid),
        _wallet
      )
    );
  }

  // wallet -> signer -> payloadHash -> timestamp
  mapping(address => mapping(address => mapping(bytes32 => uint256))) public timestampForQueuedPayload;

  // (write once helper)
  // wallet -> signer -> payloadHash[]
  mapping(address => mapping(address => bytes32[])) public queuedPayloadHashes;

  function totalQueuedPayloads(address _wallet, address _signer) public view returns (uint256) {
    return queuedPayloadHashes[_wallet][_signer].length;
  }

  function _leafForRecoveryLeaf(
    address _signer,
    uint256 _requiredDeltaTime,
    uint256 _minTimestamp
  ) internal pure returns (bytes32) {
    return keccak256(abi.encodePacked("Sequence recovery leaf:\n", _signer, _requiredDeltaTime, _minTimestamp));
  }

  function _recoverBranch(
    address _wallet,
    bytes32 _payloadHash,
    bytes calldata _signature
  ) internal view returns (bool verified, bytes32 root) {
    uint256 rindex;

    while (rindex < _signature.length) {
      // The first byte is the flag, it determines if we are reading
      uint256 flag;
      (flag, rindex) = _signature.readUint8(rindex);

      if (flag == FLAG_RECOVERY_LEAF) {
        // Read the signer and requiredDeltaTime
        address signer;
        uint256 requiredDeltaTime;
        uint256 minTimestamp;

        (signer, rindex) = _signature.readAddress(rindex);
        (requiredDeltaTime, rindex) = _signature.readUint24(rindex);
        (minTimestamp, rindex) = _signature.readUint64(rindex);

        // Check if we have a queued payload for this signer
        uint256 queuedAt = timestampForQueuedPayload[_wallet][signer][_payloadHash];
        if (queuedAt != 0 && queuedAt >= minTimestamp && block.timestamp - queuedAt >= requiredDeltaTime) {
          verified = true;
        }

        bytes32 node = _leafForRecoveryLeaf(signer, requiredDeltaTime, minTimestamp);
        root = root != bytes32(0) ? LibOptim.fkeccak256(root, node) : node;
        continue;
      }

      if (flag == FLAG_NODE) {
        // Read node hash
        bytes32 node;
        (node, rindex) = _signature.readBytes32(rindex);
        root = root != bytes32(0) ? LibOptim.fkeccak256(root, node) : node;
        continue;
      }

      if (flag == FLAG_BRANCH) {
        // Read size
        uint256 size;
        (size, rindex) = _signature.readUint24(rindex);

        // Enter a branch of the signature merkle tree
        uint256 nrindex = rindex + size;

        (bool nverified, bytes32 nroot) = _recoverBranch(_wallet, _payloadHash, _signature[rindex:nrindex]);
        rindex = nrindex;

        verified = verified || nverified;
        root = LibOptim.fkeccak256(root, nroot);
        continue;
      }

      revert InvalidSignatureFlag(flag);
    }

    return (verified, root);
  }

  function recoveryPayloadHash(address _wallet, Payload.Decoded calldata _payload) public view returns (bytes32) {
    bytes32 domain = domainSeparator(_payload.noChainId, _wallet);
    bytes32 structHash = Payload.toEIP712(_payload);
    return keccak256(abi.encodePacked("\x19\x01", domain, structHash));
  }

  function recoverSapientSignatureCompact(
    bytes32 _payloadHash,
    bytes calldata _signature
  ) external view returns (bytes32) {
    (bool verified, bytes32 root) = _recoverBranch(msg.sender, _payloadHash, _signature);
    if (!verified) {
      revert QueueNotReady(msg.sender, _payloadHash);
    }

    return root;
  }

  function queuePayload(
    address _wallet,
    address _signer,
    Payload.Decoded calldata _payload,
    bytes calldata _signature
  ) external {
    if (!isValidSignature(_wallet, _signer, _payload, _signature)) {
      revert InvalidSignature(_wallet, _signer, _payload, _signature);
    }

    bytes32 payloadHash = Payload.hashFor(_payload, _wallet);
    if (timestampForQueuedPayload[_wallet][_signer][payloadHash] != 0) {
      revert AlreadyQueued(_wallet, _signer, payloadHash);
    }

    timestampForQueuedPayload[_wallet][_signer][payloadHash] = block.timestamp;
    queuedPayloadHashes[_wallet][_signer].push(payloadHash);

    emit NewQueuedPayload(_wallet, _signer, payloadHash, block.timestamp);
  }

  function isValidSignature(
    address _wallet,
    address _signer,
    Payload.Decoded calldata _payload,
    bytes calldata _signature
  ) internal view returns (bool) {
    bytes32 rPayloadHash = recoveryPayloadHash(_wallet, _payload);

    if (_signer.code.length != 0) {
      return IERC1271(_signer).isValidSignature(rPayloadHash, _signature) == IERC1271_MAGIC_VALUE;
    }

    (bytes32 r, bytes32 yParityAndS) = abi.decode(_signature, (bytes32, bytes32));
    uint256 yParity = uint256(yParityAndS >> 255);
    bytes32 s = bytes32(uint256(yParityAndS) & 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
    uint8 v = uint8(yParity) + 27;

    address addr = ecrecover(rPayloadHash, v, r, s);
    return addr == _signer;
  }

}
