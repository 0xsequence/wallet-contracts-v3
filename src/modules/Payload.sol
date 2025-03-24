// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { LibBytesPointer } from "../utils/LibBytesPointer.sol";

using LibBytesPointer for bytes;

library Payload {

  bytes32 private constant EIP712_DOMAIN_TYPEHASH =
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

  bytes32 private constant EIP712_DOMAIN_NAME_SEQUENCE = keccak256("Sequence Wallet");
  bytes32 private constant EIP712_DOMAIN_VERSION_SEQUENCE = keccak256("3");

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

  bytes32 private constant CALL_TYPEHASH = keccak256(
    "Call(address to,uint256 value,bytes data,uint256 gasLimit,bool delegateCall,bool onlyFallback,uint256 behaviorOnError)"
  );

  bytes32 private constant CALLS_TYPEHASH = keccak256(
    "Calls(Call[] calls,uint256 space,uint256 nonce,address[] wallets)Call(address to,uint256 value,bytes data,uint256 gasLimit,bool delegateCall,bool onlyFallback,uint256 behaviorOnError)"
  );

  bytes32 private constant MESSAGE_TYPEHASH = keccak256("Message(bytes message,address[] wallets)");

  bytes32 private constant CONFIG_UPDATE_TYPEHASH = keccak256("ConfigUpdate(bytes32 imageHash,address[] wallets)");

  uint8 public constant KIND_TRANSACTIONS = 0x00;
  uint8 public constant KIND_MESSAGE = 0x01;
  uint8 public constant KIND_CONFIG_UPDATE = 0x02;
  uint8 public constant KIND_DIGEST = 0x03;

  uint8 public constant BEHAVIOR_IGNORE_ERROR = 0x00;
  uint8 public constant BEHAVIOR_REVERT_ON_ERROR = 0x01;
  uint8 public constant BEHAVIOR_ABORT_ON_ERROR = 0x02;

  struct Call {
    address to;
    uint256 value;
    bytes data;
    uint256 gasLimit;
    bool delegateCall;
    bool onlyFallback;
    uint256 behaviorOnError;
  }

  struct Decoded {
    uint8 kind;
    bool noChainId;
    // Transaction kind
    Call[] calls;
    uint256 space;
    uint256 nonce;
    // Message kind
    // TODO: Maybe native 721 ?
    bytes message;
    // Config update kind
    bytes32 imageHash;
    // Digest kind for 1271
    bytes32 digest;
    // Parent wallets
    address[] parentWallets;
  }

  function fromMessage(
    bytes memory message
  ) internal pure returns (Decoded memory _decoded) {
    _decoded.kind = KIND_MESSAGE;
    _decoded.message = message;
  }

  function fromConfigUpdate(
    bytes32 imageHash
  ) internal pure returns (Decoded memory _decoded) {
    _decoded.kind = KIND_CONFIG_UPDATE;
    _decoded.imageHash = imageHash;
  }

  function fromDigest(
    bytes32 digest
  ) internal pure returns (Decoded memory _decoded) {
    _decoded.kind = KIND_DIGEST;
    _decoded.digest = digest;
  }

  function fromPackedCalls(
    bytes calldata packed
  ) internal view returns (Decoded memory _decoded) {
    _decoded.kind = KIND_TRANSACTIONS;

    // Read the global flag
    (uint256 globalFlag, uint256 pointer) = packed.readFirstUint8();

    // First bit determines if space is zero or not
    if (globalFlag & 0x01 == 0x01) {
      _decoded.space = 0;
    } else {
      (_decoded.space, pointer) = packed.readUint160(pointer);
    }

    // Next 3 bits determine the size of the nonce
    uint256 nonceSize = (globalFlag >> 1) & 0x07;

    if (nonceSize > 0) {
      // Read the nonce
      (_decoded.nonce, pointer) = packed.readUintX(pointer, nonceSize);
    }

    uint256 numCalls;

    // Bit 5 determines if the batch contains a single call
    if (globalFlag & 0x10 == 0x10) {
      numCalls = 1;
    } else {
      // Bit 6 determines if the number of calls uses 1 byte or 2 bytes
      if (globalFlag & 0x20 == 0x20) {
        (numCalls, pointer) = packed.readUint16(pointer);
      } else {
        (numCalls, pointer) = packed.readUint8(pointer);
      }
    }

    // Read the calls
    _decoded.calls = new Call[](numCalls);

    for (uint256 i = 0; i < numCalls; i++) {
      uint8 flags;
      (flags, pointer) = packed.readUint8(pointer);

      // First bit determines if this is a call to self
      // or a call to another address
      if (flags & 0x01 == 0x01) {
        // Call to self
        _decoded.calls[i].to = address(this);
      } else {
        // Call to another address
        (_decoded.calls[i].to, pointer) = packed.readAddress(pointer);
      }

      // Second bit determines if the call has value or not
      if (flags & 0x02 == 0x02) {
        (_decoded.calls[i].value, pointer) = packed.readUint256(pointer);
      }

      // Third bit determines if the call has data or not
      if (flags & 0x04 == 0x04) {
        // 3 bytes determine the size of the calldata
        uint256 calldataSize;
        (calldataSize, pointer) = packed.readUint24(pointer);
        _decoded.calls[i].data = packed[pointer:pointer + calldataSize];
        pointer += calldataSize;
      }

      // Fourth bit determines if the call has a gas limit or not
      if (flags & 0x08 == 0x08) {
        (_decoded.calls[i].gasLimit, pointer) = packed.readUint256(pointer);
      }

      // Fifth bit determines if the call is a delegate call or not
      _decoded.calls[i].delegateCall = (flags & 0x10 == 0x10);

      // Sixth bit determines if the call is fallback only
      _decoded.calls[i].onlyFallback = (flags & 0x20 == 0x20);

      // Last 2 bits are directly mapped to the behavior on error
      _decoded.calls[i].behaviorOnError = (flags & 0xC0) >> 6;
    }
  }

  function hashCall(
    Call memory c
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        CALL_TYPEHASH, c.to, c.value, keccak256(c.data), c.gasLimit, c.delegateCall, c.onlyFallback, c.behaviorOnError
      )
    );
  }

  function hashCalls(
    Call[] memory calls
  ) internal pure returns (bytes32) {
    // In EIP712, an array is often hashed as the keccak256 of the concatenated
    // hashes of each item. So we hash each Call, pack them, and hash again.
    bytes memory encoded;
    for (uint256 i = 0; i < calls.length; i++) {
      bytes32 callHash = hashCall(calls[i]);
      encoded = abi.encodePacked(encoded, callHash);
    }
    return keccak256(encoded);
  }

  function _hashParentWallets(
    address[] memory wallets
  ) internal pure returns (bytes32) {
    // Similar approach for an address array: treat each address as 32 bytes
    // (left or right padded), then keccak the concatenation.
    bytes memory encoded;
    for (uint256 i = 0; i < wallets.length; i++) {
      // We can encode each address as a full 32 bytes
      encoded = abi.encode(encoded, wallets[i]);
    }
    return keccak256(encoded);
  }

  function toEIP712(
    Decoded memory _decoded
  ) internal pure returns (bytes32) {
    bytes32 walletsHash = _hashParentWallets(_decoded.parentWallets);

    if (_decoded.kind == KIND_TRANSACTIONS) {
      bytes32 callsHash = hashCalls(_decoded.calls);
      // The top-level struct for Calls might be something like:
      // Calls(Call[] calls,uint256 space,uint256 nonce,address[] wallets)
      return keccak256(abi.encode(CALLS_TYPEHASH, callsHash, _decoded.space, _decoded.nonce, walletsHash));
    } else if (_decoded.kind == KIND_MESSAGE) {
      // If you define your top-level as: Message(bytes message,address[] wallets)
      return keccak256(abi.encode(MESSAGE_TYPEHASH, keccak256(_decoded.message), walletsHash));
    } else if (_decoded.kind == KIND_CONFIG_UPDATE) {
      // Top-level: ConfigUpdate(bytes32 imageHash,address[] wallets)
      return keccak256(abi.encode(CONFIG_UPDATE_TYPEHASH, _decoded.imageHash, walletsHash));
    } else if (_decoded.kind == KIND_DIGEST) {
      // Top-level: Message(bytes message,address[] wallets)
      return keccak256(abi.encode(MESSAGE_TYPEHASH, _decoded.digest, walletsHash));
    } else {
      // Unknown kind
      revert("Unsupported kind");
    }
  }

  function hash(
    Decoded memory _decoded
  ) internal view returns (bytes32) {
    bytes32 domain = domainSeparator(_decoded.noChainId, address(this));
    bytes32 structHash = toEIP712(_decoded);
    return keccak256(abi.encodePacked("\x19\x01", domain, structHash));
  }

  function hashFor(Decoded memory _decoded, address _wallet) internal view returns (bytes32) {
    bytes32 domain = domainSeparator(_decoded.noChainId, _wallet);
    bytes32 structHash = toEIP712(_decoded);
    return keccak256(abi.encodePacked("\x19\x01", domain, structHash));
  }

}
