// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Storage } from "./Storage.sol";
import { SelfAuth } from "./auth/SelfAuth.sol";

interface IERC1155Receiver {

  function onERC1155Received(address, address, uint256, uint256, bytes calldata) external returns (bytes4);
  function onERC1155BatchReceived(
    address,
    address,
    uint256[] calldata,
    uint256[] calldata,
    bytes calldata
  ) external returns (bytes4);

}

interface IERC777Receiver {

  function tokensReceived(
    address operator,
    address from,
    address to,
    uint256 amount,
    bytes calldata data,
    bytes calldata operatorData
  ) external;

}

interface IERC721Receiver {

  function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4);

}

interface IERC223Receiver {

  function tokenReceived(address, uint256, bytes calldata) external;

}

contract Hooks is SelfAuth, IERC1155Receiver, IERC777Receiver, IERC721Receiver, IERC223Receiver {

  //                       HOOKS_KEY = keccak256("org.arcadeum.module.hooks.hooks");
  bytes32 private constant HOOKS_KEY = bytes32(0xbe27a319efc8734e89e26ba4bc95f5c788584163b959f03fa04e2d7ab4b9a120);

  event DefinedHook(bytes4 signature, address implementation);

  error HookAlreadyExists(bytes4 signature);
  error HookDoesNotExist(bytes4 signature);

  function readHook(
    bytes4 signature
  ) external view returns (address) {
    return _readHook(signature);
  }

  function addHook(bytes4 signature, address implementation) external payable onlySelf {
    if (_readHook(signature) != address(0)) {
      revert HookAlreadyExists(signature);
    }
    _writeHook(signature, implementation);
  }

  function removeHook(
    bytes4 signature
  ) external payable onlySelf {
    if (_readHook(signature) == address(0)) {
      revert HookDoesNotExist(signature);
    }
    _writeHook(signature, address(0));
  }

  function _readHook(
    bytes4 signature
  ) private view returns (address) {
    return address(uint160(uint256(Storage.readBytes32Map(HOOKS_KEY, bytes32(signature)))));
  }

  function _writeHook(bytes4 signature, address implementation) private {
    Storage.writeBytes32Map(HOOKS_KEY, bytes32(signature), bytes32(uint256(uint160(implementation))));
    emit DefinedHook(signature, implementation);
  }

  function onERC1155Received(
    address,
    address,
    uint256,
    uint256,
    bytes calldata
  ) external _fallbackIfAvailable(IERC1155Receiver.onERC1155Received.selector) returns (bytes4) {
    return Hooks.onERC1155Received.selector;
  }

  function onERC1155BatchReceived(
    address,
    address,
    uint256[] calldata,
    uint256[] calldata,
    bytes calldata
  ) external _fallbackIfAvailable(IERC1155Receiver.onERC1155BatchReceived.selector) returns (bytes4) {
    return Hooks.onERC1155BatchReceived.selector;
  }

  function tokensReceived(
    address operator,
    address from,
    address to,
    uint256 amount,
    bytes calldata data,
    bytes calldata operatorData
  ) external _fallbackIfAvailable(IERC777Receiver.tokensReceived.selector) { }

  function onERC721Received(
    address,
    address,
    uint256,
    bytes calldata
  ) external _fallbackIfAvailable(IERC721Receiver.onERC721Received.selector) returns (bytes4) {
    return Hooks.onERC721Received.selector;
  }

  function tokenReceived(
    address,
    uint256,
    bytes calldata
  ) external _fallbackIfAvailable(IERC223Receiver.tokenReceived.selector) { }

  modifier _fallbackIfAvailable(
    bytes4 selector
  ) {
    address target = _readHook(selector);
    if (target == address(0)) {
      _;
    } else {
      (bool success, bytes memory result) = target.delegatecall(msg.data);
      assembly {
        if iszero(success) { revert(add(result, 32), mload(result)) }
        return(add(result, 32), mload(result))
      }
    }
  }

  fallback() external payable {
    if (msg.data.length >= 4) {
      address target = _readHook(bytes4(msg.data));
      if (target != address(0)) {
        (bool success, bytes memory result) = target.delegatecall(msg.data);
        assembly {
          if iszero(success) { revert(add(result, 32), mload(result)) }
          return(add(result, 32), mload(result))
        }
      }
    }
  }

  receive() external payable { }

}
