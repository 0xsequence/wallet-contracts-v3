// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Factory } from "./Factory.sol";
import { Wallet } from "./Wallet.sol";

/// @title ERC4337FactoryWrapper
/// @author Michael Standen
/// @notice A factory wrapper that supports ERC-4337 restrictions.
contract ERC4337FactoryWrapper {

  error NotSenderCreator();

  Factory public immutable factory;
  address public immutable senderCreator;

  /// @notice Constructor
  /// @param _factory Address of the factory
  /// @param _senderCreator Address of the ERC-4337 entrypoint's sender creator
  constructor(address _factory, address _senderCreator) {
    factory = Factory(_factory);
    senderCreator = _senderCreator;
  }

  /// @notice Deploy a new wallet instance
  /// @param _mainModule Address of the main module to be used by the wallet
  /// @param _salt Salt used to generate the wallet, which is the imageHash of the wallet's configuration.
  /// @dev It is recommended to not have more than 200 signers as opcode repricing could make transactions impossible to execute as all the signers must be passed for each transaction.
  /// @dev Only the senderCreator can deploy a wallet.
  /// @return _contract The address of the deployed wallet
  function deploy(address _mainModule, bytes32 _salt) public payable returns (address _contract) {
    if (msg.sender != senderCreator) {
      revert NotSenderCreator();
    }
    bytes memory code = abi.encodePacked(Wallet.creationCode, uint256(uint160(_mainModule)));
    bytes32 bytecodeHash = keccak256(code);
    address factoryAddress = address(factory);
    // OpenZeppelin's Create2.computeAddress implementation
    assembly ("memory-safe") {
      let ptr := mload(0x40)
      mstore(add(ptr, 0x40), bytecodeHash)
      mstore(add(ptr, 0x20), _salt)
      mstore(ptr, factoryAddress)
      let start := add(ptr, 0x0b)
      mstore8(start, 0xff)
      _contract := and(keccak256(start, 85), 0xffffffffffffffffffffffffffffffffffffffff)
    }
    if (_contract.code.length > 0) {
      return _contract;
    }
    return factory.deploy{ value: msg.value }(_mainModule, _salt);
  }

}
