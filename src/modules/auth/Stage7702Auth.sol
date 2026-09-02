// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { LibOptim } from "../../utils/LibOptim.sol";
import { Implementation7702 } from "../Implementation7702.sol";
import { Storage } from "../Storage.sol";
import { BaseAuth } from "./BaseAuth.sol";
import { BaseSig } from "./BaseSig.sol";

/// @title Stage7702Auth
/// @author Agustin Aguilar
/// @notice EIP-7702 version auth contract (single stage)
contract Stage7702Auth is BaseAuth, Implementation7702 {

  /// @dev keccak256("org.arcadeum.module.auth.upgradable.image.hash")
  bytes32 internal constant IMAGE_HASH_KEY =
    bytes32(0xea7157fa25e3aa17d0ae2d5280fa4e24d421c61842aa85e45194e1145aa72bf8);

  /// @notice Emitted when the image hash is updated
  event ImageHashUpdated(bytes32 newImageHash);

  /// @notice Error thrown when the image hash is zero
  error ImageHashIsZero();

  /// @notice Checkpointer used at the wallet creation
  /// @dev This address is committed into the counterfactual configuration of every fresh wallet
  ///      using this module, see `imageHash()`. It is fixed for all of them at module deploy time
  ///      and can only be changed by replacing the configuration of each wallet individually.
  ///
  ///      A non-zero value makes the first signature of every fresh wallet depend on this contract:
  ///      the signature must carry the checkpointer flag, and `BaseSig.recover` will call
  ///      `snapshotFor` on it. That call must not revert, and it must return either an empty
  ///      snapshot or the counterfactual image hash, otherwise recovery reverts with
  ///      `UnusedSnapshot` and the wallet cannot execute, validate ERC-1271 signatures or pass
  ///      ERC-4337 validation until its configuration is replaced.
  ///
  ///      A checkpointer can therefore block a fresh wallet, but it can never forge a
  ///      configuration for it, since the image hash is still derived from the signature itself.
  ///
  ///      `address(0)` is the recommended value. A checkpointer should only be set when it is
  ///      actually required, and such a contract MUST NOT revert and MUST return an empty snapshot
  ///      for wallets it does not know about.
  address public immutable DEFAULT_CHECKPOINTER;

  /// @param _defaultCheckpointer Checkpointer committed into the counterfactual configuration of
  ///        every fresh wallet using this module, see `DEFAULT_CHECKPOINTER`. Use `address(0)`
  ///        unless a checkpointer is required, as a non-zero value makes the first signature of
  ///        every fresh wallet depend on `snapshotFor` succeeding on that contract.
  constructor(
    address _defaultCheckpointer
  ) {
    DEFAULT_CHECKPOINTER = _defaultCheckpointer;
  }

  /// @notice Get the image hash
  /// @return imageHash The image hash
  /// @dev Uses the stored imageHash or computes the counterfactual one assuming an EIP-7702 wallet
  function imageHash() public view virtual returns (bytes32) {
    bytes32 onchain = Storage.readBytes32(IMAGE_HASH_KEY);
    if (onchain != bytes32(0)) {
      return onchain;
    }

    // In an EIP-7702 wallet the Sequence wallet starts as its own signer in a 1/1 configuration
    // so we only need to statically verify that the signer is the expected one
    bytes32 counterfactual = BaseSig._leafForAddressAndWeight(address(this), 1);
    counterfactual = LibOptim.fkeccak256(counterfactual, bytes32(uint256(1)));
    counterfactual = LibOptim.fkeccak256(counterfactual, bytes32(uint256(0)));
    counterfactual = LibOptim.fkeccak256(counterfactual, bytes32(uint256(uint160(DEFAULT_CHECKPOINTER))));
    return counterfactual;
  }

  function _updateImageHash(
    bytes32 _imageHash
  ) internal virtual override {
    // Update imageHash in storage
    if (_imageHash == bytes32(0)) {
      revert ImageHashIsZero();
    }
    Storage.writeBytes32(IMAGE_HASH_KEY, _imageHash);
    emit ImageHashUpdated(_imageHash);
  }

  function _isValidImage(
    bytes32 _imageHash
  ) internal view virtual override returns (bool) {
    return _imageHash == imageHash();
  }

}
