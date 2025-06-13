// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

import { Calls } from "./Calls.sol";
import { IAccount, PackedUserOperation } from "./interfaces/IAccount.sol";
import { IERC1271, IERC1271_MAGIC_VALUE_HASH } from "./interfaces/IERC1271.sol";
import { Entrypoint } from "./interfaces/IEntrypoint.sol";

abstract contract ERC4337 is IAccount, Calls {

  uint256 internal constant SIG_VALIDATION_FAILED = 1;

  address public immutable entrypoint;

  error InvalidEntrypoint(address _entrypoint);
  error ERC4337Disabled();

  constructor(
    address _entrypoint
  ) {
    entrypoint = _entrypoint;
  }

  function validateUserOp(
    PackedUserOperation calldata userOp,
    bytes32 userOpHash,
    uint256 missingAccountFunds
  ) external returns (uint256 validationData) {
    if (entrypoint == address(0)) {
      revert ERC4337Disabled();
    }

    if (msg.sender != entrypoint) {
      revert InvalidEntrypoint(msg.sender);
    }

    // userOp.nonce is validated by the entrypoint

    if (missingAccountFunds != 0) {
      Entrypoint(entrypoint).depositFor(address(this), missingAccountFunds);
    }

    if (this.isValidSignature(userOpHash, userOp.signature) != IERC1271_MAGIC_VALUE_HASH) {
      return SIG_VALIDATION_FAILED;
    }

    return 0;
  }

  function executeUserOp(
    bytes calldata _payload
  ) external {
    if (entrypoint == address(0)) {
      revert ERC4337Disabled();
    }

    if (msg.sender != entrypoint) {
      revert InvalidEntrypoint(msg.sender);
    }

    this.selfExecute(_payload);
  }

}
