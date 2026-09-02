// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Calls } from "./modules/Calls.sol";

import { ERC4337v07 } from "./modules/ERC4337v07.sol";
import { Hooks } from "./modules/Hooks.sol";
import { Stage7702Auth } from "./modules/auth/Stage7702Auth.sol";
import { IAuth } from "./modules/interfaces/IAuth.sol";

/// @title Stage7702Module
/// @author Agustin Aguilar
/// @notice The only stage of an EIP-7702 wallet
/// @dev EIP-7702 re-delegation does not clear account storage. An account that pointed at some other
///      implementation before pointing here keeps everything that implementation wrote, and this module reads
///      the same namespaced slots it always reads:
///
///      - keccak256("org.arcadeum.module.auth.upgradable.image.hash"), the image hash. `imageHash()` returns
///        the stored value whenever it is non-zero, so a planted hash replaces the counterfactual 1-of-1
///        configuration without any event or call.
///      - keccak256("org.arcadeum.module.hooks.hooks"), the hooks map. Hooks are arbitrary delegatecall
///        targets that any caller can reach through the fallback.
///      - keccak256("org.sequence.module.auth.static"), the static signature map.
///      - keccak256("org.arcadeum.module.calls.nonce"), the nonce map.
///      - keccak256("org.sequence.module.reentrancyguard.status"), the reentrancy status. A value left at
///        `_ENTERED` makes every `execute` call revert.
///
///      Namespacing these slots prevents accidental collisions, not deliberate ones, so delegating to this
///      module must not be taken as sanitizing the account. Integrators SHOULD read `imageHash()`, and
///      `readHook(selector)` for sensitive selectors, before treating a newly delegated account as fresh.
contract Stage7702Module is Calls, Stage7702Auth, Hooks, ERC4337v07 {

  constructor(
    address _entryPoint,
    address _defaultCheckpointer
  ) ERC4337v07(_entryPoint) Stage7702Auth(_defaultCheckpointer) { }

  /// @inheritdoc IAuth
  function _isValidImage(
    bytes32 _imageHash
  ) internal view virtual override(IAuth, Stage7702Auth) returns (bool) {
    return super._isValidImage(_imageHash);
  }

}
