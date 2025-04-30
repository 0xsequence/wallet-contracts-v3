// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Permission, UsageLimit } from "./Permission.sol";

/// @notice Permissions configuration for a specific session signer
struct SessionPermissions {
  /// @notice Address of the session signer these permissions apply to
  address signer;
  /// @notice Whether signing messages is allowed
  bool allowMessages;
  /// @notice Maximum native token value this signer can send
  uint256 valueLimit;
  /// @notice Deadline for the session. (0 = no deadline)
  uint256 deadline;
  /// @notice Array of encoded permissions granted to this signer
  Permission[] permissions;
}

/// @notice Usage limits configuration for a specific session signer
struct SessionUsageLimits {
  /// @notice Address of the session signer these limits apply to
  address signer;
  /// @notice Array of usage limits
  UsageLimit[] limits;
  /// @notice Total native token value used
  uint256 totalValueUsed;
}

interface IExplicitSessionManager {

  /// @notice Increment usage for a caller's given session and target
  /// @param limits Array of limit/session/target combinations
  function incrementUsageLimit(
    UsageLimit[] calldata limits
  ) external;

}
