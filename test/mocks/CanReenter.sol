// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

contract CanReenter {

  function doAnotherCall(address target, bytes calldata data) external {
    (bool success,) = target.call(data);
    require(success, "Call failed");
  }

}
