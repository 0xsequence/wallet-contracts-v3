// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Test } from "forge-std/Test.sol";

import { IAuth } from "src/modules/interfaces/IAuth.sol";

contract IAuthMock is IAuth {

  function isValidImage(
    bytes32 imageHash
  ) public view returns (bool) {
    return _isValidImage(imageHash);
  }

  function _updateImageHash(
    bytes32
  ) internal view override { }

}

contract IAuthTest is Test {

  IAuthMock auth;

  function setUp() public {
    auth = new IAuthMock();
  }

  function test_isValidImage(
    bytes32 imageHash
  ) public view {
    assertEq(auth.isValidImage(imageHash), false); // Default implementation returns false
  }

}
