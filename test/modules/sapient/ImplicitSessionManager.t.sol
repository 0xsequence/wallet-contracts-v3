// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { IImplicitSessionManager } from "../../../src/modules/interfaces/IImplicitSessionManager.sol";
import { ISapient } from "../../../src/modules/interfaces/ISapient.sol";
import { ImplicitSessionManager } from "../../../src/modules/sapient/ImplicitSessionManager.sol";

import { AdvTest } from "../../utils/TestUtils.sol";
import { console } from "forge-std/console.sol";

contract ImplicitSessionManagerTest is AdvTest {

  ImplicitSessionManager public sessionManager;

  function setUp() public {
    sessionManager = new ImplicitSessionManager();
  }

  function test_SupportsInterface() public view {
    assertTrue(sessionManager.supportsInterface(type(ISapient).interfaceId));
    assertTrue(sessionManager.supportsInterface(type(IImplicitSessionManager).interfaceId));
  }

}
