// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Nonce } from "../../src/modules/Nonce.sol";
import { SelfAuth } from "../../src/modules/auth/SelfAuth.sol";

import { AdvTest } from "../utils/TestUtils.sol";
import { Vm } from "forge-std/Test.sol";

contract NonceImp is Nonce {

  function writeNonce(uint256 _space, uint256 _nonce) public {
    super._writeNonce(_space, _nonce);
  }

  function consumeNonce(uint256 _space, uint256 _nonce) public {
    super._consumeNonce(_space, _nonce);
  }

}

contract NonceTest is AdvTest {

  NonceImp public nonceImp;

  function setUp() public {
    nonceImp = new NonceImp();
  }

  function test_readNonce(uint256 _space, uint256 _nonce) public {
    nonceImp.writeNonce(_space, _nonce);
    assertEq(nonceImp.readNonce(_space), _nonce);
  }

  function test_consumeNonce(uint256 _space, uint256 _nonce) public {
    vm.assume(_nonce < type(uint256).max - 1);
    nonceImp.writeNonce(_space, _nonce);
    nonceImp.consumeNonce(_space, _nonce);
    assertEq(nonceImp.readNonce(_space), _nonce + 1);
  }

  function test_consumeNonce_revertWhenBadNonce(uint256 _space, uint256 _nonce, uint256 _badNonce) public {
    vm.assume(_nonce < type(uint256).max - 1);
    vm.assume(_badNonce != _nonce);
    nonceImp.writeNonce(_space, _nonce);
    vm.expectRevert(abi.encodeWithSelector(Nonce.BadNonce.selector, _space, _badNonce, _nonce));
    nonceImp.consumeNonce(_space, _badNonce);
  }

}
