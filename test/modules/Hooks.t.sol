// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Factory } from "../../src/Factory.sol";
import { Hooks, IERC1155Receiver, IERC223Receiver, IERC721Receiver, IERC777Receiver } from "../../src/modules/Hooks.sol";
import { SelfAuth } from "../../src/modules/auth/SelfAuth.sol";

import { AdvTest } from "../utils/TestUtils.sol";

contract HooksTest is AdvTest {

  Hooks public hooks;
  address public constant TEST_IMPLEMENTATION = address(0x123);
  Factory public factory;

  function setUp() public {
    // Deploy via factory to test forwarding
    Hooks impl = new Hooks();
    factory = new Factory();
    hooks = Hooks(payable(factory.deploy(address(impl), bytes32(0))));
  }

  // Hook Management Tests
  function test_addHook() public {
    bytes4 signature = bytes4(keccak256("testFunction()"));
    vm.prank(address(hooks));
    hooks.addHook(signature, TEST_IMPLEMENTATION);
    assertEq(hooks.readHook(signature), TEST_IMPLEMENTATION);
  }

  function test_addHook_revertWhenHookExists() public {
    bytes4 signature = bytes4(keccak256("testFunction()"));
    vm.prank(address(hooks));
    hooks.addHook(signature, TEST_IMPLEMENTATION);
    vm.expectRevert(abi.encodeWithSelector(Hooks.HookAlreadyExists.selector, signature));
    vm.prank(address(hooks));
    hooks.addHook(signature, TEST_IMPLEMENTATION);
  }

  function test_addHook_revertWhenNotSelf() public {
    bytes4 signature = bytes4(keccak256("testFunction()"));
    vm.expectRevert(abi.encodeWithSelector(SelfAuth.OnlySelf.selector, address(this)));
    hooks.addHook(signature, TEST_IMPLEMENTATION);
  }

  function test_removeHook() public {
    bytes4 signature = bytes4(keccak256("testFunction()"));
    vm.prank(address(hooks));
    hooks.addHook(signature, TEST_IMPLEMENTATION);
    vm.prank(address(hooks));
    hooks.removeHook(signature);
    assertEq(hooks.readHook(signature), address(0));
  }

  function test_removeHook_revertWhenHookDoesNotExist() public {
    bytes4 signature = bytes4(keccak256("testFunction()"));
    vm.expectRevert(abi.encodeWithSelector(Hooks.HookDoesNotExist.selector, signature));
    vm.prank(address(hooks));
    hooks.removeHook(signature);
  }

  // ERC1155 Receiver Tests
  function test_onERC1155Received(
    address _from,
    address _to,
    uint256 _id,
    uint256 _value,
    bytes calldata _data
  ) external view {
    bytes4 selector = IERC1155Receiver.onERC1155Received.selector;
    assertEq(selector, bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)")));
    bytes4 returnValue = hooks.onERC1155Received(_from, _to, _id, _value, _data);
    assertEq(returnValue, selector);
  }

  function test_onERC1155BatchReceived(
    address _from,
    address _to,
    uint256[] calldata _ids,
    uint256[] calldata _values,
    bytes calldata _data
  ) external view {
    bytes4 selector = IERC1155Receiver.onERC1155BatchReceived.selector;
    assertEq(selector, bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)")));
    bytes4 returnValue = hooks.onERC1155BatchReceived(_from, _to, _ids, _values, _data);
    assertEq(returnValue, selector);
  }

  // ERC777 Receiver Tests
  function test_tokensReceived(
    address _operator,
    address _from,
    address _to,
    uint256 _amount,
    bytes calldata _data,
    bytes calldata _operatorData
  ) public {
    bytes4 selector = IERC777Receiver.tokensReceived.selector;
    assertEq(selector, bytes4(keccak256("tokensReceived(address,address,address,uint256,bytes,bytes)")));
    hooks.tokensReceived(_operator, _from, _to, _amount, _data, _operatorData);
  }

  // ERC721 Receiver Tests
  function test_onERC721Received(address _from, address _to, uint256 _tokenId, bytes calldata _data) external view {
    bytes4 selector = IERC721Receiver.onERC721Received.selector;
    assertEq(selector, bytes4(keccak256("onERC721Received(address,address,uint256,bytes)")));
    bytes4 returnValue = hooks.onERC721Received(_from, _to, _tokenId, _data);
    assertEq(returnValue, selector);
  }

  // ERC223 Receiver Tests
  function test_tokenReceived(address _from, uint256 _value, bytes calldata _data) external view {
    bytes4 selector = IERC223Receiver.tokenReceived.selector;
    assertEq(selector, bytes4(keccak256("tokenReceived(address,uint256,bytes)")));
    bytes4 returnValue = hooks.tokenReceived(_from, _value, _data);
    assertEq(returnValue, selector);
  }

  // Fallback and Receive Tests
  function test_fallback() public {
    bytes4 signature = bytes4(keccak256("testFunction()"));
    address mockImplementation = address(new MockImplementation());
    vm.prank(address(hooks));
    hooks.addHook(signature, mockImplementation);

    (bool success, bytes memory result) = address(hooks).call(abi.encodeWithSelector(signature));
    assertTrue(success);
    assertEq(result, abi.encode(true));

    success = MockImplementation(address(hooks)).testFunction();
    assertTrue(success);
  }

  function test_fallbackRevertWhenHookNotPayable() public {
    bytes4 signature = bytes4(keccak256("testFunction()"));
    address mockImplementation = address(new MockImplementation());
    vm.prank(address(hooks));
    hooks.addHook(signature, mockImplementation);

    (bool success,) = address(hooks).call{ value: 1 ether }(abi.encodeWithSelector(signature));
    assertFalse(success);
  }

  function test_payableFallback() public {
    bytes4 signature = bytes4(keccak256("testPayableFunction()"));
    address mockImplementation = address(new MockImplementation());
    vm.prank(address(hooks));
    hooks.addHook(signature, mockImplementation);

    (bool success, bytes memory result) = address(hooks).call{ value: 1 ether }(abi.encodeWithSelector(signature));
    assertTrue(success);
    assertEq(result, abi.encode(true));
    assertEq(address(hooks).balance, 1 ether);
  }

  function test_receive() public {
    vm.deal(address(this), 1 ether);
    (bool success,) = address(hooks).call{ value: 1 ether }("");
    assertTrue(success);
  }

}

contract MockImplementation {

  function testFunction() external pure returns (bool) {
    return true;
  }

  function testPayableFunction() external payable returns (bool) {
    return true;
  }

}
