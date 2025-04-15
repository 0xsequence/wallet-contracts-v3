// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Hooks, IERC1155Receiver, IERC223Receiver, IERC721Receiver, IERC777Receiver } from "../../src/modules/Hooks.sol";
import { SelfAuth } from "../../src/modules/auth/SelfAuth.sol";

import { AdvTest } from "../utils/TestUtils.sol";
import { Vm } from "forge-std/Test.sol";

contract HooksTest is AdvTest {

  Hooks public hooks;
  address public constant TEST_IMPLEMENTATION = address(0x123);

  function setUp() public {
    hooks = new Hooks();
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
  function test_onERC1155Received(address _from, address _to, uint256 _id, uint256 _value, bytes calldata _data) public {
    bytes4 selector = IERC1155Receiver.onERC1155Received.selector;
    assertEq(selector, bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)")));
    bytes4 returnValue = hooks.onERC1155Received(_from, _to, _id, _value, _data);
    assertEq(returnValue, selector);
  }

  function test_onERC1155Received_fallback(
    address _from,
    address _to,
    uint256 _id,
    uint256 _value,
    bytes calldata _data
  ) public {
    MockERC1155ReceiverFallback mock = new MockERC1155ReceiverFallback();
    vm.prank(address(hooks));
    hooks.addHook(IERC1155Receiver.onERC1155Received.selector, address(mock));
    vm.expectEmit(true, true, true, true);
    emit MockERC1155ReceiverFallback.Received(address(this), _from, _to, _id, _value, _data);
    test_onERC1155Received(_from, _to, _id, _value, _data);
  }

  function test_onERC1155BatchReceived(
    address _from,
    address _to,
    uint256[] calldata _ids,
    uint256[] calldata _values,
    bytes calldata _data
  ) public {
    bytes4 selector = IERC1155Receiver.onERC1155BatchReceived.selector;
    assertEq(selector, bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)")));
    bytes4 returnValue = hooks.onERC1155BatchReceived(_from, _to, _ids, _values, _data);
    assertEq(returnValue, selector);
  }

  function test_onERC1155BatchReceived_fallback(
    address _from,
    address _to,
    uint256[] calldata _ids,
    uint256[] calldata _values,
    bytes calldata _data
  ) external {
    MockERC1155ReceiverFallback mock = new MockERC1155ReceiverFallback();
    vm.prank(address(hooks));
    hooks.addHook(IERC1155Receiver.onERC1155BatchReceived.selector, address(mock));
    vm.expectEmit(true, true, true, true);
    emit MockERC1155ReceiverFallback.ReceivedBatch(address(this), _from, _to, _ids, _values, _data);
    test_onERC1155BatchReceived(_from, _to, _ids, _values, _data);
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

  function test_tokensReceived_fallback(
    address _operator,
    address _from,
    address _to,
    uint256 _amount,
    bytes calldata _data,
    bytes calldata _operatorData
  ) external {
    MockERC777ReceiverFallback mock = new MockERC777ReceiverFallback();
    vm.prank(address(hooks));
    hooks.addHook(IERC777Receiver.tokensReceived.selector, address(mock));
    vm.expectEmit(true, true, true, true);
    emit MockERC777ReceiverFallback.Received(address(this), _operator, _from, _to, _amount, _data, _operatorData);
    test_tokensReceived(_operator, _from, _to, _amount, _data, _operatorData);
  }

  // ERC721 Receiver Tests
  function test_onERC721Received(address _from, address _to, uint256 _tokenId, bytes calldata _data) public {
    bytes4 selector = IERC721Receiver.onERC721Received.selector;
    assertEq(selector, bytes4(keccak256("onERC721Received(address,address,uint256,bytes)")));
    bytes4 returnValue = hooks.onERC721Received(_from, _to, _tokenId, _data);
    assertEq(returnValue, selector);
  }

  function test_onERC721Received_fallback(address _from, address _to, uint256 _tokenId, bytes calldata _data) external {
    MockERC721ReceiverFallback mock = new MockERC721ReceiverFallback();
    vm.prank(address(hooks));
    hooks.addHook(IERC721Receiver.onERC721Received.selector, address(mock));
    vm.expectEmit(true, true, true, true);
    emit MockERC721ReceiverFallback.Received(address(this), _from, _to, _tokenId, _data);
    test_onERC721Received(_from, _to, _tokenId, _data);
  }

  // ERC223 Receiver Tests
  function test_tokenReceived(address _from, uint256 _value, bytes calldata _data) public {
    // This function should not revert
    hooks.tokenReceived(_from, _value, _data);
  }

  function test_tokenReceived_fallback(address _from, uint256 _value, bytes calldata _data) external {
    MockERC223ReceiverFallback mock = new MockERC223ReceiverFallback();
    vm.prank(address(hooks));
    hooks.addHook(IERC223Receiver.tokenReceived.selector, address(mock));
    vm.expectEmit(true, true, true, true);
    emit MockERC223ReceiverFallback.Received(address(this), _from, _value, _data);
    test_tokenReceived(_from, _value, _data);
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

}

contract MockERC1155ReceiverFallback is IERC1155Receiver {

  event Received(address sender, address from, address to, uint256 id, uint256 value, bytes data);
  event ReceivedBatch(address sender, address from, address to, uint256[] ids, uint256[] values, bytes data);

  function onERC1155Received(
    address from,
    address to,
    uint256 id,
    uint256 value,
    bytes calldata data
  ) external returns (bytes4) {
    emit Received(msg.sender, from, to, id, value, data);
    return this.onERC1155Received.selector;
  }

  function onERC1155BatchReceived(
    address from,
    address to,
    uint256[] calldata ids,
    uint256[] calldata values,
    bytes calldata data
  ) external returns (bytes4) {
    emit ReceivedBatch(msg.sender, from, to, ids, values, data);
    return this.onERC1155BatchReceived.selector;
  }

}

contract MockERC777ReceiverFallback is IERC777Receiver {

  event Received(
    address sender, address operator, address from, address to, uint256 amount, bytes data, bytes operatorData
  );

  function tokensReceived(
    address operator,
    address from,
    address to,
    uint256 amount,
    bytes calldata data,
    bytes calldata operatorData
  ) external {
    emit Received(msg.sender, operator, from, to, amount, data, operatorData);
  }

}

contract MockERC721ReceiverFallback is IERC721Receiver {

  event Received(address sender, address from, address to, uint256 tokenId, bytes data);

  function onERC721Received(address from, address to, uint256 tokenId, bytes calldata data) external returns (bytes4) {
    emit Received(msg.sender, from, to, tokenId, data);
    return this.onERC721Received.selector;
  }

}

contract MockERC223ReceiverFallback is IERC223Receiver {

  event Received(address sender, address from, uint256 value, bytes data);

  function tokenReceived(address from, uint256 value, bytes calldata data) external {
    emit Received(msg.sender, from, value, data);
  }

}
