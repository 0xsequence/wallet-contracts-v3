// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

contract AddressToBooleanMap {

  mapping(address => bool) private _values;

  function set(address _addr, bool _val) external {
    _values[_addr] = _val;
  }

  function get(
    address _addr
  ) external view returns (bool) {
    return _values[_addr];
  }

}

contract BytesToBooleanMap {

  mapping(bytes => bool) private _values;

  function set(bytes calldata _bytes, bool _val) external {
    _values[_bytes] = _val;
  }

  function get(
    bytes calldata _bytes
  ) external view returns (bool) {
    return _values[_bytes];
  }

}

contract Bytes32ToUint256Map {

  mapping(bytes32 => uint256) private _values;

  function set(bytes32 _bytes32, uint256 _val) external {
    _values[_bytes32] = _val;
  }

  function get(
    bytes32 _bytes32
  ) external view returns (uint256) {
    return _values[_bytes32];
  }

}
