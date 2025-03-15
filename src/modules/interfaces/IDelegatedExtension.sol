// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

interface IDelegatedExtension {

  function handleSequenceDelegateCall(
    bytes32 _opHash,
    uint256 _startingGas,
    uint256 _index,
    uint256 _numCalls,
    uint256 _space,
    bytes calldata _data
  ) external;

}
