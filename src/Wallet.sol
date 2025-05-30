// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

/*
#define macro CONSTRUCTOR() = takes (0) returns (0) {
  0x3e                   // [code + arg size] (code_size + 32)
  __codeoffset(MAIN)     // [code_start, code + arg size]
  returndatasize         // [0, code_start, code + arg size]
  codecopy               // []

  __codesize(MAIN)       // [code_size]
  dup1                   // [code_size, code_size]
  mload                  // [arg1, code_size]
  address                // [address, arg1, code_size]
  sstore                 // [code_size]

  returndatasize         // [0, code_size]
  return
}

#define macro MAIN() = takes(0) returns(0) {
  returndatasize     // [0]
  returndatasize     // [0, 0]
  callvalue          // [cv, 0, 0]
  success            // [nr, cv, 0, 0]
  jumpi
    calldatasize     // [cds, 0, 0]
    returndatasize   // [0, cds, 0, 0]
    returndatasize   // [0, 0, cds, 0, 0]
    calldatacopy     // [0, 0]
    returndatasize   // [0, 0, 0]
    calldatasize     // [cds, 0, 0, 0]
    returndatasize   // [0, cds, 0, 0, 0]
    address          // [addr, 0, cds, 0, 0, 0]
    sload            // [imp, 0, cds, 0, 0, 0]
    gas              // [gas, imp, 0, cds, 0, 0, 0]
    delegatecall     // [suc, 0]
    returndatasize   // [rds, suc, 0]
    dup3             // [0, rds, suc, 0]
    dup1             // [0, 0, rds, suc, 0]
    returndatacopy   // [suc, 0]
    swap1            // [0, suc]
    returndatasize   // [rds, 0, suc]
    swap2            // [suc, 0, rds]
    success          // [nr, suc, 0, rds]
    jumpi
      revert
  success:
    return
}
*/

/// @title Delegate Proxy
/// @author Agusx1211
/// @notice Implements a proxy that uses the contract's own address to store the location of the proxy.
/// All calls are forwarded to the stored proxy address as long as they don't include value.
library Wallet {

  bytes internal constant creationCode =
    hex"603e600e3d39601e805130553df33d3d34601c57363d3d373d363d30545af43d82803e903d91601c57fd5bf3";

}
