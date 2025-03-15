// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { ERC20 } from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

import { Attestation, LibAttestation } from "src/extensions/sessions/implicit/Attestation.sol";
import { ISignalsImplicitMode, Payload } from "src/extensions/sessions/implicit/ISignalsImplicitMode.sol";

contract MockERC20 is ERC20 {

  constructor(string memory name, string memory symbol) ERC20(name, symbol) { }

  function mint(address to, uint256 amount) external {
    _mint(to, amount);
  }

}

// ERC20 implementation that allows a free one time mint with implicit signals
// A real usage would be to lock transfer to be under a given limit
contract ERC20ImplicitMint is ISignalsImplicitMode, ERC20 {

  bytes32 private immutable redirectUrlHash;
  mapping(address => bool) public minted;

  constructor(string memory name, string memory symbol, string memory redirectUrl) ERC20(name, symbol) {
    redirectUrlHash = keccak256(abi.encodePacked(redirectUrl));
  }

  function acceptImplicitRequest(
    address wallet,
    Attestation calldata attestation,
    Payload.Call calldata call
  ) external view returns (bytes32) {
    // Validate the session is from a known app
    if (keccak256(abi.encodePacked(attestation.authData.redirectUrl)) != redirectUrlHash) {
      revert("Invalid redirect URL");
    }
    // Unneccessary validation, but done for clarity
    if (call.to != address(this) || call.value > 0) {
      revert("Invalid call");
    }

    // Check this is a call to the mint function with the correct params
    bytes4 selector = bytes4(call.data[:4]);
    (address to, uint256 amount) = abi.decode(call.data[4:], (address, uint256));
    if (selector != this.mintOnce.selector || to != wallet || amount != 1e18) {
      revert("Invalid call");
    }

    return LibAttestation.generateImplicitRequestMagic(attestation, wallet);
  }

  function mintOnce(address to, uint256 amount) external {
    if (minted[to]) {
      revert("Wallet already minted");
    }
    _mint(to, amount);
    minted[to] = true;
  }

}
