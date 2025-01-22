// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Attestation, LibAttestation } from "../src/modules/Attestation.sol";
import { Permissions } from "../src/modules/Permissions.sol";
import { ISapient, Payload } from "../src/modules/interfaces/ISapient.sol";
import {
  ISessionManager,
  ISessionManagerSignals,
  SessionConfiguration,
  SessionConfigurationPermissions,
  SessionSignature
} from "../src/modules/interfaces/ISessionManager.sol";
import { ISignalsImplicitMode } from "../src/modules/interfaces/ISignalsImplicitMode.sol";
import { SessionManager } from "../src/modules/sapient/SessionManager.sol";
import { Test, Vm } from "forge-std/Test.sol";

using LibAttestation for Attestation;

contract MockImplicitContract is ISignalsImplicitMode {

  function acceptImplicitRequest(
    address wallet,
    Attestation calldata attestation,
    bytes32,
    Payload.Call calldata
  ) external pure returns (bytes32) {
    return attestation.generateImplicitRequestMagic(wallet);
  }

}

contract SessionManagerTest is Test, ISessionManagerSignals {

  SessionManager public sessionManager;
  Vm.Wallet public wallet;
  Vm.Wallet public globalSigner;
  Vm.Wallet public sessionSigner;
  MockImplicitContract public mockImplicit;

  function setUp() public {
    sessionManager = new SessionManager();
    wallet = vm.createWallet("wallet");
    sessionSigner = vm.createWallet("sessionSigner");
    globalSigner = vm.createWallet("globalSigner");

    mockImplicit = new MockImplicitContract();
  }

  function test_SupportsInterface() public view {
    assertTrue(sessionManager.supportsInterface(type(ISapient).interfaceId));
    assertTrue(sessionManager.supportsInterface(type(ISessionManager).interfaceId));
  }

  function test_ExplicitMode_ERC20(
    address tokenAddr
  ) public {
    // Create session configuration with ERC20 permission
    Permissions.EncodedPermission[] memory permissions = new Permissions.EncodedPermission[](1);
    permissions[0] = Permissions.encodeERC20(
      tokenAddr,
      1000 // limit
    );

    SessionConfigurationPermissions[] memory sessionPermissions = new SessionConfigurationPermissions[](1);
    sessionPermissions[0] = SessionConfigurationPermissions({
      signer: sessionSigner.addr,
      deadline: 0,
      permissions: permissions,
      valueLimit: 0
    });

    // Sort the permissions array by signer address
    _sortSessionPermissions(sessionPermissions);

    SessionConfiguration memory config = _createSessionConfiguration(
      sessionPermissions,
      new address[](0) // Empty blacklist for explicit mode
    );

    // Test all ERC20 operations
    bytes4[] memory selectors = new bytes4[](3);
    selectors[0] = bytes4(keccak256("transfer(address,uint256)"));
    selectors[1] = bytes4(keccak256("transferFrom(address,address,uint256)"));
    selectors[2] = bytes4(keccak256("approve(address,uint256)"));

    for (uint256 i = 0; i < selectors.length; i++) {
      Payload.Call[] memory calls = _createERC20Calls(tokenAddr, selectors[i], 500);

      (SessionSignature memory signature, bytes32 expectedImageHash) = _createValidSignature(
        calls,
        config,
        2 // number of calls including incrementLimitUsage
      );

      vm.prank(wallet.addr);
      bytes32 imageHash = sessionManager.isValidSapientSignature(
        Payload.Decoded({
          kind: Payload.KIND_TRANSACTIONS,
          noChainId: false,
          calls: calls,
          space: 0,
          nonce: 0,
          message: "",
          imageHash: bytes32(0),
          digest: bytes32(0),
          parentWallets: new address[](0)
        }),
        abi.encode(signature)
      );

      assertEq(imageHash, expectedImageHash);
    }
  }

  function test_ImplicitMode() public {
    address[] memory blacklist = new address[](1);
    blacklist[0] = address(0xdead);

    SessionConfiguration memory config =
      _createSessionConfiguration(new SessionConfigurationPermissions[](0), blacklist);

    Payload.Call[] memory calls = new Payload.Call[](1);
    calls[0] = Payload.Call({
      to: address(mockImplicit),
      value: 0,
      data: abi.encodeWithSelector(
        MockImplicitContract.acceptImplicitRequest.selector, wallet.addr, bytes32(0), bytes32(0)
      ),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    (SessionSignature memory signature, bytes32 expectedImageHash) = _createValidSignature(calls, config, 1);
    signature.isImplicit = true;

    vm.prank(wallet.addr);
    bytes32 imageHash = sessionManager.isValidSapientSignature(
      Payload.Decoded({
        kind: Payload.KIND_TRANSACTIONS,
        noChainId: false,
        calls: calls,
        space: 0,
        nonce: 0,
        message: "",
        imageHash: bytes32(0),
        digest: bytes32(0),
        parentWallets: new address[](0)
      }),
      abi.encode(signature)
    );

    assertEq(imageHash, expectedImageHash);
  }

  function test_RevertInvalidSessionSignature() public {
    Permissions.EncodedPermission[] memory permissions = new Permissions.EncodedPermission[](1);
    permissions[0] = Permissions.encodeERC20(address(0x1234), 1000);

    SessionConfigurationPermissions[] memory sessionPermissions = new SessionConfigurationPermissions[](1);
    sessionPermissions[0] = SessionConfigurationPermissions({
      signer: sessionSigner.addr,
      deadline: 0,
      permissions: permissions,
      valueLimit: 0
    });

    SessionConfiguration memory config = _createSessionConfiguration(sessionPermissions, new address[](0));

    Payload.Call[] memory calls =
      _createERC20Calls(address(0x1234), bytes4(keccak256("transfer(address,uint256)")), 500);

    (SessionSignature memory signature,) = _createValidSignature(calls, config, 2);
    // Corrupt the session signature
    signature.sessionSignature = bytes("invalid");

    vm.prank(wallet.addr);
    vm.expectRevert();
    sessionManager.isValidSapientSignature(
      Payload.Decoded({
        kind: Payload.KIND_TRANSACTIONS,
        noChainId: false,
        calls: calls,
        space: 0,
        nonce: 0,
        message: "",
        imageHash: bytes32(0),
        digest: bytes32(0),
        parentWallets: new address[](0)
      }),
      abi.encode(signature)
    );
  }

  function test_RevertBlacklistedAddress() public {
    address[] memory blacklist = new address[](1);
    blacklist[0] = address(mockImplicit);

    SessionConfiguration memory config =
      _createSessionConfiguration(new SessionConfigurationPermissions[](0), blacklist);

    Payload.Call[] memory calls = new Payload.Call[](1);
    calls[0] = Payload.Call({
      to: address(mockImplicit),
      value: 0,
      data: abi.encodeWithSelector(
        MockImplicitContract.acceptImplicitRequest.selector, wallet.addr, bytes32(0), bytes32(0)
      ),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    (SessionSignature memory signature,) = _createValidSignature(calls, config, 1);
    signature.isImplicit = true;

    vm.prank(wallet.addr);
    vm.expectRevert(abi.encodeWithSelector(BlacklistedAddress.selector, wallet.addr, address(mockImplicit)));
    sessionManager.isValidSapientSignature(
      Payload.Decoded({
        kind: Payload.KIND_TRANSACTIONS,
        noChainId: false,
        calls: calls,
        space: 0,
        nonce: 0,
        message: "",
        imageHash: bytes32(0),
        digest: bytes32(0),
        parentWallets: new address[](0)
      }),
      abi.encode(signature)
    );
  }

  function test_GetImageHash(
    address globalSignerAddr,
    address signerAddr,
    bytes memory permissionData,
    address[] memory blacklist,
    uint256 deadline,
    uint256 valueLimit
  ) public view {
    Permissions.EncodedPermission[] memory permissions = new Permissions.EncodedPermission[](1);
    permissions[0] =
      Permissions.EncodedPermission({ pType: Permissions.PermissionType.FUNCTION_CALL, data: permissionData });

    SessionConfigurationPermissions[] memory sessionPermissions = new SessionConfigurationPermissions[](1);
    sessionPermissions[0] = SessionConfigurationPermissions({
      signer: signerAddr,
      permissions: permissions,
      valueLimit: valueLimit,
      deadline: deadline
    });

    // Create configuration
    SessionConfiguration memory config = _createSessionConfiguration(sessionPermissions, blacklist);

    // Calculate expected hash manually
    bytes32 expectedHash = keccak256(abi.encode(globalSignerAddr, config));

    // Get hash from contract
    bytes32 actualHash = sessionManager.getImageHash(globalSignerAddr, config);

    // Verify hashes match
    assertEq(actualHash, expectedHash, "Image hash mismatch");
  }

  // Helper functions
  function _createERC20Calls(
    address token,
    bytes4 selector,
    uint256 amount
  ) internal view returns (Payload.Call[] memory) {
    Payload.Call[] memory calls = new Payload.Call[](2);

    if (selector == bytes4(keccak256("transfer(address,uint256)"))) {
      calls[0] = Payload.Call({
        to: token,
        value: 0,
        data: abi.encodeWithSelector(selector, address(0xdead), amount),
        gasLimit: 0,
        delegateCall: false,
        onlyFallback: false,
        behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
      });
    } else if (selector == bytes4(keccak256("transferFrom(address,address,uint256)"))) {
      calls[0] = Payload.Call({
        to: token,
        value: 0,
        data: abi.encodeWithSelector(selector, wallet.addr, address(0xdead), amount),
        gasLimit: 0,
        delegateCall: false,
        onlyFallback: false,
        behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
      });
    } else if (selector == bytes4(keccak256("approve(address,uint256)"))) {
      calls[0] = Payload.Call({
        to: token,
        value: 0,
        data: abi.encodeWithSelector(selector, address(0xdead), amount),
        gasLimit: 0,
        delegateCall: false,
        onlyFallback: false,
        behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
      });
    }

    // Add incrementLimitUsage call
    bytes32[] memory usageHashes = new bytes32[](1);
    usageHashes[0] = sessionManager.getUsageHash(wallet.addr, sessionSigner.addr, token);
    uint256[] memory usageAmounts = new uint256[](1);
    usageAmounts[0] = amount;

    calls[1] = Payload.Call({
      to: address(sessionManager),
      value: 0,
      data: abi.encodeWithSelector(SessionManager.incrementLimitUsage.selector, usageHashes, usageAmounts),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR
    });

    return calls;
  }

  function _createValidSignature(
    Payload.Call[] memory calls,
    SessionConfiguration memory config,
    uint256 numCalls
  ) internal view returns (SessionSignature memory signature, bytes32 expectedImageHash) {
    Payload.Decoded memory payload = Payload.Decoded({
      kind: Payload.KIND_TRANSACTIONS,
      noChainId: false,
      calls: calls,
      space: 0,
      nonce: 0,
      message: "",
      imageHash: bytes32(0),
      digest: bytes32(0),
      parentWallets: new address[](0)
    });

    // Create attestation with the stored sessionSigner
    Attestation memory attestation = Attestation({
      _approvedSigner: sessionSigner.addr,
      _identityType: bytes4(0),
      _issuerHash: bytes32(0),
      _audienceHash: bytes32(0),
      _authData: "",
      _applicationData: ""
    });

    bytes32 payloadHash = keccak256(abi.encode(payload));
    bytes memory sessionSig = _signMessage(payloadHash, sessionSigner.privateKey);
    bytes32 attestationHash = attestation.toHash();
    bytes memory globalSig = _signMessage(attestationHash, globalSigner.privateKey);

    signature = SessionSignature({
      isImplicit: false,
      sessionConfiguration: config,
      attestation: attestation,
      globalSignature: globalSig,
      sessionSignature: sessionSig,
      permissionIdxPerCall: new uint8[](numCalls)
    });

    // for (uint256 i = 0; i < numCalls; i++) {
    //   signature.permissionIdxPerCall[i] = 0;
    // }

    expectedImageHash = keccak256(abi.encode(globalSigner.addr, config));
  }

  function _createSessionConfiguration(
    SessionConfigurationPermissions[] memory _permissions,
    address[] memory _blacklist
  ) internal pure returns (SessionConfiguration memory) {
    return SessionConfiguration({ sessionPermissions: _permissions, implicitBlacklist: _blacklist });
  }

  function _signMessage(bytes32 message, uint256 privateKey) internal pure returns (bytes memory) {
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, message);
    return abi.encodePacked(r, s, v);
  }

  // Add this helper function to sort session permissions
  function _sortSessionPermissions(
    SessionConfigurationPermissions[] memory permissions
  ) internal pure {
    for (uint256 i = 0; i < permissions.length - 1; i++) {
      for (uint256 j = 0; j < permissions.length - i - 1; j++) {
        if (permissions[j].signer > permissions[j + 1].signer) {
          SessionConfigurationPermissions memory temp = permissions[j];
          permissions[j] = permissions[j + 1];
          permissions[j + 1] = temp;
        }
      }
    }
  }

  // Add this helper function to sort addresses
  function _sortAddresses(
    address[] memory addresses
  ) internal pure {
    for (uint256 i = 0; i < addresses.length - 1; i++) {
      for (uint256 j = 0; j < addresses.length - i - 1; j++) {
        if (addresses[j] > addresses[j + 1]) {
          address temp = addresses[j];
          addresses[j] = addresses[j + 1];
          addresses[j + 1] = temp;
        }
      }
    }
  }

  function _hasLimit(
    Permissions.PermissionType pType
  ) internal pure returns (bool) {
    return pType == Permissions.PermissionType.ERC20 || pType == Permissions.PermissionType.ERC1155
      || pType == Permissions.PermissionType.NATIVE;
  }

}
