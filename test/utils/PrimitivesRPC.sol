// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

import { Vm } from "forge-std/Vm.sol";
import { Payload } from "src/modules/Payload.sol";

library PrimitivesRPC {

  uint256 private constant COUNTER_UNINITIALIZED = 0;
  uint256 private constant COUNTER_SLOT = uint256(keccak256("sequence.primitives-rpc.counter"));

  function getCounter() private view returns (uint256) {
    bytes32 counterSlot = bytes32(COUNTER_SLOT);
    uint256 value;
    assembly {
      value := sload(counterSlot)
    }
    return value;
  }

  function setCounter(
    uint256 value
  ) private {
    bytes32 counterSlot = bytes32(COUNTER_SLOT);
    assembly {
      sstore(counterSlot, value)
    }
  }

  function rpcURL(
    Vm _vm
  ) internal returns (string memory) {
    uint256 minPort = uint256(_vm.envUint("SEQ_SDK_RPC_MIN_PORT"));
    uint256 maxPort = uint256(_vm.envUint("SEQ_SDK_RPC_MAX_PORT"));
    require(maxPort >= minPort, "Invalid port range");

    // Get or initialize counter
    uint256 counter = getCounter();
    if (counter == COUNTER_UNINITIALIZED) {
      counter = uint256(keccak256(abi.encodePacked(msg.data)));
    }

    // Increment counter
    counter++;
    setCounter(counter);

    // Generate port within range using counter
    uint256 range = maxPort - minPort + 1;
    uint256 randomPort = minPort + (counter % range);

    string memory prefix = _vm.envString("SEQ_SDK_RPC_URL_PREFIX");
    string memory suffix = _vm.envString("SEQ_SDK_RPC_URL_SUFFIX");

    return string.concat(prefix, _vm.toString(randomPort), suffix);
  }

  // ----------------------------------------------------------------
  // devTools
  // ----------------------------------------------------------------

  function randomConfig(
    Vm _vm,
    uint256 _maxDepth,
    uint256 _seed,
    uint256 _minThresholdOnNested,
    string memory _skew
  ) internal returns (string memory) {
    string memory params = string.concat(
      '{"maxDepth":',
      _vm.toString(_maxDepth),
      ',"seed":"',
      _vm.toString(_seed),
      '","minThresholdOnNested":',
      _vm.toString(_minThresholdOnNested),
      ',"skewed":"',
      _skew,
      '"}'
    );
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "devTools_randomConfig", params);
    return string(rawResponse);
  }

  function randomSessionTopology(
    Vm _vm,
    uint256 _maxDepth,
    uint256 _maxPermissions,
    uint256 _maxRules,
    uint256 _seed
  ) internal returns (string memory) {
    string memory params = string.concat(
      '{"maxDepth":',
      _vm.toString(_maxDepth),
      ',"maxPermissions":',
      _vm.toString(_maxPermissions),
      ',"maxRules":',
      _vm.toString(_maxRules),
      ',"seed":"',
      _vm.toString(_seed),
      '"}'
    );
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "devTools_randomSessionTopology", params);
    return string(rawResponse);
  }

  // ----------------------------------------------------------------
  // payload
  // ----------------------------------------------------------------

  function toPackedPayload(Vm _vm, Payload.Decoded memory _decoded) internal returns (bytes memory) {
    string memory params = string.concat('{"payload":"', _vm.toString(abi.encode(_decoded)), '"}');
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "payload_toPacked", params);
    return (rawResponse);
  }

  function toPackedPayloadForWallet(
    Vm _vm,
    Payload.Decoded memory _decoded,
    address _wallet
  ) internal returns (bytes memory) {
    string memory params =
      string.concat('{"payload":"', _vm.toString(abi.encode(_decoded)), '","wallet":"', _vm.toString(_wallet), '"}');
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "payload_toPacked", params);
    return (rawResponse);
  }

  function hashForPayload(
    Vm _vm,
    address _wallet,
    uint64 _chainId,
    Payload.Decoded memory _decoded
  ) internal returns (bytes32) {
    string memory params = string.concat(
      '{"wallet":"',
      _vm.toString(_wallet),
      '","chainId":"',
      _vm.toString(_chainId),
      '","payload":"',
      _vm.toString(abi.encode(_decoded)),
      '"}'
    );
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "payload_hashFor", params);
    return abi.decode(rawResponse, (bytes32));
  }

  // ----------------------------------------------------------------
  // config
  // ----------------------------------------------------------------

  function newConfig(
    Vm _vm,
    uint16 _threshold,
    uint256 _checkpoint,
    string memory _elements
  ) internal returns (string memory) {
    string memory params = string.concat(
      '{"threshold":"',
      _vm.toString(_threshold),
      '","checkpoint":"',
      _vm.toString(_checkpoint),
      '","from":"flat","content":"',
      _elements,
      '"}'
    );
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "config_new", params);
    return string(rawResponse);
  }

  function newConfigWithCheckpointer(
    Vm _vm,
    address _checkpointer,
    uint16 _threshold,
    uint256 _checkpoint,
    string memory _elements
  ) internal returns (string memory) {
    string memory params = string.concat(
      '{"threshold":"',
      _vm.toString(_threshold),
      '","checkpoint":"',
      _vm.toString(_checkpoint),
      '","from":"flat","content":"',
      _elements,
      '","checkpointer":"',
      _vm.toString(_checkpointer),
      '"}'
    );
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "config_new", params);
    return string(rawResponse);
  }

  function toEncodedConfig(Vm _vm, string memory configJson) internal returns (bytes memory) {
    string memory params = string.concat('{"input":', configJson, "}");
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "config_encode", params);
    return (rawResponse);
  }

  function getImageHash(Vm _vm, string memory configJson) internal returns (bytes32) {
    string memory params = string.concat('{"input":', configJson, "}");
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "config_imageHash", params);
    bytes memory hexBytes = (rawResponse);
    return abi.decode(hexBytes, (bytes32));
  }

  // ----------------------------------------------------------------
  // signature
  // ----------------------------------------------------------------

  function toEncodedSignature(
    Vm _vm,
    string memory configJson,
    string memory signatures,
    bool _chainId
  ) internal returns (bytes memory) {
    // If you wanted no chainId, adapt the JSON, e.g. `"chainId":false`.
    string memory params = string.concat(
      '{"input":', configJson, ',"signatures":"', signatures, '","chainId":', _chainId ? "true" : "false", "}"
    );
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "signature_encode", params);
    return (rawResponse);
  }

  function toEncodedSignatureWithCheckpointerData(
    Vm _vm,
    string memory configJson,
    string memory signatures,
    bool _chainId,
    bytes memory checkpointerData
  ) internal returns (bytes memory) {
    string memory params = string.concat(
      '{"input":',
      configJson,
      ',"signatures":"',
      signatures,
      '","chainId":',
      _chainId ? "true" : "false",
      ',"checkpointerData":"',
      _vm.toString(checkpointerData),
      '"}'
    );
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "signature_encode", params);
    return (rawResponse);
  }

  function concatSignatures(Vm _vm, bytes[] memory _signatures) internal returns (bytes memory) {
    string memory arrayPrefix = '{"signatures":[';
    string memory arraySuffix = "]}";
    string memory arrayMid;
    for (uint256 i = 0; i < _signatures.length; i++) {
      arrayMid = string.concat(arrayMid, i == 0 ? '"' : ',"', _vm.toString(_signatures[i]), '"');
    }
    string memory params = string.concat(arrayPrefix, arrayMid, arraySuffix);
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "signature_concat", params);
    return (rawResponse);
  }

  // ----------------------------------------------------------------
  // session
  // ----------------------------------------------------------------

  function sessionEmpty(Vm _vm, address identitySigner) internal returns (string memory) {
    string memory params = string.concat('{"identitySigner":"', _vm.toString(identitySigner), '"}');
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "session_empty", params);
    return string(rawResponse);
  }

  function sessionEncodeTopology(Vm _vm, string memory topologyInput) internal returns (bytes memory) {
    string memory params = string.concat('{"sessionTopology":', topologyInput, "}");
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "session_encodeTopology", params);
    return rawResponse;
  }

  function sessionEncodeCallSignatures(
    Vm _vm,
    string memory topologyInput,
    string[] memory callSignatures,
    address[] memory explicitSigners,
    address[] memory implicitSigners
  ) internal returns (bytes memory) {
    string memory callSignaturesJson = _toJsonUnwrapped(_vm, callSignatures);
    string memory explicitSignersJson = _toJson(_vm, explicitSigners);
    string memory implicitSignersJson = _toJson(_vm, implicitSigners);
    string memory params = string.concat(
      '{"sessionTopology":',
      topologyInput,
      ',"callSignatures":',
      callSignaturesJson,
      ',"explicitSigners":',
      explicitSignersJson,
      ',"implicitSigners":',
      implicitSignersJson,
      "}"
    );
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "session_encodeCallSignatures", params);
    return rawResponse;
  }

  function sessionImageHash(Vm _vm, string memory sessionTopologyInput) internal returns (bytes32) {
    string memory params = string.concat('{"sessionTopology":', sessionTopologyInput, "}");
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "session_imageHash", params);
    return abi.decode(rawResponse, (bytes32));
  }

  // ----------------------------------------------------------------
  // session explicit
  // ----------------------------------------------------------------

  function sessionExplicitAdd(
    Vm _vm,
    string memory sessionInput,
    string memory topologyInput
  ) internal returns (string memory) {
    string memory params = string.concat('{"explicitSession":', sessionInput, ',"sessionTopology":', topologyInput, "}");
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "session_explicit_add", params);
    return string(rawResponse);
  }

  function sessionExplicitRemove(
    Vm _vm,
    address explicitSessionAddress,
    string memory topologyInput
  ) internal returns (string memory) {
    string memory params = string.concat(
      '{"explicitSessionAddress":"', _vm.toString(explicitSessionAddress), '","sessionTopology":', topologyInput, "}"
    );
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "session_explicit_remove", params);
    return string(rawResponse);
  }

  // ----------------------------------------------------------------
  // session implicit
  // ----------------------------------------------------------------

  function sessionImplicitAddBlacklistAddress(
    Vm _vm,
    string memory topologyInput,
    address addressToAdd
  ) internal returns (string memory) {
    string memory params =
      string.concat('{"sessionTopology":', topologyInput, ',"blacklistAddress":"', _vm.toString(addressToAdd), '"}');
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "session_implicit_addBlacklistAddress", params);
    return string(rawResponse);
  }

  function sessionImplicitRemoveBlacklistAddress(
    Vm _vm,
    string memory topologyInput,
    address addressToRemove
  ) internal returns (string memory) {
    string memory params =
      string.concat('{"sessionTopology":', topologyInput, ',"blacklistAddress":"', _vm.toString(addressToRemove), '"}');
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "session_implicit_removeBlacklistAddress", params);
    return string(rawResponse);
  }

  // ----------------------------------------------------------------
  // wallet
  // ----------------------------------------------------------------

  function getAddress(Vm _vm, bytes32 _configHash, address _factory, address _module) internal returns (address) {
    string memory params = string.concat(
      '{"imageHash":"',
      _vm.toString(_configHash),
      '","factory":"',
      _vm.toString(_factory),
      '","module":"',
      _vm.toString(_module),
      '"}'
    );
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "address_calculate", params);
    // Convert the raw response (a non-padded hex string) into an address
    string memory addrStr = _vm.toString(rawResponse);
    return parseAddress(addrStr);
  }

  function parseAddress(
    string memory _a
  ) internal pure returns (address) {
    bytes memory b = bytes(_a);
    require(b.length == 42, "Invalid address format"); // "0x" + 40 hex characters
    uint160 addr = 0;
    for (uint256 i = 2; i < 42; i += 2) {
      addr *= 256;
      uint8 b1 = uint8(b[i]);
      uint8 b2 = uint8(b[i + 1]);
      uint8 nib1;
      uint8 nib2;
      // Convert first hex character
      if (b1 >= 48 && b1 <= 57) {
        // '0'-'9'
        nib1 = b1 - 48;
      } else if (b1 >= 65 && b1 <= 70) {
        // 'A'-'F'
        nib1 = b1 - 55;
      } else if (b1 >= 97 && b1 <= 102) {
        // 'a'-'f'
        nib1 = b1 - 87;
      } else {
        revert("Invalid hex char");
      }
      // Convert second hex character
      if (b2 >= 48 && b2 <= 57) {
        nib2 = b2 - 48;
      } else if (b2 >= 65 && b2 <= 70) {
        nib2 = b2 - 55;
      } else if (b2 >= 97 && b2 <= 102) {
        nib2 = b2 - 87;
      } else {
        revert("Invalid hex char");
      }
      addr += uint160(nib1 * 16 + nib2);
    }
    return address(addr);
  }

  // ----------------------------------------------------------------
  // utils
  // ----------------------------------------------------------------

  function _toJson(Vm _vm, address[] memory _addresses) internal pure returns (string memory) {
    if (_addresses.length == 0) {
      return "[]";
    }
    string memory json = '["';
    for (uint256 i = 0; i < _addresses.length; i++) {
      json = string.concat(json, _vm.toString(_addresses[i]), '"');
      if (i < _addresses.length - 1) {
        json = string.concat(json, ',"');
      }
    }
    return string.concat(json, "]");
  }

  // For lists of strings
  function _toJson(Vm, string[] memory _strings) internal pure returns (string memory) {
    if (_strings.length == 0) {
      return "[]";
    }
    string memory json = '["';
    for (uint256 i = 0; i < _strings.length; i++) {
      json = string.concat(json, _strings[i], '"');
      if (i < _strings.length - 1) {
        json = string.concat(json, ',"');
      }
    }
    return string.concat(json, "]");
  }

  // For lists of JSONified strings
  function _toJsonUnwrapped(Vm, string[] memory _strings) internal pure returns (string memory) {
    if (_strings.length == 0) {
      return "[]";
    }
    string memory json = "[";
    for (uint256 i = 0; i < _strings.length; i++) {
      json = string.concat(json, _strings[i]);
      if (i < _strings.length - 1) {
        json = string.concat(json, ",");
      }
    }
    return string.concat(json, "]");
  }

  // ----------------------------------------------------------------
  // recovery
  // ----------------------------------------------------------------

  function recoveryHashFromLeaves(Vm _vm, string memory leaves) internal returns (bytes32) {
    string memory params = string.concat('{"leaves":"', leaves, '"}');
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "recovery_hashFromLeaves", params);
    return abi.decode(rawResponse, (bytes32));
  }

  function recoveryEncode(Vm _vm, string memory leaves) internal returns (bytes memory) {
    string memory params = string.concat('{"leaves":"', leaves, '"}');
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "recovery_encode", params);
    return rawResponse;
  }

  function recoveryTrim(Vm _vm, string memory leaves, address signer) internal returns (bytes memory) {
    string memory params = string.concat('{"leaves":"', leaves, '","signer":"', _vm.toString(signer), '"}');
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "recovery_trim", params);
    return rawResponse;
  }

  function recoveryHashEncoded(Vm _vm, bytes memory encoded) internal returns (bytes32) {
    string memory params = string.concat('{"encoded":"', _vm.toString(encoded), '"}');
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "recovery_hashEncoded", params);
    return abi.decode(rawResponse, (bytes32));
  }

  // ----------------------------------------------------------------
  // passkeys
  // ----------------------------------------------------------------

  struct PasskeyPublicKey {
    bytes32 x;
    bytes32 y;
    bool requireUserVerification;
    string credentialId;
    bytes32 metadataHash;
  }

  struct PasskeySignatureComponents {
    bytes32 r;
    bytes32 s;
    bytes authenticatorData;
    string clientDataJson;
  }

  function passkeysEncodeSignature(
    Vm _vm,
    PasskeyPublicKey memory _pk,
    PasskeySignatureComponents memory _sig,
    bool _embedMetadata
  ) internal returns (bytes memory) {
    string memory params = '{"x":"';
    params = string.concat(params, _vm.toString(_pk.x));
    params = string.concat(params, '","y":"', _vm.toString(_pk.y));
    params = string.concat(params, '","requireUserVerification":', _pk.requireUserVerification ? "true" : "false");
    if (bytes(_pk.credentialId).length > 0) {
      params = string.concat(params, ',"credentialId":"', _pk.credentialId, '"');
    } else if (_pk.metadataHash != bytes32(0)) {
      params = string.concat(params, ',"metadataHash":"', _vm.toString(_pk.metadataHash), '"');
    }
    params = string.concat(params, ',"r":"', _vm.toString(_sig.r));
    params = string.concat(params, '","s":"', _vm.toString(_sig.s));
    params = string.concat(params, '","authenticatorData":"', _vm.toString(_sig.authenticatorData));
    params = string.concat(params, '","clientDataJson":', _sig.clientDataJson);
    params = string.concat(params, ',"embedMetadata":', _embedMetadata ? "true" : "false", "}");

    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "passkeys_encodeSignature", params);
    return rawResponse;
  }

  function passkeysDecodeSignature(Vm _vm, bytes memory _encodedSignature) internal returns (string memory) {
    string memory params = string.concat('{"encodedSignature":"', _vm.toString(_encodedSignature), '"}');
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "passkeys_decodeSignature", params);
    return string(rawResponse);
  }

  function passkeysComputeRoot(Vm _vm, PasskeyPublicKey memory _pk) internal returns (bytes32) {
    string memory params = '{"x":"';
    params = string.concat(params, _vm.toString(_pk.x));
    params = string.concat(params, '","y":"', _vm.toString(_pk.y));
    params = string.concat(params, '","requireUserVerification":', _pk.requireUserVerification ? "true" : "false");
    if (bytes(_pk.credentialId).length > 0) {
      params = string.concat(params, ',"credentialId":"', _pk.credentialId, '"');
    } else if (_pk.metadataHash != bytes32(0)) {
      params = string.concat(params, ',"metadataHash":"', _vm.toString(_pk.metadataHash), '"');
    }
    params = string.concat(params, "}");

    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "passkeys_computeRoot", params);
    return abi.decode(rawResponse, (bytes32));
  }

  function passkeysValidateSignature(
    Vm _vm,
    bytes32 _challenge,
    PasskeyPublicKey memory _pk,
    PasskeySignatureComponents memory _sig
  ) internal returns (bool) {
    string memory params = '{"challenge":"';
    params = string.concat(params, _vm.toString(_challenge));
    params = string.concat(params, '","x":"', _vm.toString(_pk.x));
    params = string.concat(params, '","y":"', _vm.toString(_pk.y));
    params = string.concat(params, '","requireUserVerification":', _pk.requireUserVerification ? "true" : "false");
    if (bytes(_pk.credentialId).length > 0) {
      params = string.concat(params, ',"credentialId":"', _pk.credentialId, '"');
    } else if (_pk.metadataHash != bytes32(0)) {
      params = string.concat(params, ',"metadataHash":"', _vm.toString(_pk.metadataHash), '"');
    }
    params = string.concat(params, ',"r":"', _vm.toString(_sig.r));
    params = string.concat(params, '","s":"', _vm.toString(_sig.s));
    params = string.concat(params, '","authenticatorData":"', _vm.toString(_sig.authenticatorData));
    params = string.concat(params, '","clientDataJson":', _sig.clientDataJson, "}");

    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "passkeys_validateSignature", params);
    return abi.decode(rawResponse, (bool));
  }

}
