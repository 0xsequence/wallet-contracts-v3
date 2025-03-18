// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

import { Vm } from "forge-std/Vm.sol";

import { console2 } from "forge-std/console2.sol";
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

  // Hardcoded RPC URL
  string public constant RPC_URL_2 = "http://127.0.0.1:9998/rpc";

  // ----------------------------------------------------------------
  // devTools
  // ----------------------------------------------------------------

  function randomConfig(
    Vm _vm,
    uint256 _maxDepth,
    uint256 _seed,
    uint256 _minThresholdOnNested,
    string memory _checkpointer
  ) internal returns (string memory) {
    string memory params = string.concat(
      '{"maxDepth":',
      _vm.toString(_maxDepth),
      ',"seed":"',
      _vm.toString(_seed),
      '","minThresholdOnNested":',
      _vm.toString(_minThresholdOnNested),
      ',"checkpointer":"',
      _checkpointer,
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

    bytes memory rawResponse2 = _vm.rpc(RPC_URL_2, "payload_toPacked", params);

    // Encode the raw response to JSON with key `packedPayload`:
    string memory rawResponseJson = string.concat('{"packedPayload":"', _vm.toString(rawResponse), '"}');
    string memory rawResponse2Json = string.concat('{"packedPayload":"', _vm.toString(rawResponse2), '"}');

    _vm.writeJson(rawResponseJson, "./tmp/payload_toPacked.json");
    _vm.writeJson(rawResponse2Json, "./tmp/payload_toPacked2.json");

    require(keccak256(rawResponse) == keccak256(rawResponse2), "Raw payload to packed responses are not equal");

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
    bytes memory rawResponse2 = _vm.rpc(RPC_URL_2, "payload_hashFor", params);

    _vm.writeJson(string(rawResponse), "./tmp/payload_hashFor.json");
    _vm.writeJson(string(rawResponse2), "./tmp/payload_hashFor2.json");

    require(keccak256(rawResponse) == keccak256(rawResponse2), "Raw payload hash for responses are not equal");

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
    // console2.logBytes(rawResponse);

    bytes memory rawResponse2 = _vm.rpc(RPC_URL_2, "config_new", params);
    // console2.logBytes(rawResponse2);

    _vm.writeJson(string(rawResponse), "./tmp/config_new.json");
    _vm.writeJson(string(rawResponse2), "./tmp/config_new2.json");

    require(keccak256(rawResponse) == keccak256(rawResponse2), "Raw config new responses are not equal");

    return string(rawResponse);
  }

  function toEncodedConfig(Vm _vm, string memory configJson) internal returns (bytes memory) {
    console2.log("toEncodedConfig");

    string memory params = string.concat('{"input":', configJson, "}");
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "config_encode", params);
    console2.logBytes(rawResponse);

    bytes memory rawResponse2 = _vm.rpc(RPC_URL_2, "config_encode", params);
    console2.logBytes(rawResponse2);

    _vm.writeJson(string(rawResponse), "./tmp/config_encode.json");
    _vm.writeJson(string(rawResponse2), "./tmp/config_encode2.json");

    require(keccak256(rawResponse) == keccak256(rawResponse2), "Raw config encode responses are not equal");
    return (rawResponse);
  }

  function getImageHash(Vm _vm, string memory configJson) internal returns (bytes32) {
    console2.log("getImageHash");

    string memory params = string.concat('{"input":', configJson, "}");
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "config_imageHash", params);
    console2.logBytes(rawResponse);

    bytes memory rawResponse2 = _vm.rpc(RPC_URL_2, "config_imageHash", params);
    console2.logBytes(rawResponse2);

    // Encode the raw response to JSON with key `imageHash`:
    string memory rawResponseJson = string.concat('{"imageHash":"', _vm.toString(rawResponse), '"}');
    string memory rawResponse2Json = string.concat('{"imageHash":"', _vm.toString(rawResponse2), '"}');

    _vm.writeJson(rawResponseJson, "./tmp/image_hash.json");
    _vm.writeJson(rawResponse2Json, "./tmp/image_hash2.json");

    require(keccak256(rawResponse) == keccak256(rawResponse2), "Raw image hash responses are not equal");

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
    console2.logBytes(rawResponse);

    bytes memory rawResponse2 = _vm.rpc(RPC_URL_2, "signature_encode", params);
    console2.logBytes(rawResponse2);

    // Encode the raw response to JSON with key `sig`:
    string memory rawResponseJson = string.concat('{"sig":"', _vm.toString(rawResponse), '"}');
    string memory rawResponse2Json = string.concat('{"sig":"', _vm.toString(rawResponse2), '"}');

    _vm.writeJson(rawResponseJson, "./tmp/signature_encode.json");
    _vm.writeJson(rawResponse2Json, "./tmp/signature_encode2.json");

    require(keccak256(rawResponse) == keccak256(rawResponse2), "Raw signature encode responses are not equal");

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

    bytes memory rawResponse2 = _vm.rpc(RPC_URL_2, "signature_concat", params);

    _vm.writeJson(string(rawResponse), "./tmp/signature_concat.json");
    _vm.writeJson(string(rawResponse2), "./tmp/signature_concat2.json");

    require(keccak256(rawResponse) == keccak256(rawResponse2), "Raw signature concat responses are not equal");

    return (rawResponse);
  }

  // ----------------------------------------------------------------
  // permission
  // ----------------------------------------------------------------

  function toPackedPermission(Vm _vm, string memory permissionJson) internal returns (bytes memory) {
    string memory params = string.concat('{"permission":', permissionJson, "}");
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "permission_toPacked", params);

    bytes memory rawResponse2 = _vm.rpc(RPC_URL_2, "permission_toPacked", params);

    _vm.writeJson(string(rawResponse), "./tmp/permission_toPacked.json");
    _vm.writeJson(string(rawResponse2), "./tmp/permission_toPacked2.json");

    require(keccak256(rawResponse) == keccak256(rawResponse2), "Raw permission to packed responses are not equal");

    return (rawResponse);
  }

  function toPackedSessionPermission(Vm _vm, string memory sessionJson) internal returns (bytes memory) {
    string memory params = string.concat('{"sessionPermission":', sessionJson, "}");
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "permission_toPackedSession", params);

    bytes memory rawResponse2 = _vm.rpc(RPC_URL_2, "permission_toPackedSession", params);

    _vm.writeJson(string(rawResponse), "./tmp/permission_toPackedSession.json");
    _vm.writeJson(string(rawResponse2), "./tmp/permission_toPackedSession2.json");

    require(
      keccak256(rawResponse) == keccak256(rawResponse2), "Raw permission to packed session responses are not equal"
    );

    return (rawResponse);
  }

  // ----------------------------------------------------------------
  // session
  // ----------------------------------------------------------------

  function sessionEmpty(Vm _vm, address identitySigner) internal returns (string memory) {
    string memory params = string.concat('{"identitySigner":"', _vm.toString(identitySigner), '"}');
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "session_empty", params);
    bytes memory rawResponse2 = _vm.rpc(RPC_URL_2, "session_empty", params);

    _vm.writeJson(string(rawResponse), "./tmp/session_empty.json");
    // _vm.writeJson(string(rawResponse2), "./tmp/session_empty2.json");

    // require(keccak256(rawResponse) == keccak256(rawResponse2), "Raw session empty responses are not equal");

    return string(rawResponse);
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
    bytes memory rawResponse2 = _vm.rpc(RPC_URL_2, "session_encodeCallSignatures", params);

    _vm.writeJson(string(rawResponse), "./tmp/session_encodeCallSignatures.json");
    _vm.writeJson(string(rawResponse2), "./tmp/session_encodeCallSignatures2.json");

    require(
      keccak256(rawResponse) == keccak256(rawResponse2), "Raw session encode call signatures responses are not equal"
    );

    return rawResponse;
  }

  function sessionImageHash(Vm _vm, string memory sessionTopologyInput) internal returns (bytes32) {
    string memory params = string.concat('{"sessionTopology":', sessionTopologyInput, "}");
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "session_imageHash", params);

    bytes memory rawResponse2 = _vm.rpc(RPC_URL_2, "session_imageHash", params);

    _vm.writeJson(string(rawResponse), "./tmp/session_imageHash.json");
    _vm.writeJson(string(rawResponse2), "./tmp/session_imageHash2.json");

    require(keccak256(rawResponse) == keccak256(rawResponse2), "Raw session image hash responses are not equal");

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

    bytes memory rawResponse2 = _vm.rpc(RPC_URL_2, "session_explicit_add", params);

    _vm.writeJson(string(rawResponse), "./tmp/session_explicit_add.json");
    _vm.writeJson(string(rawResponse2), "./tmp/session_explicit_add2.json");

    require(keccak256(rawResponse) == keccak256(rawResponse2), "Raw session explicit add responses are not equal");

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

    bytes memory rawResponse2 = _vm.rpc(RPC_URL_2, "session_explicit_remove", params);

    _vm.writeJson(string(rawResponse), "./tmp/session_explicit_remove.json");
    _vm.writeJson(string(rawResponse2), "./tmp/session_explicit_remove2.json");

    require(keccak256(rawResponse) == keccak256(rawResponse2), "Raw session explicit remove responses are not equal");

    return string(rawResponse);
  }

  function sessionExplicitEncodeCallSignature(
    Vm _vm,
    string memory signatureInput,
    uint8 permissionIdx
  ) internal returns (bytes memory) {
    string memory params =
      string.concat('{"signature":"', signatureInput, '","permissionIndex":', _vm.toString(permissionIdx), "}");
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "session_explicit_encodeCallSignature", params);

    bytes memory rawResponse2 = _vm.rpc(RPC_URL_2, "session_explicit_encodeCallSignature", params);

    _vm.writeJson(string(rawResponse), "./tmp/session_explicit_encodeCallSignature.json");
    _vm.writeJson(string(rawResponse2), "./tmp/session_explicit_encodeCallSignature2.json");

    require(
      keccak256(rawResponse) == keccak256(rawResponse2),
      "Raw session explicit encode call signature responses are not equal"
    );

    return rawResponse;
  }

  // ----------------------------------------------------------------
  // session implicit
  // ----------------------------------------------------------------

  function sessionImplicitAddBlacklistAddress(
    Vm _vm,
    string memory implicitSessionJson,
    address addressToAdd
  ) internal returns (string memory) {
    string memory params = string.concat(
      '{"sessionConfiguration":', implicitSessionJson, ',"blacklistAddress":"', _vm.toString(addressToAdd), '"}'
    );
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "session_implicit_addBlacklistAddress", params);

    bytes memory rawResponse2 = _vm.rpc(RPC_URL_2, "session_implicit_addBlacklistAddress", params);

    _vm.writeJson(string(rawResponse), "./tmp/session_implicit_addBlacklistAddress.json");
    _vm.writeJson(string(rawResponse2), "./tmp/session_implicit_addBlacklistAddress2.json");

    require(
      keccak256(rawResponse) == keccak256(rawResponse2),
      "Raw session implicit add blacklist address responses are not equal"
    );

    return string(rawResponse);
  }

  function sessionImplicitRemoveBlacklistAddress(
    Vm _vm,
    string memory implicitSessionJson,
    address addressToRemove
  ) internal returns (string memory) {
    string memory params = string.concat(
      '{"sessionConfiguration":', implicitSessionJson, ',"blacklistAddress":"', _vm.toString(addressToRemove), '"}'
    );
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "session_implicit_removeBlacklistAddress", params);

    bytes memory rawResponse2 = _vm.rpc(RPC_URL_2, "session_implicit_removeBlacklistAddress", params);

    _vm.writeJson(string(rawResponse), "./tmp/session_implicit_removeBlacklistAddress.json");
    _vm.writeJson(string(rawResponse2), "./tmp/session_implicit_removeBlacklistAddress2.json");

    require(
      keccak256(rawResponse) == keccak256(rawResponse2),
      "Raw session implicit remove blacklist address responses are not equal"
    );

    return string(rawResponse);
  }

  function sessionImplicitEncodeCallSignature(
    Vm _vm,
    string memory sessionSignature,
    string memory globalSignature,
    string memory attestationJson
  ) internal returns (bytes memory) {
    string memory params = string.concat(
      '{"sessionSignature":"',
      sessionSignature,
      '",',
      '"globalSignature":"',
      globalSignature,
      '",',
      '"attestation":',
      attestationJson,
      "}"
    );
    bytes memory rawResponse = _vm.rpc(rpcURL(_vm), "session_implicit_encodeCallSignature", params);

    bytes memory rawResponse2 = _vm.rpc(RPC_URL_2, "session_implicit_encodeCallSignature", params);

    _vm.writeJson(string(rawResponse), "./tmp/session_implicit_encodeCallSignature.json");
    _vm.writeJson(string(rawResponse2), "./tmp/session_implicit_encodeCallSignature2.json");

    require(
      keccak256(rawResponse) == keccak256(rawResponse2),
      "Raw session implicit encode call signature responses are not equal"
    );

    return rawResponse;
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

}
