// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Test, Vm } from "forge-std/Test.sol";
import { console } from "forge-std/console.sol";

import { Passkeys } from "../../../src/extensions/passkeys/Passkeys.sol";
import { WebAuthn } from "../../../src/utils/WebAuthn.sol";
import { PrimitivesRPC } from "../../utils/PrimitivesRPC.sol";
import { AdvTest } from "../../utils/TestUtils.sol";

// Harness contract to expose internal functions for testing
contract PasskeysImp is Passkeys {

  function rootForPasskeyPub(
    bool _requireUserVerification,
    bytes32 _x,
    bytes32 _y,
    bytes32 _metadata
  ) external pure returns (bytes32) {
    return _rootForPasskey(_requireUserVerification, _x, _y, _metadata);
  }

  function decodeSignaturePub(
    bytes calldata _signature
  )
    external
    pure
    returns (
      WebAuthn.WebAuthnAuth memory _webAuthnAuth,
      bool _requireUserVerification,
      bytes32 _x,
      bytes32 _y,
      bytes32 _metadata
    )
  {
    return _decodeSignature(_signature);
  }

}

address constant P256_VERIFIER = 0x000000000000D01eA45F9eFD5c54f037Fa57Ea1a;
bytes constant P256_VERIFIER_RUNTIME_CODE =
  hex"3d604052610216565b60008060006ffffffffeffffffffffffffffffffffff60601b19808687098188890982838389096004098384858485093d510985868b8c096003090891508384828308850385848509089650838485858609600809850385868a880385088509089550505050808188880960020991505093509350939050565b81513d83015160408401516ffffffffeffffffffffffffffffffffff60601b19808384098183840982838388096004098384858485093d510985868a8b096003090896508384828308850385898a09089150610102848587890960020985868787880960080987038788878a0387088c0908848b523d8b015260408a0152565b505050505050505050565b81513d830151604084015185513d87015160408801518361013d578287523d870182905260408701819052610102565b80610157578587523d870185905260408701849052610102565b6ffffffffeffffffffffffffffffffffff60601b19808586098183840982818a099850828385830989099750508188830383838809089450818783038384898509870908935050826101be57836101be576101b28a89610082565b50505050505050505050565b808485098181860982828a09985082838a8b0884038483860386898a09080891506102088384868a0988098485848c09860386878789038f088a0908848d523d8d015260408c0152565b505050505050505050505050565b6020357fffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325513d6040357f7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a88111156102695782035b60206108005260206108205260206108405280610860526002830361088052826108a0526ffffffffeffffffffffffffffffffffff60601b198060031860205260603560803560203d60c061080060055afa60203d1416837f5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b8585873d5189898a09080908848384091484831085851016888710871510898b108b151016609f3611161616166103195760206080f35b60809182523d820152600160c08190527f6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2966102009081527f4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f53d909101526102405261038992509050610100610082565b610397610200610400610082565b6103a7610100608061018061010d565b6103b7610200608061028061010d565b6103c861020061010061030061010d565b6103d961020061018061038061010d565b6103e9610400608061048061010d565b6103fa61040061010061050061010d565b61040b61040061018061058061010d565b61041c61040061020061060061010d565b61042c610600608061068061010d565b61043d61060061010061070061010d565b61044e61060061018061078061010d565b81815182350982825185098283846ffffffffeffffffffffffffffffffffff60601b193d515b82156105245781858609828485098384838809600409848586848509860986878a8b096003090885868384088703878384090886878887880960080988038889848b03870885090887888a8d096002098882830996508881820995508889888509600409945088898a8889098a098a8b86870960030908935088898687088a038a868709089a5088898284096002099950505050858687868709600809870387888b8a0386088409089850505050505b61018086891b60f71c16610600888a1b60f51c16176040810151801585151715610564578061055357506105fe565b81513d8301519750955093506105fe565b83858609848283098581890986878584098b0991508681880388858851090887838903898a8c88093d8a015109089350836105b957806105b9576105a9898c8c610008565b9a509b50995050505050506105fe565b8781820988818309898285099350898a8586088b038b838d038d8a8b0908089b50898a8287098b038b8c8f8e0388088909089c5050508788868b098209985050505050505b5082156106af5781858609828485098384838809600409848586848509860986878a8b096003090885868384088703878384090886878887880960080988038889848b03870885090887888a8d096002098882830996508881820995508889888509600409945088898a8889098a098a8b86870960030908935088898687088a038a868709089a5088898284096002099950505050858687868709600809870387888b8a0386088409089850505050505b61018086891b60f51c16610600888a1b60f31c161760408101518015851517156106ef57806106de5750610789565b81513d830151975095509350610789565b83858609848283098581890986878584098b0991508681880388858851090887838903898a8c88093d8a01510908935083610744578061074457610734898c8c610008565b9a509b5099505050505050610789565b8781820988818309898285099350898a8586088b038b838d038d8a8b0908089b50898a8287098b038b8c8f8e0388088909089c5050508788868b098209985050505050505b50600488019760fb19016104745750816107a2573d6040f35b81610860526002810361088052806108a0523d3d60c061080060055afa898983843d513d510987090614163d525050505050505050503d3df3fea264697066735822122063ce32ec0e56e7893a1f6101795ce2e38aca14dd12adb703c71fe3bee27da71e64736f6c634300081a0033";

contract PasskeysTest is AdvTest {

  PasskeysImp public passkeysImp;

  function setUp() public {
    passkeysImp = new PasskeysImp();
  }

  // --- _rootForPasskey Tests ---

  // Fuzz test for _rootForPasskey using metadataHash
  function test_rootForPasskey_metadataHash(
    bool requireUserVerification,
    bytes32 x,
    bytes32 y,
    bytes32 metadataHash
  ) public {
    bytes32 contractRoot = passkeysImp.rootForPasskeyPub(requireUserVerification, x, y, metadataHash);

    PrimitivesRPC.PasskeyPublicKey memory pkParams;
    pkParams.x = x;
    pkParams.y = y;
    pkParams.requireUserVerification = requireUserVerification;
    pkParams.metadataHash = metadataHash;

    bytes32 rpcRoot = PrimitivesRPC.passkeysComputeRoot(vm, pkParams);

    assertEq(contractRoot, rpcRoot, "Contract root hash should match RPC root hash using metadataHash");
  }

  // Fuzz test for _rootForPasskey using credentialId
  function test_rootForPasskey_credentialId(
    bool requireUserVerification,
    bytes32 x,
    bytes32 y,
    uint256 credentialIdSeed
  ) public {
    string memory credentialId = generateRandomString(credentialIdSeed);
    vm.assume(bytes(credentialId).length > 0);
    bytes32 expectedMetadataNodeHash = keccak256(bytes(credentialId));
    bytes32 contractRoot = passkeysImp.rootForPasskeyPub(requireUserVerification, x, y, expectedMetadataNodeHash);

    PrimitivesRPC.PasskeyPublicKey memory pkParams;
    pkParams.x = x;
    pkParams.y = y;
    pkParams.requireUserVerification = requireUserVerification;
    pkParams.credentialId = credentialId;

    bytes32 rpcRoot = PrimitivesRPC.passkeysComputeRoot(vm, pkParams);

    assertEq(contractRoot, rpcRoot, "Contract root hash should match RPC root hash using credentialId");
  }

  // Fuzz test for _rootForPasskey without metadata
  function test_rootForPasskey_noMetadata(bool requireUserVerification, bytes32 x, bytes32 y) public {
    bytes32 noMetadataHash = bytes32(0);
    bytes32 contractRoot = passkeysImp.rootForPasskeyPub(requireUserVerification, x, y, noMetadataHash);

    PrimitivesRPC.PasskeyPublicKey memory pkParams;
    pkParams.x = x;
    pkParams.y = y;
    pkParams.requireUserVerification = requireUserVerification;

    bytes32 rpcRoot = PrimitivesRPC.passkeysComputeRoot(vm, pkParams);

    assertEq(contractRoot, rpcRoot, "Contract root hash should match RPC root hash without metadata");
  }

  struct test_decodeSignature_packed_params {
    bool requireUserVerification;
    bytes32 x;
    bytes32 y;
    bytes32 r;
    bytes32 s;
    bytes authenticatorData;
    bytes challengeBytes;
    bytes32 metadataHash;
    bool embedMetadata;
    uint256 typeValueSeed;
    uint256 originValueSeed;
  }

  struct test_decodeSignature_packed_vars {
    string clientDataJSON;
    uint256 challengeIndex;
    uint256 typeIndex;
    PrimitivesRPC.PasskeyPublicKey pkParams;
    PrimitivesRPC.PasskeySignatureComponents sigParams;
    bytes encodedSignature;
    WebAuthn.WebAuthnAuth decodedAuth;
    bool decodedRUV;
    bytes32 decodedX;
    bytes32 decodedY;
    bytes32 decodedMetadata;
    string typeValue;
    string originValue;
  }

  function test_decodeSignature_packed(
    test_decodeSignature_packed_params memory params
  ) public {
    vm.assume(params.authenticatorData.length > 0 && params.authenticatorData.length <= 65535);
    vm.assume(params.challengeBytes.length > 0 && params.challengeBytes.length < 100);
    vm.assume(params.r != bytes32(0));
    vm.assume(params.s != bytes32(0));

    if (params.embedMetadata) {
      vm.assume(params.metadataHash != bytes32(0));
    } else {
      params.metadataHash = bytes32(0);
    }

    test_decodeSignature_packed_vars memory vars;

    string memory base64UrlChallenge = vm.toBase64URL(params.challengeBytes);

    vars.typeValue = generateRandomString(params.typeValueSeed);
    vars.originValue = generateRandomString(params.originValueSeed);

    vars.clientDataJSON = string.concat(
      '{"type":"', vars.typeValue, '","challenge":"', base64UrlChallenge, '","origin":"', vars.originValue, '"}'
    );

    vars.typeIndex = 1;
    vars.challengeIndex = 11 + bytes(vars.typeValue).length;

    vars.pkParams.x = params.x;
    vars.pkParams.y = params.y;
    vars.pkParams.requireUserVerification = params.requireUserVerification;
    if (params.embedMetadata || params.metadataHash != bytes32(0)) {
      vars.pkParams.metadataHash = params.metadataHash;
    }

    vars.sigParams.r = params.r;
    vars.sigParams.s = params.s;
    vars.sigParams.authenticatorData = params.authenticatorData;
    vars.sigParams.clientDataJson = vars.clientDataJSON;

    vars.encodedSignature =
      PrimitivesRPC.passkeysEncodeSignature(vm, vars.pkParams, vars.sigParams, params.embedMetadata);

    (vars.decodedAuth, vars.decodedRUV, vars.decodedX, vars.decodedY, vars.decodedMetadata) =
      passkeysImp.decodeSignaturePub(vars.encodedSignature);

    assertEq(vars.decodedRUV, params.requireUserVerification, "Packed Decoded RUV mismatch");
    assertEq(vars.decodedY, params.y, "Packed Decoded Y mismatch");
    assertEq(vars.decodedX, params.x, "Packed Decoded X mismatch");
    assertEq(
      keccak256(vars.decodedAuth.authenticatorData),
      keccak256(params.authenticatorData),
      "Packed Decoded authenticatorData mismatch"
    );
    assertEq(
      keccak256(bytes(vars.decodedAuth.clientDataJSON)),
      keccak256(bytes(vars.clientDataJSON)),
      "Packed Decoded clientDataJSON mismatch"
    );
    assertEq(vars.decodedAuth.r, params.r, "Packed Decoded R mismatch");
    assertEq(vars.decodedAuth.s, params.s, "Packed Decoded S mismatch");
    assertEq(vars.decodedAuth.challengeIndex, vars.challengeIndex, "Packed Decoded challengeIndex mismatch");
    assertEq(vars.decodedAuth.typeIndex, vars.typeIndex, "Packed Decoded typeIndex mismatch");
    assertEq(vars.decodedMetadata, params.metadataHash, "Packed Decoded metadata mismatch");
  }

  struct test_decodeSignature_abi_params {
    bool requireUserVerification;
    bytes32 x;
    bytes32 y;
    bytes32 r;
    bytes32 s;
    bytes authenticatorData;
    bytes challengeBytes;
    bytes32 metadataHash;
    bool includeMetadata;
    uint256 typeValueSeed;
    uint256 originValueSeed;
  }

  struct test_decodeSignature_abi_vars {
    string clientDataJSON;
    uint256 challengeIndex;
    uint256 typeIndex;
    WebAuthn.WebAuthnAuth authInput;
    bytes encodedTuple;
    bytes1 flagByte;
    bytes encodedSignatureWithFlag;
    WebAuthn.WebAuthnAuth decodedAuth;
    bool decodedRUV;
    bytes32 decodedX;
    bytes32 decodedY;
    bytes32 decodedMetadata;
    string typeValue;
    string originValue;
  }

  // Fuzz test for _decodeSignature using the ABI encoded fallback format
  function test_decodeSignature_abi(
    test_decodeSignature_abi_params memory params
  ) public view {
    // --- Setup & Assumptions ---
    vm.assume(params.authenticatorData.length > 0 && params.authenticatorData.length <= 65535);
    vm.assume(params.challengeBytes.length > 0 && params.challengeBytes.length < 100);
    vm.assume(params.r != bytes32(0));
    vm.assume(params.s != bytes32(0));

    if (params.includeMetadata) {
      vm.assume(params.metadataHash != bytes32(0));
    } else {
      params.metadataHash = bytes32(0);
    }

    test_decodeSignature_abi_vars memory vars;

    string memory base64UrlChallenge = vm.toBase64URL(params.challengeBytes);
    vars.typeValue = generateRandomString(params.typeValueSeed);
    vars.originValue = generateRandomString(params.originValueSeed);

    vars.clientDataJSON = string.concat(
      '{"type":"', vars.typeValue, '","challenge":"', base64UrlChallenge, '","origin":"', vars.originValue, '"}'
    );
    vars.challengeIndex = 11 + bytes(vars.typeValue).length;
    vars.typeIndex = 1;

    // --- ABI Encoding ---
    vars.authInput = WebAuthn.WebAuthnAuth({
      authenticatorData: params.authenticatorData,
      clientDataJSON: vars.clientDataJSON,
      challengeIndex: vars.challengeIndex,
      typeIndex: vars.typeIndex,
      r: params.r,
      s: params.s
    });

    vars.encodedTuple =
      abi.encode(vars.authInput, params.requireUserVerification, params.x, params.y, params.metadataHash);
    vars.flagByte = bytes1(uint8(0x20) | (params.includeMetadata ? uint8(0x40) : uint8(0x00)));
    vars.encodedSignatureWithFlag = abi.encodePacked(vars.flagByte, vars.encodedTuple);

    // --- Contract Decoding ---
    (vars.decodedAuth, vars.decodedRUV, vars.decodedX, vars.decodedY, vars.decodedMetadata) =
      passkeysImp.decodeSignaturePub(vars.encodedSignatureWithFlag);

    // --- Assertions ---
    assertEq(vars.decodedRUV, params.requireUserVerification, "ABI Decoded RUV mismatch");
    assertEq(vars.decodedX, params.x, "ABI Decoded X mismatch");
    assertEq(vars.decodedY, params.y, "ABI Decoded Y mismatch");
    assertEq(
      keccak256(vars.decodedAuth.authenticatorData),
      keccak256(params.authenticatorData),
      "ABI Decoded authenticatorData mismatch"
    );
    assertEq(
      keccak256(bytes(vars.decodedAuth.clientDataJSON)),
      keccak256(bytes(vars.clientDataJSON)),
      "ABI Decoded clientDataJSON mismatch"
    );
    assertEq(vars.decodedAuth.r, params.r, "ABI Decoded R mismatch");
    assertEq(vars.decodedAuth.s, params.s, "ABI Decoded S mismatch");
    assertEq(vars.decodedAuth.challengeIndex, vars.challengeIndex, "ABI Decoded challengeIndex mismatch");
    assertEq(vars.decodedAuth.typeIndex, vars.typeIndex, "ABI Decoded typeIndex mismatch");
    assertEq(vars.decodedMetadata, params.metadataHash, "ABI Decoded metadata mismatch");
  }

  struct RecoverParams {
    uint256 pkSeed;
    bytes32 digest;
    bool requireUserVerification;
    bytes32 metadataHash;
    bool embedMetadata;
    uint256 originValueSeed;
    bytes32 rpIdHash;
    uint32 signCount;
  }

  struct recoverSapientSignatureCompact_valid_vars {
    Vm.Wallet wallet;
    uint256 pubX;
    uint256 pubY;
    PrimitivesRPC.PasskeyPublicKey pkParams;
    string base64UrlChallenge;
    string typeValue;
    string originValue;
    string clientDataJSON;
    PrimitivesRPC.PasskeySignatureComponents sigParams;
    bytes32 clientDataJSONHash;
    bytes32 messageHash;
    bytes encodedSignature;
    bytes32 expectedRoot;
    bytes32 recoveredRoot;
    bytes generatedAuthenticatorData;
  }

  function test_recoverSapientSignatureCompact_valid(
    RecoverParams memory params
  ) public {
    vm.etch(P256_VERIFIER, P256_VERIFIER_RUNTIME_CODE);

    recoverSapientSignatureCompact_valid_vars memory vars;

    params.pkSeed = boundP256Pk(params.pkSeed);
    vars.wallet = vm.createWallet(params.pkSeed);

    if (params.embedMetadata) {
      vm.assume(params.metadataHash != bytes32(0));
    } else {
      params.metadataHash = bytes32(0);
    }

    (vars.pubX, vars.pubY) = vm.publicKeyP256(vars.wallet.privateKey);
    vars.pkParams.x = bytes32(vars.pubX);
    vars.pkParams.y = bytes32(vars.pubY);
    vars.pkParams.requireUserVerification = params.requireUserVerification;
    vars.pkParams.metadataHash = params.metadataHash;
    vars.pkParams.credentialId = "";

    uint8 flags = 0x01;
    if (params.requireUserVerification) {
      flags |= 0x04;
    }

    vars.generatedAuthenticatorData = abi.encodePacked(params.rpIdHash, flags, params.signCount);

    string memory raw = vm.toBase64URL(abi.encodePacked(params.digest));
    if (bytes(raw)[bytes(raw).length - 1] == "=") {
      assembly {
        mstore(raw, sub(mload(raw), 1))
      }
    }
    vars.base64UrlChallenge = raw;
    vars.typeValue = "webauthn.get";
    vars.originValue = generateRandomString(params.originValueSeed);
    vm.assume(bytes(vars.originValue).length > 0);

    vars.clientDataJSON = string.concat(
      '{"type":"', vars.typeValue, '","challenge":"', vars.base64UrlChallenge, '","origin":"', vars.originValue, '"}'
    );
    vars.sigParams.clientDataJson = vars.clientDataJSON;
    vars.sigParams.authenticatorData = vars.generatedAuthenticatorData;

    vars.clientDataJSONHash = sha256(bytes(vars.clientDataJSON));
    vars.messageHash = sha256(abi.encodePacked(vars.generatedAuthenticatorData, vars.clientDataJSONHash));
    (bytes32 rVal, bytes32 sVal) = vm.signP256(vars.wallet.privateKey, vars.messageHash);

    bytes32 halfN = bytes32(0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8);
    if (sVal > halfN) {
      sVal = bytes32(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 - uint256(sVal));
    }

    vars.sigParams.r = bytes32(rVal);
    vars.sigParams.s = bytes32(sVal);
    vars.encodedSignature =
      PrimitivesRPC.passkeysEncodeSignature(vm, vars.pkParams, vars.sigParams, params.embedMetadata);

    vars.expectedRoot = PrimitivesRPC.passkeysComputeRoot(vm, vars.pkParams);

    vars.recoveredRoot = passkeysImp.recoverSapientSignatureCompact(params.digest, vars.encodedSignature);
    assertEq(vars.recoveredRoot, vars.expectedRoot, "Recovered root should match expected root");
  }

  struct recoverSapientSignatureCompact_invalidSignature_vars {
    Vm.Wallet wallet;
    Vm.Wallet wrongWallet;
    uint256 pubX;
    uint256 pubY;
    PrimitivesRPC.PasskeyPublicKey pkParams;
    string base64UrlChallenge;
    string typeValue;
    string originValue;
    string clientDataJSON;
    PrimitivesRPC.PasskeySignatureComponents sigParams;
    bytes32 clientDataJSONHash;
    bytes32 messageHash;
    bytes encodedSignature;
    uint256 challengeIndex;
    uint256 typeIndex;
    WebAuthn.WebAuthnAuth expectedAuthStruct;
    bytes generatedAuthenticatorData;
  }

  function test_recoverSapientSignatureCompact_invalidSignature(RecoverParams memory params, uint256 wrongSeed) public {
    vm.etch(P256_VERIFIER, P256_VERIFIER_RUNTIME_CODE);

    recoverSapientSignatureCompact_invalidSignature_vars memory vars;

    params.pkSeed = boundP256Pk(params.pkSeed);
    wrongSeed = boundP256Pk(wrongSeed);
    vm.assume(wrongSeed != params.pkSeed);

    vars.wallet = vm.createWallet(params.pkSeed);
    vars.wrongWallet = vm.createWallet(wrongSeed);

    if (params.embedMetadata) {
      vm.assume(params.metadataHash != bytes32(0));
    } else {
      params.metadataHash = bytes32(0);
    }

    (vars.pubX, vars.pubY) = vm.publicKeyP256(vars.wallet.privateKey);
    vars.pkParams.x = bytes32(vars.pubX);
    vars.pkParams.y = bytes32(vars.pubY);
    vars.pkParams.requireUserVerification = params.requireUserVerification;
    vars.pkParams.metadataHash = params.metadataHash;
    vars.pkParams.credentialId = "";

    uint8 flags = 0x01;
    if (params.requireUserVerification) {
      flags |= 0x04;
    }
    vars.generatedAuthenticatorData = abi.encodePacked(params.rpIdHash, flags, params.signCount);

    string memory raw = vm.toBase64URL(abi.encodePacked(params.digest));
    if (bytes(raw)[bytes(raw).length - 1] == "=") {
      assembly {
        mstore(raw, sub(mload(raw), 1))
      }
    }
    vars.base64UrlChallenge = raw;
    vars.typeValue = "webauthn.get";
    vars.originValue = generateRandomString(params.originValueSeed);
    vm.assume(bytes(vars.originValue).length > 0);

    vars.clientDataJSON = string.concat(
      '{"type":"', vars.typeValue, '","challenge":"', vars.base64UrlChallenge, '","origin":"', vars.originValue, '"}'
    );
    vars.sigParams.clientDataJson = vars.clientDataJSON;
    vars.sigParams.authenticatorData = vars.generatedAuthenticatorData;

    vars.clientDataJSONHash = sha256(bytes(vars.clientDataJSON));
    vars.messageHash = sha256(abi.encodePacked(vars.generatedAuthenticatorData, vars.clientDataJSONHash));
    (vars.sigParams.r, vars.sigParams.s) = vm.signP256(vars.wrongWallet.privateKey, vars.messageHash);

    vars.encodedSignature =
      PrimitivesRPC.passkeysEncodeSignature(vm, vars.pkParams, vars.sigParams, params.embedMetadata);

    vars.challengeIndex = LibString.indexOf(vars.clientDataJSON, '"challenge":"');
    vars.typeIndex = LibString.indexOf(vars.clientDataJSON, '"type":"');

    vars.expectedAuthStruct = WebAuthn.WebAuthnAuth({
      authenticatorData: vars.generatedAuthenticatorData,
      clientDataJSON: vars.clientDataJSON,
      challengeIndex: vars.challengeIndex,
      typeIndex: vars.typeIndex,
      r: vars.sigParams.r,
      s: vars.sigParams.s
    });

    vm.expectRevert(
      abi.encodeWithSelector(
        Passkeys.InvalidPasskeySignature.selector,
        vars.expectedAuthStruct,
        params.requireUserVerification,
        vars.pkParams.x,
        vars.pkParams.y
      )
    );
    passkeysImp.recoverSapientSignatureCompact(params.digest, vars.encodedSignature);
  }

  function boundP256Pk(
    uint256 _a
  ) internal pure returns (uint256) {
    _a = bound(_a, 1, 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550);
    return _a;
  }

}

library LibString {

  function indexOf(string memory haystack, string memory needle) internal pure returns (uint256) {
    bytes memory h = bytes(haystack);
    bytes memory n = bytes(needle);
    if (n.length == 0) {
      return 0;
    }
    if (n.length > h.length) {
      return type(uint256).max;
    }

    for (uint256 i = 0; i <= h.length - n.length; i++) {
      bool m = true;
      for (uint256 j = 0; j < n.length; j++) {
        if (h[i + j] != n[j]) {
          m = false;
          break;
        }
      }
      if (m) {
        return i;
      }
    }
    return type(uint256).max;
  }

}
