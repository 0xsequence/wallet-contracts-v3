// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../../src/modules/Payload.sol";
import { BaseSig } from "../../src/modules/auth/BaseSig.sol";

import { ISapient, ISapientCompact } from "../../src/modules/interfaces/ISapient.sol";
import { PrimitivesRPC } from "../utils/PrimitivesRPC.sol";

import { AdvTest } from "../utils/TestUtils.sol";
import { Vm } from "forge-std/Test.sol";
import { console } from "forge-std/console.sol";

contract BaseSigImp {

  function recoverPub(
    Payload.Decoded memory _payload,
    bytes calldata _signature,
    bool _ignoreCheckpointer,
    address _checkpointer
  ) external view returns (uint256 threshold, uint256 weight, bytes32 imageHash, uint256 checkpoint, bytes32 opHash) {
    return BaseSig.recover(_payload, _signature, _ignoreCheckpointer, _checkpointer);
  }

}

contract BaseSigTest is AdvTest {

  BaseSigImp public baseSigImp;

  function setUp() public {
    baseSigImp = new BaseSigImp();
  }

  function test_recover_random_config_unsigned(uint256 _maxDepth, uint256 _seed) external {
    _maxDepth = bound(_maxDepth, 1, 6);

    Payload.Decoded memory payload;
    payload.noChainId = true;

    string memory config = PrimitivesRPC.randomConfig(vm, _maxDepth, _seed, 1, "");
    bytes memory encodedConfig = PrimitivesRPC.toEncodedConfig(vm, config);

    (, uint256 weight, bytes32 imageHash,, bytes32 opHash) =
      baseSigImp.recoverPub(payload, encodedConfig, true, address(0));

    assertEq(weight, 0);
    assertEq(imageHash, PrimitivesRPC.getImageHash(vm, config));
    assertEq(opHash, Payload.hashFor(payload, address(baseSigImp)));
  }

  struct AddressWeightPair {
    address addr;
    uint8 weight;
  }

  struct test_recover_one_signer_params {
    AddressWeightPair[] prefix;
    AddressWeightPair[] suffix;
    Payload.Decoded payload;
    uint16 threshold;
    uint56 checkpoint;
    uint8 weight;
    uint256 pk;
    bool useEthSign;
  }

  function test_recover_one_signer(
    test_recover_one_signer_params memory params
  ) external {
    vm.assume(params.prefix.length + params.suffix.length < 600);

    boundToLegalPayload(params.payload);
    params.pk = boundPk(params.pk);

    address signer = vm.addr(params.pk);

    // The signer should not be in the prefix or suffix
    // or we may end up with more weight than expected
    for (uint256 i = 0; i < params.prefix.length; i++) {
      vm.assume(params.prefix[i].addr != signer);
    }
    for (uint256 i = 0; i < params.suffix.length; i++) {
      vm.assume(params.suffix[i].addr != signer);
    }

    string memory config;

    {
      string memory ce;
      for (uint256 i = 0; i < params.prefix.length; i++) {
        ce = string(
          abi.encodePacked(
            ce, "signer:", vm.toString(params.prefix[i].addr), ":", vm.toString(params.prefix[i].weight), " "
          )
        );
      }

      ce = string(abi.encodePacked(ce, "signer:", vm.toString(signer), ":", vm.toString(params.weight)));

      for (uint256 i = 0; i < params.suffix.length; i++) {
        ce = string(
          abi.encodePacked(
            ce, " signer:", vm.toString(params.suffix[i].addr), ":", vm.toString(params.suffix[i].weight)
          )
        );
      }

      config = PrimitivesRPC.newConfig(vm, params.threshold, params.checkpoint, ce);
    }

    bytes memory encodedSignature;
    {
      bytes32 payloadHash = Payload.hashFor(params.payload, address(baseSigImp));

      if (params.useEthSign) {
        payloadHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", payloadHash));
      }

      (uint8 v, bytes32 r, bytes32 s) = vm.sign(params.pk, payloadHash);

      string memory signatureType;
      if (params.useEthSign) {
        signatureType = ":eth_sign:";
      } else {
        signatureType = ":hash:";
      }

      string memory signatures = string(
        abi.encodePacked(vm.toString(signer), signatureType, vm.toString(r), ":", vm.toString(s), ":", vm.toString(v))
      );

      encodedSignature = PrimitivesRPC.toEncodedSignature(vm, config, signatures, !params.payload.noChainId);
    }

    (uint256 threshold, uint256 weight, bytes32 imageHash, uint256 checkpoint, bytes32 opHash) =
      baseSigImp.recoverPub(params.payload, encodedSignature, true, address(0));

    assertEq(threshold, params.threshold);
    assertEq(imageHash, PrimitivesRPC.getImageHash(vm, config));
    assertEq(checkpoint, params.checkpoint);
    assertEq(weight, params.weight);
    assertEq(opHash, Payload.hashFor(params.payload, address(baseSigImp)));
  }

  struct test_recover_one_1271_signer_params {
    AddressWeightPair[] prefix;
    AddressWeightPair[] suffix;
    Payload.Decoded payload;
    uint16 threshold;
    uint56 checkpoint;
    uint8 weight;
    address signer;
    bytes signature;
  }

  function test_recover_one_1271_signer(
    test_recover_one_1271_signer_params memory params
  ) external {
    assumeNotPrecompile2(params.signer);
    vm.assume(params.prefix.length + params.suffix.length < 600);

    // The signer should not be in the prefix or suffix
    // or we may end up with more weight than expected
    for (uint256 i = 0; i < params.prefix.length; i++) {
      vm.assume(params.prefix[i].addr != params.signer);
    }
    for (uint256 i = 0; i < params.suffix.length; i++) {
      vm.assume(params.suffix[i].addr != params.signer);
    }

    boundToLegalPayload(params.payload);

    string memory config;

    {
      string memory ce;
      for (uint256 i = 0; i < params.prefix.length; i++) {
        ce = string(
          abi.encodePacked(
            ce, "signer:", vm.toString(params.prefix[i].addr), ":", vm.toString(params.prefix[i].weight), " "
          )
        );
      }

      ce = string(abi.encodePacked(ce, "signer:", vm.toString(params.signer), ":", vm.toString(params.weight)));

      for (uint256 i = 0; i < params.suffix.length; i++) {
        ce = string(
          abi.encodePacked(
            ce, " signer:", vm.toString(params.suffix[i].addr), ":", vm.toString(params.suffix[i].weight)
          )
        );
      }

      config = PrimitivesRPC.newConfig(vm, params.threshold, params.checkpoint, ce);
    }

    bytes memory encodedSignature;
    {
      bytes32 payloadHash = Payload.hashFor(params.payload, address(baseSigImp));

      vm.mockCall(
        address(params.signer),
        abi.encodeWithSignature("isValidSignature(bytes32,bytes)", payloadHash, params.signature),
        abi.encode(bytes4(0x20c13b0b))
      );

      vm.expectCall(
        address(params.signer),
        abi.encodeWithSignature("isValidSignature(bytes32,bytes)", payloadHash, params.signature)
      );

      string memory se =
        string(abi.encodePacked(vm.toString(params.signer), ":erc1271:", vm.toString(params.signature)));

      encodedSignature = PrimitivesRPC.toEncodedSignature(vm, config, se, !params.payload.noChainId);
    }

    (uint256 threshold, uint256 weight, bytes32 imageHash, uint256 checkpoint, bytes32 opHash) =
      baseSigImp.recoverPub(params.payload, encodedSignature, true, address(0));

    assertEq(threshold, params.threshold);
    assertEq(imageHash, PrimitivesRPC.getImageHash(vm, config));
    assertEq(checkpoint, params.checkpoint);
    assertEq(weight, params.weight);
    assertEq(opHash, Payload.hashFor(params.payload, address(baseSigImp)));
  }

  struct test_recover_one_sapient_signer_params {
    AddressWeightPair[] prefix;
    AddressWeightPair[] suffix;
    Payload.Decoded payload;
    uint16 threshold;
    uint56 checkpoint;
    uint8 weight;
    address signer;
    bytes signature;
    bytes32 sapientImageHash;
    bool isCompact;
  }

  function test_recover_one_sapient_signer(
    test_recover_one_sapient_signer_params memory params
  ) external {
    assumeNotPrecompile2(params.signer);
    vm.assume(params.prefix.length + params.suffix.length < 600);

    // The signer should not be in the prefix or suffix
    // or we may end up with more weight than expected
    for (uint256 i = 0; i < params.prefix.length; i++) {
      vm.assume(params.prefix[i].addr != params.signer);
    }
    for (uint256 i = 0; i < params.suffix.length; i++) {
      vm.assume(params.suffix[i].addr != params.signer);
    }

    boundToLegalPayload(params.payload);

    string memory config;

    {
      string memory ce;
      for (uint256 i = 0; i < params.prefix.length; i++) {
        ce = string(
          abi.encodePacked(
            ce, "signer:", vm.toString(params.prefix[i].addr), ":", vm.toString(params.prefix[i].weight), " "
          )
        );
      }

      ce = string(
        abi.encodePacked(
          ce,
          "sapient:",
          vm.toString(params.sapientImageHash),
          ":",
          vm.toString(params.signer),
          ":",
          vm.toString(params.weight)
        )
      );

      for (uint256 i = 0; i < params.suffix.length; i++) {
        ce = string(
          abi.encodePacked(
            ce, " signer:", vm.toString(params.suffix[i].addr), ":", vm.toString(params.suffix[i].weight)
          )
        );
      }

      config = PrimitivesRPC.newConfig(vm, params.threshold, params.checkpoint, ce);
    }

    bytes memory encodedSignature;
    {
      string memory st;

      if (params.isCompact) {
        st = ":sapient_compact:";
        bytes32 payloadHash = Payload.hashFor(params.payload, address(baseSigImp));

        vm.mockCall(
          address(params.signer),
          abi.encodeWithSelector(ISapientCompact.recoverSapientSignatureCompact.selector, payloadHash, params.signature),
          abi.encode(params.sapientImageHash)
        );

        vm.expectCall(
          address(params.signer),
          abi.encodeWithSelector(ISapientCompact.recoverSapientSignatureCompact.selector, payloadHash, params.signature)
        );
      } else {
        st = ":sapient:";
        vm.mockCall(
          address(params.signer),
          abi.encodeWithSelector(ISapient.recoverSapientSignature.selector, params.payload, params.signature),
          abi.encode(params.sapientImageHash)
        );

        vm.expectCall(
          address(params.signer),
          abi.encodeWithSelector(ISapient.recoverSapientSignature.selector, params.payload, params.signature)
        );
      }

      string memory se = string(abi.encodePacked(vm.toString(params.signer), st, vm.toString(params.signature)));

      encodedSignature = PrimitivesRPC.toEncodedSignature(vm, config, se, !params.payload.noChainId);
    }

    (uint256 threshold, uint256 weight, bytes32 imageHash, uint256 checkpoint, bytes32 opHash) =
      baseSigImp.recoverPub(params.payload, encodedSignature, true, address(0));

    assertEq(threshold, params.threshold);
    assertEq(imageHash, PrimitivesRPC.getImageHash(vm, config));
    assertEq(checkpoint, params.checkpoint);
    assertEq(weight, params.weight);
    assertEq(opHash, Payload.hashFor(params.payload, address(baseSigImp)));
  }

  struct test_recover_nested_config_params {
    AddressWeightPair[] prefix;
    AddressWeightPair[] suffix;
    AddressWeightPair[] nestedPrefix;
    AddressWeightPair[] nestedSuffix;
    Payload.Decoded payload;
    uint16 threshold;
    uint56 checkpoint;
    uint16 internalThreshold;
    uint8 externalWeight;
    uint8 weight;
    uint256 pk;
    bool useEthSign;
  }

  function test_recover_nested_config(
    test_recover_nested_config_params memory params
  ) external {
    vm.assume(
      params.prefix.length + params.suffix.length + params.nestedPrefix.length + params.nestedSuffix.length < 600
    );

    boundToLegalPayload(params.payload);
    params.pk = boundPk(params.pk);

    address signer = vm.addr(params.pk);

    // The signer should not be in the prefix or suffix
    // or we may end up with more weight than expected
    for (uint256 i = 0; i < params.prefix.length; i++) {
      vm.assume(params.prefix[i].addr != signer);
    }
    for (uint256 i = 0; i < params.suffix.length; i++) {
      vm.assume(params.suffix[i].addr != signer);
    }

    for (uint256 i = 0; i < params.nestedPrefix.length; i++) {
      vm.assume(params.nestedPrefix[i].addr != signer);
    }
    for (uint256 i = 0; i < params.nestedSuffix.length; i++) {
      vm.assume(params.nestedSuffix[i].addr != signer);
    }

    string memory config;

    {
      string memory ce;
      for (uint256 i = 0; i < params.prefix.length; i++) {
        ce = string(
          abi.encodePacked(
            ce, "signer:", vm.toString(params.prefix[i].addr), ":", vm.toString(params.prefix[i].weight), " "
          )
        );
      }

      string memory nestedContent;
      for (uint256 i = 0; i < params.nestedPrefix.length; i++) {
        nestedContent = string(
          abi.encodePacked(
            nestedContent,
            "signer:",
            vm.toString(params.nestedPrefix[i].addr),
            ":",
            vm.toString(params.nestedPrefix[i].weight),
            " "
          )
        );
      }

      nestedContent =
        string(abi.encodePacked(nestedContent, "signer:", vm.toString(signer), ":", vm.toString(params.weight)));

      for (uint256 i = 0; i < params.nestedSuffix.length; i++) {
        nestedContent = string(
          abi.encodePacked(
            nestedContent,
            " signer:",
            vm.toString(params.nestedSuffix[i].addr),
            ":",
            vm.toString(params.nestedSuffix[i].weight)
          )
        );
      }

      ce = string(
        abi.encodePacked(
          ce,
          "nested:",
          vm.toString(params.internalThreshold),
          ":",
          vm.toString(params.externalWeight),
          ":(",
          nestedContent,
          ")"
        )
      );

      for (uint256 i = 0; i < params.suffix.length; i++) {
        ce = string(
          abi.encodePacked(
            ce, " signer:", vm.toString(params.suffix[i].addr), ":", vm.toString(params.suffix[i].weight)
          )
        );
      }

      config = PrimitivesRPC.newConfig(vm, params.threshold, params.checkpoint, ce);
    }

    bytes memory encodedSignature;
    {
      bytes32 payloadHash = Payload.hashFor(params.payload, address(baseSigImp));

      if (params.useEthSign) {
        payloadHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", payloadHash));
      }

      (uint8 v, bytes32 r, bytes32 s) = vm.sign(params.pk, payloadHash);

      string memory signatureType;
      if (params.useEthSign) {
        signatureType = ":eth_sign:";
      } else {
        signatureType = ":hash:";
      }

      string memory se = string(
        abi.encodePacked(vm.toString(signer), signatureType, vm.toString(r), ":", vm.toString(s), ":", vm.toString(v))
      );

      encodedSignature = PrimitivesRPC.toEncodedSignature(vm, config, se, !params.payload.noChainId);
    }

    (uint256 threshold, uint256 weight, bytes32 imageHash, uint256 checkpoint, bytes32 opHash) =
      baseSigImp.recoverPub(params.payload, encodedSignature, true, address(0));

    assertEq(threshold, params.threshold);
    assertEq(imageHash, PrimitivesRPC.getImageHash(vm, config));
    assertEq(checkpoint, params.checkpoint);
    assertEq(weight, params.weight >= params.internalThreshold ? params.externalWeight : 0);
    assertEq(opHash, Payload.hashFor(params.payload, address(baseSigImp)));
  }

  struct test_recover_chained_signature_single_case_vars {
    address signer1addr;
    address signer2addr;
    address signer3addr;
    uint256 signer1pk;
    uint256 signer2pk;
    uint256 signer3pk;
    string config1;
    string config2;
    string config3;
    bytes32 config1Hash;
    bytes32 config2Hash;
    bytes32 config3Hash;
    Payload.Decoded payloadApprove2;
    Payload.Decoded payloadApprove3;
    bytes signatureForFinalPayload;
    bytes signature1to2;
    bytes signature2to3;
    uint8 v2;
    bytes32 r2;
    bytes32 s2;
    uint8 v3;
    bytes32 r3;
    bytes32 s3;
    uint8 fv;
    bytes32 fr;
    bytes32 fs;
  }

  function test_recover_chained_signature_single_case(
    Payload.Decoded memory _finalPayload
  ) external {
    boundToLegalPayload(_finalPayload);

    test_recover_chained_signature_single_case_vars memory vars;

    vars.signer1pk = 1;
    vars.signer2pk = 2;
    vars.signer3pk = 3;

    vars.signer1addr = vm.addr(vars.signer1pk);
    vars.signer2addr = vm.addr(vars.signer2pk);
    vars.signer3addr = vm.addr(vars.signer3pk);

    vars.config1 =
      PrimitivesRPC.newConfig(vm, 1, 1, string(abi.encodePacked("signer:", vm.toString(vars.signer1addr), ":1")));

    vars.config2 = PrimitivesRPC.newConfig(
      vm,
      1,
      2,
      string(
        abi.encodePacked(
          "signer:", vm.toString(vars.signer2addr), ":3 ", "signer:", vm.toString(vars.signer1addr), ":2"
        )
      )
    );

    vars.config3 = PrimitivesRPC.newConfig(
      vm,
      1,
      3,
      string(
        abi.encodePacked(
          "signer:", vm.toString(vars.signer3addr), ":2 ", "signer:", vm.toString(vars.signer2addr), ":2"
        )
      )
    );

    vars.config1Hash = PrimitivesRPC.getImageHash(vm, vars.config1);
    vars.config2Hash = PrimitivesRPC.getImageHash(vm, vars.config2);
    vars.config3Hash = PrimitivesRPC.getImageHash(vm, vars.config3);

    vars.payloadApprove2.kind = Payload.KIND_CONFIG_UPDATE;
    vars.payloadApprove3.kind = Payload.KIND_CONFIG_UPDATE;

    vars.payloadApprove2.imageHash = vars.config2Hash;
    vars.payloadApprove3.imageHash = vars.config3Hash;

    {
      (vars.v2, vars.r2, vars.s2) = vm.sign(vars.signer1pk, Payload.hashFor(vars.payloadApprove2, address(baseSigImp)));
      (vars.v3, vars.r3, vars.s3) = vm.sign(vars.signer2pk, Payload.hashFor(vars.payloadApprove3, address(baseSigImp)));
      (vars.fv, vars.fr, vars.fs) = vm.sign(vars.signer3pk, Payload.hashFor(_finalPayload, address(baseSigImp)));

      // Signature for final payload
      vars.signatureForFinalPayload = PrimitivesRPC.toEncodedSignature(
        vm,
        vars.config3,
        string(
          abi.encodePacked(
            vm.toString(vars.signer3addr),
            ":hash:",
            vm.toString(vars.fr),
            ":",
            vm.toString(vars.fs),
            ":",
            vm.toString(vars.fv)
          )
        ),
        !_finalPayload.noChainId
      );

      // Signatures for links, config3 -> config2 -> config1
      vars.signature1to2 = PrimitivesRPC.toEncodedSignature(
        vm,
        vars.config1,
        string(
          abi.encodePacked(
            "--signature ",
            vm.toString(vars.signer1addr),
            ":hash:",
            vm.toString(vars.r2),
            ":",
            vm.toString(vars.s2),
            ":",
            vm.toString(vars.v2)
          )
        ),
        true
      );
      vars.signature2to3 = PrimitivesRPC.toEncodedSignature(
        vm,
        vars.config2,
        string(
          abi.encodePacked(
            "--signature ",
            vm.toString(vars.signer2addr),
            ":hash:",
            vm.toString(vars.r3),
            ":",
            vm.toString(vars.s3),
            ":",
            vm.toString(vars.v3)
          )
        ),
        true
      );
    }

    bytes[] memory signatures = new bytes[](3);
    signatures[0] = vars.signatureForFinalPayload;
    signatures[1] = vars.signature2to3;
    signatures[2] = vars.signature1to2;

    bytes memory chainedSignature = PrimitivesRPC.concatSignatures(vm, signatures);

    // Recover chained signature
    (uint256 threshold, uint256 weight, bytes32 imageHash, uint256 checkpoint, bytes32 opHash) =
      baseSigImp.recoverPub(_finalPayload, chainedSignature, true, address(0));

    assertEq(threshold, 1);
    assertEq(weight, 1);
    assertEq(imageHash, vars.config1Hash);
    assertEq(checkpoint, 1);
    assertEq(opHash, Payload.hashFor(_finalPayload, address(baseSigImp)));
  }

  struct test_recover_subdigest_params {
    Payload.Decoded payload;
    AddressWeightPair[] prefix;
    AddressWeightPair[] suffix;
    uint16 threshold;
    uint56 checkpoint;
  }

  function test_recover_subdigest(
    test_recover_subdigest_params memory params
  ) public {
    boundToLegalPayload(params.payload);

    bytes32 opHash = Payload.hashFor(params.payload, address(baseSigImp));

    string memory ce;

    for (uint256 i = 0; i < params.prefix.length; i++) {
      ce =
        string.concat(ce, "signer:", vm.toString(params.prefix[i].addr), ":", vm.toString(params.prefix[i].weight), " ");
    }

    ce = string.concat(ce, "subdigest:", vm.toString(opHash));

    for (uint256 i = 0; i < params.suffix.length; i++) {
      ce =
        string.concat(ce, " ", "signer:", vm.toString(params.suffix[i].addr), ":", vm.toString(params.suffix[i].weight));
    }

    string memory config = PrimitivesRPC.newConfig(vm, params.threshold, params.checkpoint, ce);

    bytes memory encodedSig = PrimitivesRPC.toEncodedSignature(vm, config, "", !params.payload.noChainId);
    bytes32 expectedImageHash = PrimitivesRPC.getImageHash(vm, config);

    (uint256 threshold, uint256 weight, bytes32 imageHash, uint256 checkpoint, bytes32 recoveredOpHash) =
      baseSigImp.recoverPub(params.payload, encodedSig, true, address(0));

    assertEq(threshold, params.threshold);
    assertEq(checkpoint, params.checkpoint);
    assertEq(weight, type(uint256).max);
    assertEq(recoveredOpHash, opHash);
    assertEq(imageHash, expectedImageHash);
  }

  struct test_recover_anyAddressSubdigest_params {
    Payload.Decoded payload;
    AddressWeightPair[] prefix;
    AddressWeightPair[] suffix;
    uint16 threshold;
    uint56 checkpoint;
  }

  function test_recover_anyAddressSubdigest(
    test_recover_anyAddressSubdigest_params memory params
  ) public {
    vm.assume(params.payload.calls.length < 5);
    boundToLegalPayload(params.payload);

    bytes32 expectedAnyAddressDigest = Payload.hashFor(params.payload, address(0));
    bytes32 opHash = Payload.hashFor(params.payload, address(baseSigImp));

    string memory ce;

    for (uint256 i = 0; i < params.prefix.length; i++) {
      ce =
        string.concat(ce, "signer:", vm.toString(params.prefix[i].addr), ":", vm.toString(params.prefix[i].weight), " ");
    }

    ce = string.concat(ce, "any-address-subdigest:", vm.toString(expectedAnyAddressDigest));

    for (uint256 i = 0; i < params.suffix.length; i++) {
      ce =
        string.concat(ce, " ", "signer:", vm.toString(params.suffix[i].addr), ":", vm.toString(params.suffix[i].weight));
    }

    string memory config = PrimitivesRPC.newConfig(vm, params.threshold, params.checkpoint, ce);

    bytes memory encodedSig = PrimitivesRPC.toEncodedSignature(vm, config, "", !params.payload.noChainId);
    bytes32 expectedImageHash = PrimitivesRPC.getImageHash(vm, config);

    (uint256 threshold, uint256 weight, bytes32 imageHash, uint256 checkpoint, bytes32 recoveredOpHash) =
      baseSigImp.recoverPub(params.payload, encodedSig, true, address(0));

    assertEq(threshold, params.threshold);
    assertEq(checkpoint, params.checkpoint);
    assertEq(weight, type(uint256).max);
    assertEq(recoveredOpHash, opHash);
    assertEq(imageHash, expectedImageHash);
  }

}
