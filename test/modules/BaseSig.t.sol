// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../../src/modules/Payload.sol";
import { BaseSig } from "../../src/modules/auth/BaseSig.sol";

import { ICheckpointer, Snapshot } from "../../src/modules/interfaces/ICheckpointer.sol";
import { ISapient, ISapientCompact } from "../../src/modules/interfaces/ISapient.sol";
import { PrimitivesRPC } from "../utils/PrimitivesRPC.sol";
import { AdvTest } from "../utils/TestUtils.sol";
import { Vm } from "forge-std/Test.sol";

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

    string memory config = PrimitivesRPC.randomConfig(vm, _maxDepth, _seed, 1, "none");
    bytes memory encodedConfig = PrimitivesRPC.toEncodedConfig(vm, config);

    (, uint256 weight, bytes32 imageHash,, bytes32 opHash) =
      baseSigImp.recoverPub(payload, encodedConfig, true, address(0));

    assertEq(weight, 0);
    assertEq(imageHash, PrimitivesRPC.getImageHash(vm, config));
    assertEq(opHash, Payload.hashFor(payload, address(baseSigImp)));
  }

  function test_recover_random_config_unsigned_skewed_left(uint256 _seed) external {
    uint256 _maxDepth = 54;

    Payload.Decoded memory payload;
    payload.noChainId = true;

    string memory config = PrimitivesRPC.randomConfig(vm, _maxDepth, _seed, 1, "left");
    bytes memory encodedConfig = PrimitivesRPC.toEncodedConfig(vm, config);

    (, uint256 weight, bytes32 imageHash,, bytes32 opHash) =
      baseSigImp.recoverPub(payload, encodedConfig, true, address(0));

    assertEq(weight, 0);
    assertEq(imageHash, PrimitivesRPC.getImageHash(vm, config));
    assertEq(opHash, Payload.hashFor(payload, address(baseSigImp)));
  }

  function test_recover_random_config_unsigned_skewed_right(uint256 _seed) external {
    uint256 _maxDepth = 54;

    Payload.Decoded memory payload;
    payload.noChainId = true;

    string memory config = PrimitivesRPC.randomConfig(vm, _maxDepth, _seed, 1, "right");
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
        abi.encode(bytes4(0x1626ba7e))
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

  struct test_recover_one_1271_invalid_signature_fail_params {
    AddressWeightPair[] prefix;
    AddressWeightPair[] suffix;
    Payload.Decoded payload;
    uint16 threshold;
    uint56 checkpoint;
    uint8 weight;
    address signer;
    bytes signature;
    bytes revertFromSigner;
  }

  function test_recover_one_1271_invalid_signature_revert_fail(
    test_recover_one_1271_invalid_signature_fail_params memory params
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

      vm.mockCallRevert(
        address(params.signer),
        abi.encodeWithSignature("isValidSignature(bytes32,bytes)", payloadHash, params.signature),
        params.revertFromSigner
      );

      string memory se =
        string(abi.encodePacked(vm.toString(params.signer), ":erc1271:", vm.toString(params.signature)));

      encodedSignature = PrimitivesRPC.toEncodedSignature(vm, config, se, !params.payload.noChainId);
    }

    vm.expectRevert(params.revertFromSigner);
    baseSigImp.recoverPub(params.payload, encodedSignature, true, address(0));
  }

  struct test_recover_one_1271_invalid_signature_bad_return_fail_params {
    AddressWeightPair[] prefix;
    AddressWeightPair[] suffix;
    Payload.Decoded payload;
    uint16 threshold;
    uint56 checkpoint;
    uint8 weight;
    address signer;
    bytes signature;
    bytes4 bad4Bytes;
  }

  function test_recover_one_1271_invalid_signature_bad_return_fail(
    test_recover_one_1271_invalid_signature_bad_return_fail_params memory params
  ) external {
    assumeNotPrecompile2(params.signer);
    vm.assume(params.prefix.length + params.suffix.length < 600);

    if (params.bad4Bytes == bytes4(0x1626ba7e)) {
      params.bad4Bytes = bytes4(0x00000000);
    }

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
    bytes32 payloadHash = Payload.hashFor(params.payload, address(baseSigImp));

    {
      vm.mockCall(
        address(params.signer),
        abi.encodeWithSignature("isValidSignature(bytes32,bytes)", payloadHash, params.signature),
        abi.encode(params.bad4Bytes)
      );

      string memory se =
        string(abi.encodePacked(vm.toString(params.signer), ":erc1271:", vm.toString(params.signature)));

      encodedSignature = PrimitivesRPC.toEncodedSignature(vm, config, se, !params.payload.noChainId);
    }

    vm.expectRevert(
      abi.encodeWithSelector(BaseSig.InvalidERC1271Signature.selector, payloadHash, params.signer, params.signature)
    );
    baseSigImp.recoverPub(params.payload, encodedSignature, true, address(0));
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

  function test_recover_invalid_signature_flag(
    Payload.Decoded memory _payload,
    uint8 checkpointSize,
    uint8 thresholdSize,
    uint8 invalidFlag
  ) external {
    boundToLegalPayload(_payload);

    invalidFlag = uint8(bound(invalidFlag, BaseSig.FLAG_SIGNATURE_SAPIENT_COMPACT + 1, 15));
    checkpointSize = uint8(bound(checkpointSize, 0, 7));
    thresholdSize = uint8(bound(thresholdSize, 0, 1));

    uint8 signatureFlag = uint8((checkpointSize << 2) | (thresholdSize << 5));
    uint256 thresholdLen = thresholdSize + 1;

    bytes memory signature = new bytes(1 + checkpointSize + thresholdLen + 1);
    signature[0] = bytes1(signatureFlag);

    signature[1 + checkpointSize + thresholdLen] = bytes1((invalidFlag << 4));

    vm.expectRevert(abi.encodeWithSelector(BaseSig.InvalidSignatureFlag.selector, invalidFlag));
    baseSigImp.recoverPub(_payload, signature, false, address(0));
  }

  struct test_recover_chained_low_weight_fail_params {
    Payload.Decoded payload;
    uint256 threshold;
    uint256 weight;
    uint256 signer1pk;
    uint256 signer2pk;
    uint256 signer3pk;
  }

  struct test_recover_chained_low_weight_fail_vars {
    address signer1addr;
    address signer2addr;
    address signer3addr;
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

  function test_recover_chained_low_weight_fail(
    test_recover_chained_low_weight_fail_params memory params
  ) external {
    boundToLegalPayload(params.payload);
    params.weight = bound(params.weight, 0, type(uint8).max);
    params.threshold = bound(params.threshold, params.weight + 1, type(uint16).max);

    test_recover_chained_low_weight_fail_vars memory vars;

    params.signer1pk = boundPk(params.signer1pk);
    params.signer2pk = boundPk(params.signer2pk);
    params.signer3pk = boundPk(params.signer3pk);

    vars.signer1addr = vm.addr(params.signer1pk);
    vars.signer2addr = vm.addr(params.signer2pk);
    vars.signer3addr = vm.addr(params.signer3pk);

    vars.config1 =
      PrimitivesRPC.newConfig(vm, 1, 1, string(abi.encodePacked("signer:", vm.toString(vars.signer1addr), ":1")));
    vars.config2 = PrimitivesRPC.newConfig(
      vm,
      uint16(params.threshold),
      2,
      string(abi.encodePacked("signer:", vm.toString(vars.signer2addr), ":", vm.toString(params.weight)))
    );
    vars.config3 =
      PrimitivesRPC.newConfig(vm, 1, 3, string(abi.encodePacked("signer:", vm.toString(vars.signer3addr), ":3")));

    vars.payloadApprove2.kind = Payload.KIND_CONFIG_UPDATE;
    vars.payloadApprove3.kind = Payload.KIND_CONFIG_UPDATE;

    vars.payloadApprove2.imageHash = vars.config2Hash;
    vars.payloadApprove3.imageHash = vars.config3Hash;

    {
      (vars.v2, vars.r2, vars.s2) =
        vm.sign(params.signer1pk, Payload.hashFor(vars.payloadApprove2, address(baseSigImp)));
      (vars.v3, vars.r3, vars.s3) =
        vm.sign(params.signer2pk, Payload.hashFor(vars.payloadApprove3, address(baseSigImp)));
      (vars.fv, vars.fr, vars.fs) = vm.sign(params.signer3pk, Payload.hashFor(params.payload, address(baseSigImp)));

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
        !params.payload.noChainId
      );

      vars.signature1to2 = PrimitivesRPC.toEncodedSignature(
        vm,
        vars.config1,
        string(
          abi.encodePacked(
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

    vm.expectRevert(
      abi.encodeWithSelector(BaseSig.LowWeightChainedSignature.selector, signatures[1], params.threshold, params.weight)
    );
    baseSigImp.recoverPub(params.payload, chainedSignature, true, address(0));
  }

  struct test_recover_chained_wrong_checkpoint_order_fail_params {
    Payload.Decoded payload;
    uint256 signer1pk;
    uint256 signer2pk;
    uint256 signer3pk;
    uint256 checkpoint1;
    uint256 checkpoint2;
    uint256 checkpoint3;
  }

  struct test_recover_chained_wrong_checkpoint_order_fail_vars {
    address signer1addr;
    address signer2addr;
    address signer3addr;
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

  function test_recover_chained_wrong_checkpoint_order_fail(
    test_recover_chained_wrong_checkpoint_order_fail_params memory params
  ) external {
    boundToLegalPayload(params.payload);

    params.checkpoint1 = bound(params.checkpoint1, 0, type(uint56).max);
    params.checkpoint2 = bound(params.checkpoint2, 0, type(uint56).max);
    params.checkpoint3 = bound(params.checkpoint3, 0, type(uint56).max);

    // Ensure that either checkpoint2 <= checkpoint1 or checkpoint3 <= checkpoint2
    if (params.checkpoint2 > params.checkpoint1) {
      params.checkpoint1 = params.checkpoint2;
    }
    if (params.checkpoint3 > params.checkpoint2) {
      params.checkpoint2 = params.checkpoint3;
    }

    test_recover_chained_wrong_checkpoint_order_fail_vars memory vars;

    params.signer1pk = boundPk(params.signer1pk);
    params.signer2pk = boundPk(params.signer2pk);
    params.signer3pk = boundPk(params.signer3pk);

    vars.signer1addr = vm.addr(params.signer1pk);
    vars.signer2addr = vm.addr(params.signer2pk);
    vars.signer3addr = vm.addr(params.signer3pk);

    vars.config1 = PrimitivesRPC.newConfig(
      vm, 1, params.checkpoint1, string(abi.encodePacked("signer:", vm.toString(vars.signer1addr), ":1"))
    );
    vars.config2 = PrimitivesRPC.newConfig(
      vm, 2, params.checkpoint2, string(abi.encodePacked("signer:", vm.toString(vars.signer2addr), ":2"))
    );
    vars.config3 = PrimitivesRPC.newConfig(
      vm, 1, params.checkpoint3, string(abi.encodePacked("signer:", vm.toString(vars.signer3addr), ":3"))
    );

    vars.payloadApprove2.kind = Payload.KIND_CONFIG_UPDATE;
    vars.payloadApprove3.kind = Payload.KIND_CONFIG_UPDATE;

    vars.payloadApprove2.imageHash = vars.config2Hash;
    vars.payloadApprove3.imageHash = vars.config3Hash;

    {
      (vars.v2, vars.r2, vars.s2) =
        vm.sign(params.signer1pk, Payload.hashFor(vars.payloadApprove2, address(baseSigImp)));
      (vars.v3, vars.r3, vars.s3) =
        vm.sign(params.signer2pk, Payload.hashFor(vars.payloadApprove3, address(baseSigImp)));
      (vars.fv, vars.fr, vars.fs) = vm.sign(params.signer3pk, Payload.hashFor(params.payload, address(baseSigImp)));

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
        !params.payload.noChainId
      );

      vars.signature1to2 = PrimitivesRPC.toEncodedSignature(
        vm,
        vars.config1,
        string(
          abi.encodePacked(
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

    if (params.checkpoint3 > params.checkpoint2) {
      vm.expectRevert(
        abi.encodeWithSelector(BaseSig.WrongChainedCheckpointOrder.selector, params.checkpoint1, params.checkpoint2)
      );
    } else {
      vm.expectRevert(
        abi.encodeWithSelector(BaseSig.WrongChainedCheckpointOrder.selector, params.checkpoint2, params.checkpoint3)
      );
    }
    baseSigImp.recoverPub(params.payload, chainedSignature, true, address(0));
  }

  // Checkpointer tests

  struct test_checkpointer_current_snapshot_params {
    Payload.Decoded payload;
    address checkpointer;
    uint56 checkpoint;
    uint256 signer1pk;
    uint8 threshold;
    uint8 weight;
    bytes checkpointerData;
  }

  struct test_checkpointer_current_snapshot_vars {
    address signer1addr;
    string configJson;
    bytes32 expectedImageHash;
    bytes signature;
    Snapshot snapshot;
  }

  function test_checkpointer_current_snapshot(
    test_checkpointer_current_snapshot_params memory params
  ) external {
    vm.assume(params.payload.calls.length < 3);
    test_checkpointer_current_snapshot_vars memory vars;
    boundToLegalPayload(params.payload);

    params.checkpointer = boundNoPrecompile(params.checkpointer);
    params.signer1pk = boundPk(params.signer1pk);
    vars.signer1addr = vm.addr(params.signer1pk);

    params.weight = uint8(bound(params.weight, params.threshold, type(uint8).max));

    vars.configJson = PrimitivesRPC.newConfigWithCheckpointer(
      vm,
      params.checkpointer,
      params.threshold,
      params.checkpoint,
      string(abi.encodePacked("signer:", vm.toString(vars.signer1addr), ":", vm.toString(params.weight)))
    );
    vars.expectedImageHash = PrimitivesRPC.getImageHash(vm, vars.configJson);

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(params.signer1pk, Payload.hashFor(params.payload, address(baseSigImp)));

    vars.signature = PrimitivesRPC.toEncodedSignatureWithCheckpointerData(
      vm,
      vars.configJson,
      string(
        abi.encodePacked(
          vm.toString(vars.signer1addr), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v)
        )
      ),
      !params.payload.noChainId,
      params.checkpointerData
    );

    vars.snapshot.imageHash = vars.expectedImageHash;
    vars.snapshot.checkpoint = params.checkpoint;

    vm.mockCall(
      params.checkpointer, abi.encodeWithSelector(ICheckpointer.snapshotFor.selector), abi.encode(vars.snapshot)
    );

    (uint256 threshold, uint256 weight, bytes32 imageHash, uint256 checkpoint, bytes32 opHash) =
      baseSigImp.recoverPub(params.payload, vars.signature, false, address(0));
    assertEq(threshold, params.threshold);
    assertEq(weight, params.weight);
    assertEq(imageHash, vars.snapshot.imageHash);
    assertEq(checkpoint, vars.snapshot.checkpoint);
    assertEq(opHash, Payload.hashFor(params.payload, address(baseSigImp)));
  }

  struct test_checkpointer_higher_checkpoint_fail_params {
    Payload.Decoded payload;
    address checkpointer;
    bytes checkpointerData;
    uint56 checkpointerCheckpoint;
    uint56 checkpoint;
    uint256 signer1pk;
    uint8 threshold;
    uint8 weight;
  }

  struct test_checkpointer_higher_checkpoint_fail_vars {
    address signer1addr;
    string configJson;
    bytes32 expectedImageHash;
    bytes signature;
    Snapshot snapshot;
  }

  function test_checkpointer_higher_checkpoint_fail(
    test_checkpointer_higher_checkpoint_fail_params memory params
  ) external {
    boundToLegalPayload(params.payload);

    params.checkpointerCheckpoint = uint56(bound(params.checkpointerCheckpoint, 1, type(uint56).max));
    params.checkpoint = uint56(bound(params.checkpoint, 0, params.checkpointerCheckpoint - 1));

    params.checkpointer = boundNoPrecompile(params.checkpointer);
    params.signer1pk = boundPk(params.signer1pk);

    params.weight = uint8(bound(params.weight, params.threshold, type(uint8).max));

    test_checkpointer_higher_checkpoint_fail_vars memory vars;

    vars.configJson = PrimitivesRPC.newConfigWithCheckpointer(
      vm,
      params.checkpointer,
      params.threshold,
      params.checkpointerCheckpoint,
      string(abi.encodePacked("signer:", vm.toString(vars.signer1addr), ":", vm.toString(params.weight)))
    );
    vars.expectedImageHash = PrimitivesRPC.getImageHash(vm, vars.configJson);

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(params.signer1pk, Payload.hashFor(params.payload, address(baseSigImp)));

    vars.signature = PrimitivesRPC.toEncodedSignatureWithCheckpointerData(
      vm,
      vars.configJson,
      string(
        abi.encodePacked(
          vm.toString(vars.signer1addr), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v)
        )
      ),
      !params.payload.noChainId,
      params.checkpointerData
    );

    vars.snapshot.imageHash = vars.expectedImageHash;
    vars.snapshot.checkpoint = params.checkpointerCheckpoint;

    vm.mockCall(
      params.checkpointer, abi.encodeWithSelector(ICheckpointer.snapshotFor.selector), abi.encode(vars.snapshot)
    );

    vm.expectRevert(abi.encodeWithSelector(BaseSig.UnusedSnapshot.selector, vars.snapshot));
    baseSigImp.recoverPub(params.payload, vars.signature, false, address(0));
  }

  struct test_checkpointer_different_image_hash_fail_params {
    Payload.Decoded payload;
    address checkpointer;
    bytes checkpointerData;
    uint56 checkpoint;
    uint256 signer1pk;
    uint8 threshold;
    uint8 weight;
    bytes32 differentImageHash;
  }

  struct test_checkpointer_different_image_hash_fail_vars {
    address signer1addr;
    string configJson;
    bytes32 expectedImageHash;
    bytes signature;
    Snapshot snapshot;
  }

  function test_checkpointer_different_image_hash_fail(
    test_checkpointer_different_image_hash_fail_params memory params
  ) external {
    vm.assume(params.differentImageHash != bytes32(0));

    boundToLegalPayload(params.payload);

    params.checkpoint = uint56(bound(params.checkpoint, 0, type(uint56).max));
    params.checkpointer = boundNoPrecompile(params.checkpointer);
    params.signer1pk = boundPk(params.signer1pk);
    params.weight = uint8(bound(params.weight, params.threshold, type(uint8).max));

    test_checkpointer_different_image_hash_fail_vars memory vars;

    vars.signer1addr = vm.addr(params.signer1pk);
    vars.configJson = PrimitivesRPC.newConfigWithCheckpointer(
      vm,
      params.checkpointer,
      params.threshold,
      params.checkpoint,
      string(abi.encodePacked("signer:", vm.toString(vars.signer1addr), ":", vm.toString(params.weight)))
    );
    vars.expectedImageHash = PrimitivesRPC.getImageHash(vm, vars.configJson);

    // Ensure the different imageHash is actually different from the expected one and not zero
    vm.assume(params.differentImageHash != vars.expectedImageHash);

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(params.signer1pk, Payload.hashFor(params.payload, address(baseSigImp)));

    vars.signature = PrimitivesRPC.toEncodedSignatureWithCheckpointerData(
      vm,
      vars.configJson,
      string(
        abi.encodePacked(
          vm.toString(vars.signer1addr), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v)
        )
      ),
      !params.payload.noChainId,
      params.checkpointerData
    );

    // Use the provided different imageHash
    vars.snapshot.imageHash = params.differentImageHash;
    vars.snapshot.checkpoint = params.checkpoint;

    vm.mockCall(
      params.checkpointer, abi.encodeWithSelector(ICheckpointer.snapshotFor.selector), abi.encode(vars.snapshot)
    );

    vm.expectRevert(abi.encodeWithSelector(BaseSig.UnusedSnapshot.selector, vars.snapshot));
    baseSigImp.recoverPub(params.payload, vars.signature, false, address(0));
  }

  struct test_checkpointer_disabled_params {
    Payload.Decoded payload;
    address checkpointer;
    uint56 checkpoint;
    uint56 snapshotCheckpoint;
    uint256 signer1pk;
    uint8 threshold;
    uint8 weight;
    bytes checkpointerData;
  }

  struct test_checkpointer_disabled_vars {
    address signer1addr;
    string configJson;
    bytes32 expectedImageHash;
    bytes signature;
    Snapshot snapshot;
  }

  function test_checkpointer_disabled(
    test_checkpointer_disabled_params memory params
  ) external {
    vm.assume(params.payload.calls.length < 3);
    test_checkpointer_disabled_vars memory vars;
    boundToLegalPayload(params.payload);

    params.checkpointer = boundNoPrecompile(params.checkpointer);
    params.signer1pk = boundPk(params.signer1pk);
    vars.signer1addr = vm.addr(params.signer1pk);

    params.weight = uint8(bound(params.weight, params.threshold, type(uint8).max));

    vars.configJson = PrimitivesRPC.newConfigWithCheckpointer(
      vm,
      params.checkpointer,
      params.threshold,
      params.checkpoint,
      string(abi.encodePacked("signer:", vm.toString(vars.signer1addr), ":", vm.toString(params.weight)))
    );
    vars.expectedImageHash = PrimitivesRPC.getImageHash(vm, vars.configJson);

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(params.signer1pk, Payload.hashFor(params.payload, address(baseSigImp)));

    vars.signature = PrimitivesRPC.toEncodedSignatureWithCheckpointerData(
      vm,
      vars.configJson,
      string(
        abi.encodePacked(
          vm.toString(vars.signer1addr), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v)
        )
      ),
      !params.payload.noChainId,
      params.checkpointerData
    );

    // Set imageHash to 0 to indicate checkpointer is disabled
    vars.snapshot.imageHash = bytes32(0);
    vars.snapshot.checkpoint = params.snapshotCheckpoint;

    vm.mockCall(
      params.checkpointer, abi.encodeWithSelector(ICheckpointer.snapshotFor.selector), abi.encode(vars.snapshot)
    );

    (uint256 threshold, uint256 weight, bytes32 imageHash, uint256 checkpoint, bytes32 opHash) =
      baseSigImp.recoverPub(params.payload, vars.signature, false, address(0));
    assertEq(threshold, params.threshold);
    assertEq(weight, params.weight);
    assertEq(imageHash, vars.expectedImageHash);
    assertEq(checkpoint, params.checkpoint); // Should use checkpoint from config, not snapshot
    assertEq(opHash, Payload.hashFor(params.payload, address(baseSigImp)));
  }

  struct test_checkpointer_disabled_old_checkpoint_params {
    Payload.Decoded payload;
    address checkpointer;
    uint56 checkpoint;
    uint56 snapshotCheckpoint;
    uint256 signer1pk;
    uint8 threshold;
    uint8 weight;
    bytes checkpointerData;
    bytes32 ignoredImageHash;
    uint56 oldCheckpoint;
  }

  struct test_checkpointer_disabled_old_checkpoint_vars {
    address signer1addr;
    string configJson;
    bytes32 expectedImageHash;
    bytes signature;
    Snapshot snapshot;
  }

  function test_checkpointer_disabled_old_checkpoint(
    test_checkpointer_disabled_old_checkpoint_params memory params
  ) external {
    vm.assume(params.payload.calls.length < 3);
    test_checkpointer_disabled_old_checkpoint_vars memory vars;
    boundToLegalPayload(params.payload);

    params.checkpoint = uint56(bound(params.checkpoint, 1, type(uint56).max));
    params.oldCheckpoint = uint56(bound(params.oldCheckpoint, 0, params.checkpoint - 1));

    params.checkpointer = boundNoPrecompile(params.checkpointer);
    params.signer1pk = boundPk(params.signer1pk);
    vars.signer1addr = vm.addr(params.signer1pk);

    params.weight = uint8(bound(params.weight, params.threshold, type(uint8).max));

    vars.configJson = PrimitivesRPC.newConfigWithCheckpointer(
      vm,
      params.checkpointer,
      params.threshold,
      params.checkpoint,
      string(abi.encodePacked("signer:", vm.toString(vars.signer1addr), ":", vm.toString(params.weight)))
    );
    vars.expectedImageHash = PrimitivesRPC.getImageHash(vm, vars.configJson);

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(params.signer1pk, Payload.hashFor(params.payload, address(baseSigImp)));

    vars.signature = PrimitivesRPC.toEncodedSignatureWithCheckpointerData(
      vm,
      vars.configJson,
      string(
        abi.encodePacked(
          vm.toString(vars.signer1addr), ":hash:", vm.toString(r), ":", vm.toString(s), ":", vm.toString(v)
        )
      ),
      !params.payload.noChainId,
      params.checkpointerData
    );

    // Set imageHash to 0 to indicate checkpointer is disabled
    vars.snapshot.imageHash = params.ignoredImageHash;
    vars.snapshot.checkpoint = params.oldCheckpoint;

    vm.mockCall(
      params.checkpointer, abi.encodeWithSelector(ICheckpointer.snapshotFor.selector), abi.encode(vars.snapshot)
    );

    (uint256 threshold, uint256 weight, bytes32 imageHash, uint256 checkpoint, bytes32 opHash) =
      baseSigImp.recoverPub(params.payload, vars.signature, false, address(0));
    assertEq(threshold, params.threshold);
    assertEq(weight, params.weight);
    assertEq(imageHash, vars.expectedImageHash);
    assertEq(checkpoint, params.checkpoint); // Should use checkpoint from config, not snapshot
    assertEq(opHash, Payload.hashFor(params.payload, address(baseSigImp)));
  }

  struct test_checkpointer_past_with_chain_params {
    Payload.Decoded payload;
    address checkpointer;
    bytes checkpointerData;
    uint256 signerPk1;
    uint256 signerPk2;
    uint56 checkpoint1;
    uint56 checkpoint2;
  }

  struct test_checkpointer_past_with_chain_vars {
    address signer1addr;
    address signer2addr;
    string config1Json;
    string config2Json;
    bytes32 config1ImageHash;
    bytes32 config2ImageHash;
    bytes signature1to2;
    bytes signature2toPayload;
    Snapshot snapshot;
    bytes32 r1;
    bytes32 r2;
    bytes32 s1;
    bytes32 s2;
    uint8 v1;
    uint8 v2;
    Payload.Decoded payloadApprove2;
    bytes chainedSignature;
  }

  function test_checkpointer_past_with_chain(
    test_checkpointer_past_with_chain_params memory params
  ) external {
    vm.assume(params.payload.calls.length < 3);
    boundToLegalPayload(params.payload);

    params.checkpointer = boundNoPrecompile(params.checkpointer);
    params.signerPk1 = boundPk(params.signerPk1);
    params.signerPk2 = boundPk(params.signerPk2);

    params.checkpoint1 = uint56(bound(params.checkpoint1, 0, type(uint56).max - 1));
    params.checkpoint2 = uint56(bound(params.checkpoint2, params.checkpoint1 + 1, type(uint56).max));

    test_checkpointer_past_with_chain_vars memory vars;

    vars.signer1addr = vm.addr(params.signerPk1);
    vars.signer2addr = vm.addr(params.signerPk2);

    vars.config1Json = PrimitivesRPC.newConfigWithCheckpointer(
      vm,
      params.checkpointer,
      1,
      params.checkpoint1,
      string(abi.encodePacked("signer:", vm.toString(vars.signer1addr), ":1"))
    );
    vars.config1ImageHash = PrimitivesRPC.getImageHash(vm, vars.config1Json);

    vars.config2Json = PrimitivesRPC.newConfigWithCheckpointer(
      vm,
      params.checkpointer,
      2,
      params.checkpoint2,
      string(abi.encodePacked("signer:", vm.toString(vars.signer2addr), ":2"))
    );
    vars.config2ImageHash = PrimitivesRPC.getImageHash(vm, vars.config2Json);

    vars.payloadApprove2.kind = Payload.KIND_CONFIG_UPDATE;
    vars.payloadApprove2.imageHash = vars.config2ImageHash;
    vars.payloadApprove2.noChainId = true;

    (vars.v1, vars.r1, vars.s1) = vm.sign(params.signerPk1, Payload.hashFor(vars.payloadApprove2, address(baseSigImp)));
    vars.signature1to2 = PrimitivesRPC.toEncodedSignatureWithCheckpointerData(
      vm,
      vars.config1Json,
      string(
        abi.encodePacked(
          vm.toString(vars.signer1addr),
          ":hash:",
          vm.toString(vars.r1),
          ":",
          vm.toString(vars.s1),
          ":",
          vm.toString(vars.v1)
        )
      ),
      false,
      params.checkpointerData
    );

    (vars.v2, vars.r2, vars.s2) = vm.sign(params.signerPk2, Payload.hashFor(params.payload, address(baseSigImp)));
    vars.signature2toPayload = PrimitivesRPC.toEncodedSignatureWithCheckpointerData(
      vm,
      vars.config2Json,
      string(
        abi.encodePacked(
          vm.toString(vars.signer2addr),
          ":hash:",
          vm.toString(vars.r2),
          ":",
          vm.toString(vars.s2),
          ":",
          vm.toString(vars.v2)
        )
      ),
      !params.payload.noChainId,
      params.checkpointerData
    );

    vars.snapshot.imageHash = vars.config2ImageHash;
    vars.snapshot.checkpoint = params.checkpoint2;

    vm.mockCall(
      params.checkpointer, abi.encodeWithSelector(ICheckpointer.snapshotFor.selector), abi.encode(vars.snapshot)
    );

    bytes[] memory signatures = new bytes[](2);
    signatures[0] = vars.signature2toPayload;
    signatures[1] = vars.signature1to2;
    vars.chainedSignature = PrimitivesRPC.concatSignatures(vm, signatures);

    (uint256 threshold, uint256 weight, bytes32 imageHash, uint256 checkpoint, bytes32 opHash) =
      baseSigImp.recoverPub(params.payload, vars.chainedSignature, false, address(0));
    assertEq(threshold, 1);
    assertEq(weight, 1);
    assertEq(imageHash, vars.config1ImageHash);
    assertEq(checkpoint, params.checkpoint1);
    assertEq(opHash, Payload.hashFor(params.payload, address(baseSigImp)));
  }

  struct test_checkpointer_disabled_with_chain_params {
    Payload.Decoded payload;
    address checkpointer;
    bytes checkpointerData;
    uint256 signerPk1;
    uint256 signerPk2;
    uint56 checkpoint1;
    uint56 checkpoint2;
    uint56 ignoredSnapshotCheckpoint;
  }

  struct test_checkpointer_disabled_with_chain_vars {
    address signer1addr;
    address signer2addr;
    string config1Json;
    string config2Json;
    bytes32 config1ImageHash;
    bytes32 config2ImageHash;
    bytes signature1to2;
    bytes signature2toPayload;
    bytes32 r1;
    bytes32 r2;
    bytes32 s1;
    bytes32 s2;
    uint8 v1;
    uint8 v2;
    Payload.Decoded payloadApprove2;
    bytes chainedSignature;
    Snapshot snapshot;
  }

  function test_checkpointer_disabled_with_chain(
    test_checkpointer_disabled_with_chain_params memory params
  ) external {
    vm.assume(params.payload.calls.length < 3);
    boundToLegalPayload(params.payload);

    params.checkpointer = boundNoPrecompile(params.checkpointer);
    params.signerPk1 = boundPk(params.signerPk1);
    params.signerPk2 = boundPk(params.signerPk2);

    params.checkpoint1 = uint56(bound(params.checkpoint1, 0, type(uint56).max - 1));
    params.checkpoint2 = uint56(bound(params.checkpoint2, params.checkpoint1 + 1, type(uint56).max));

    test_checkpointer_disabled_with_chain_vars memory vars;

    vars.signer1addr = vm.addr(params.signerPk1);
    vars.signer2addr = vm.addr(params.signerPk2);

    vars.config1Json = PrimitivesRPC.newConfigWithCheckpointer(
      vm,
      params.checkpointer,
      1,
      params.checkpoint1,
      string(abi.encodePacked("signer:", vm.toString(vars.signer1addr), ":1"))
    );
    vars.config1ImageHash = PrimitivesRPC.getImageHash(vm, vars.config1Json);

    vars.config2Json = PrimitivesRPC.newConfigWithCheckpointer(
      vm,
      params.checkpointer,
      2,
      params.checkpoint2,
      string(abi.encodePacked("signer:", vm.toString(vars.signer2addr), ":2"))
    );
    vars.config2ImageHash = PrimitivesRPC.getImageHash(vm, vars.config2Json);

    vars.payloadApprove2.kind = Payload.KIND_CONFIG_UPDATE;
    vars.payloadApprove2.imageHash = vars.config2ImageHash;
    vars.payloadApprove2.noChainId = true;

    (vars.v1, vars.r1, vars.s1) = vm.sign(params.signerPk1, Payload.hashFor(vars.payloadApprove2, address(baseSigImp)));
    vars.signature1to2 = PrimitivesRPC.toEncodedSignatureWithCheckpointerData(
      vm,
      vars.config1Json,
      string(
        abi.encodePacked(
          vm.toString(vars.signer1addr),
          ":hash:",
          vm.toString(vars.r1),
          ":",
          vm.toString(vars.s1),
          ":",
          vm.toString(vars.v1)
        )
      ),
      false,
      params.checkpointerData
    );

    (vars.v2, vars.r2, vars.s2) = vm.sign(params.signerPk2, Payload.hashFor(params.payload, address(baseSigImp)));
    vars.signature2toPayload = PrimitivesRPC.toEncodedSignatureWithCheckpointerData(
      vm,
      vars.config2Json,
      string(
        abi.encodePacked(
          vm.toString(vars.signer2addr),
          ":hash:",
          vm.toString(vars.r2),
          ":",
          vm.toString(vars.s2),
          ":",
          vm.toString(vars.v2)
        )
      ),
      !params.payload.noChainId,
      params.checkpointerData
    );

    vars.snapshot.imageHash = bytes32(0);
    vars.snapshot.checkpoint = params.ignoredSnapshotCheckpoint;

    vm.mockCall(
      params.checkpointer, abi.encodeWithSelector(ICheckpointer.snapshotFor.selector), abi.encode(vars.snapshot)
    );

    bytes[] memory signatures = new bytes[](2);
    signatures[0] = vars.signature2toPayload;
    signatures[1] = vars.signature1to2;
    vars.chainedSignature = PrimitivesRPC.concatSignatures(vm, signatures);

    (uint256 threshold, uint256 weight, bytes32 imageHash, uint256 checkpoint, bytes32 opHash) =
      baseSigImp.recoverPub(params.payload, vars.chainedSignature, false, address(0));
    assertEq(threshold, 1);
    assertEq(weight, 1);
    assertEq(imageHash, vars.config1ImageHash);
    assertEq(checkpoint, params.checkpoint1);
    assertEq(opHash, Payload.hashFor(params.payload, address(baseSigImp)));
  }

  struct test_checkpointer_old_checkpoint_with_chain_params {
    Payload.Decoded payload;
    address checkpointer;
    bytes checkpointerData;
    uint256 signerPk1;
    uint256 signerPk2;
    uint56 checkpoint1;
    uint56 checkpoint2;
    uint56 oldCheckpoint;
    bytes32 ignoredImageHash;
  }

  struct test_checkpointer_old_checkpoint_with_chain_vars {
    address signer1addr;
    address signer2addr;
    string config1Json;
    string config2Json;
    bytes32 config1ImageHash;
    bytes32 config2ImageHash;
    bytes signature1to2;
    bytes signature2toPayload;
    bytes32 r1;
    bytes32 r2;
    bytes32 s1;
    bytes32 s2;
    uint8 v1;
    uint8 v2;
    Payload.Decoded payloadApprove2;
    bytes chainedSignature;
    Snapshot snapshot;
  }

  function test_checkpointer_old_checkpoint_with_chain(
    test_checkpointer_old_checkpoint_with_chain_params memory params
  ) external {
    vm.assume(params.payload.calls.length < 3);
    boundToLegalPayload(params.payload);

    params.checkpointer = boundNoPrecompile(params.checkpointer);
    params.signerPk1 = boundPk(params.signerPk1);
    params.signerPk2 = boundPk(params.signerPk2);

    params.checkpoint1 = uint56(bound(params.checkpoint1, 1, type(uint56).max - 1));
    params.checkpoint2 = uint56(bound(params.checkpoint2, params.checkpoint1 + 1, type(uint56).max));
    params.oldCheckpoint = uint56(bound(params.oldCheckpoint, 0, params.checkpoint1 - 1));

    test_checkpointer_old_checkpoint_with_chain_vars memory vars;

    vars.signer1addr = vm.addr(params.signerPk1);
    vars.signer2addr = vm.addr(params.signerPk2);

    vars.config1Json = PrimitivesRPC.newConfigWithCheckpointer(
      vm,
      params.checkpointer,
      1,
      params.checkpoint1,
      string(abi.encodePacked("signer:", vm.toString(vars.signer1addr), ":1"))
    );
    vars.config1ImageHash = PrimitivesRPC.getImageHash(vm, vars.config1Json);

    vars.config2Json = PrimitivesRPC.newConfigWithCheckpointer(
      vm,
      params.checkpointer,
      2,
      params.checkpoint2,
      string(abi.encodePacked("signer:", vm.toString(vars.signer2addr), ":2"))
    );
    vars.config2ImageHash = PrimitivesRPC.getImageHash(vm, vars.config2Json);

    vars.payloadApprove2.kind = Payload.KIND_CONFIG_UPDATE;
    vars.payloadApprove2.imageHash = vars.config2ImageHash;
    vars.payloadApprove2.noChainId = true;

    (vars.v1, vars.r1, vars.s1) = vm.sign(params.signerPk1, Payload.hashFor(vars.payloadApprove2, address(baseSigImp)));
    vars.signature1to2 = PrimitivesRPC.toEncodedSignatureWithCheckpointerData(
      vm,
      vars.config1Json,
      string(
        abi.encodePacked(
          vm.toString(vars.signer1addr),
          ":hash:",
          vm.toString(vars.r1),
          ":",
          vm.toString(vars.s1),
          ":",
          vm.toString(vars.v1)
        )
      ),
      false,
      params.checkpointerData
    );

    (vars.v2, vars.r2, vars.s2) = vm.sign(params.signerPk2, Payload.hashFor(params.payload, address(baseSigImp)));
    vars.signature2toPayload = PrimitivesRPC.toEncodedSignatureWithCheckpointerData(
      vm,
      vars.config2Json,
      string(
        abi.encodePacked(
          vm.toString(vars.signer2addr),
          ":hash:",
          vm.toString(vars.r2),
          ":",
          vm.toString(vars.s2),
          ":",
          vm.toString(vars.v2)
        )
      ),
      !params.payload.noChainId,
      params.checkpointerData
    );

    vars.snapshot.imageHash = params.ignoredImageHash;
    vars.snapshot.checkpoint = params.oldCheckpoint;

    vm.mockCall(
      params.checkpointer, abi.encodeWithSelector(ICheckpointer.snapshotFor.selector), abi.encode(vars.snapshot)
    );

    bytes[] memory signatures = new bytes[](2);
    signatures[0] = vars.signature2toPayload;
    signatures[1] = vars.signature1to2;
    vars.chainedSignature = PrimitivesRPC.concatSignatures(vm, signatures);

    (uint256 threshold, uint256 weight, bytes32 imageHash, uint256 checkpoint, bytes32 opHash) =
      baseSigImp.recoverPub(params.payload, vars.chainedSignature, false, address(0));
    assertEq(threshold, 1);
    assertEq(weight, 1);
    assertEq(imageHash, vars.config1ImageHash);
    assertEq(checkpoint, params.checkpoint1);
    assertEq(opHash, Payload.hashFor(params.payload, address(baseSigImp)));
  }

  struct test_checkpointer_unused_snapshot_chain_params_fail {
    Payload.Decoded payload;
    address checkpointer;
    bytes checkpointerData;
    uint256 signerPk1;
    uint256 signerPk2;
    uint56 checkpoint1;
    uint56 checkpoint2;
    uint56 snapshotCheckpoint;
    bytes32 snapshotImageHash;
  }

  struct test_checkpointer_unused_snapshot_chain_vars_fail {
    address signer1addr;
    address signer2addr;
    string config1Json;
    string config2Json;
    bytes32 config1ImageHash;
    bytes32 config2ImageHash;
    bytes signature1to2;
    bytes signature2toPayload;
    bytes32 r1;
    bytes32 r2;
    bytes32 s1;
    bytes32 s2;
    uint8 v1;
    uint8 v2;
    Payload.Decoded payloadApprove2;
    bytes chainedSignature;
    Snapshot snapshot;
  }

  function test_checkpointer_unused_snapshot_chain_fail(
    test_checkpointer_unused_snapshot_chain_params_fail memory params
  ) external {
    vm.assume(params.payload.calls.length < 3);
    boundToLegalPayload(params.payload);

    params.checkpointer = boundNoPrecompile(params.checkpointer);
    params.signerPk1 = boundPk(params.signerPk1);
    params.signerPk2 = boundPk(params.signerPk2);

    params.checkpoint1 = uint56(bound(params.checkpoint1, 0, type(uint56).max - 1));
    params.checkpoint2 = uint56(bound(params.checkpoint2, params.checkpoint1 + 1, type(uint56).max));
    params.snapshotCheckpoint = uint56(bound(params.snapshotCheckpoint, params.checkpoint1, type(uint56).max));

    test_checkpointer_unused_snapshot_chain_vars_fail memory vars;

    vars.signer1addr = vm.addr(params.signerPk1);
    vars.signer2addr = vm.addr(params.signerPk2);

    vars.config1Json = PrimitivesRPC.newConfigWithCheckpointer(
      vm,
      params.checkpointer,
      1,
      params.checkpoint1,
      string(abi.encodePacked("signer:", vm.toString(vars.signer1addr), ":1"))
    );
    vars.config1ImageHash = PrimitivesRPC.getImageHash(vm, vars.config1Json);

    vars.config2Json = PrimitivesRPC.newConfigWithCheckpointer(
      vm,
      params.checkpointer,
      2,
      params.checkpoint2,
      string(abi.encodePacked("signer:", vm.toString(vars.signer2addr), ":2"))
    );
    vars.config2ImageHash = PrimitivesRPC.getImageHash(vm, vars.config2Json);

    vm.assume(params.snapshotImageHash != vars.config1ImageHash);
    vm.assume(params.snapshotImageHash != vars.config2ImageHash);

    vars.payloadApprove2.kind = Payload.KIND_CONFIG_UPDATE;
    vars.payloadApprove2.imageHash = vars.config2ImageHash;
    vars.payloadApprove2.noChainId = true;

    (vars.v1, vars.r1, vars.s1) = vm.sign(params.signerPk1, Payload.hashFor(vars.payloadApprove2, address(baseSigImp)));
    vars.signature1to2 = PrimitivesRPC.toEncodedSignatureWithCheckpointerData(
      vm,
      vars.config1Json,
      string(
        abi.encodePacked(
          vm.toString(vars.signer1addr),
          ":hash:",
          vm.toString(vars.r1),
          ":",
          vm.toString(vars.s1),
          ":",
          vm.toString(vars.v1)
        )
      ),
      false,
      params.checkpointerData
    );

    (vars.v2, vars.r2, vars.s2) = vm.sign(params.signerPk2, Payload.hashFor(params.payload, address(baseSigImp)));
    vars.signature2toPayload = PrimitivesRPC.toEncodedSignatureWithCheckpointerData(
      vm,
      vars.config2Json,
      string(
        abi.encodePacked(
          vm.toString(vars.signer2addr),
          ":hash:",
          vm.toString(vars.r2),
          ":",
          vm.toString(vars.s2),
          ":",
          vm.toString(vars.v2)
        )
      ),
      !params.payload.noChainId,
      params.checkpointerData
    );

    vars.snapshot.imageHash = params.snapshotImageHash;
    vars.snapshot.checkpoint = params.snapshotCheckpoint;

    vm.mockCall(
      params.checkpointer, abi.encodeWithSelector(ICheckpointer.snapshotFor.selector), abi.encode(vars.snapshot)
    );

    bytes[] memory signatures = new bytes[](2);
    signatures[0] = vars.signature2toPayload;
    signatures[1] = vars.signature1to2;
    vars.chainedSignature = PrimitivesRPC.concatSignatures(vm, signatures);

    vm.expectRevert(abi.encodeWithSelector(BaseSig.UnusedSnapshot.selector, vars.snapshot));
    baseSigImp.recoverPub(params.payload, vars.chainedSignature, false, address(0));
  }

}
