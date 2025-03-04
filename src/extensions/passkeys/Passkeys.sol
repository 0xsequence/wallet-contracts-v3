// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { ISapientCompact } from "../../modules/interfaces/ISapient.sol";
import { LibBytes } from "../../utils/LibBytes.sol";

import { LibBytesPointer } from "../../utils/LibBytesPointer.sol";
import { LibOptim } from "../../utils/LibOptim.sol";
import { WebAuthn } from "../../utils/WebAuthn.sol";

contract Passkeys is ISapientCompact {

  error InvalidPasskeySignature(
    WebAuthn.WebAuthnAuth _webAuthnAuth, bool _requireUserVerification, bytes32 _x, bytes32 _y
  );

  function _rootForPasskey(bool _requireUserVerification, bytes32 _x, bytes32 _y) internal pure returns (bytes32) {
    bytes32 a = LibOptim.fkeccak256(_x, _y);

    bytes32 b;
    assembly {
      b := _requireUserVerification
    }

    return LibOptim.fkeccak256(b, a);
  }

  function _decodeSignature(
    bytes calldata _signature
  )
    internal
    pure
    returns (WebAuthn.WebAuthnAuth memory _webAuthnAuth, bool _requireUserVerification, bytes32 _x, bytes32 _y)
  {
    unchecked {
      // Global flag encoding:
      // 0000 000X : requireUserVerification
      // 0000 00X0 : 1 if 16 bits for authenticatorData size, 0 if 8 bits
      // 0000 0X00 : 1 if 16 bits for clientDataJSON size, 0 if 8 bits
      // 0000 X000 : 1 if 16 bits for challengeIndex, 0 if 8 bits
      // 000X 0000 : 1 if 16 bits for typeIndex, 0 if 8 bits
      // 00X0 0000 : 1 if fallback to abi decode data
      // XX00 0000 : unused

      bytes1 flags = _signature[0];
      if ((flags & 0x20) == 0) {
        _requireUserVerification = (flags & 0x01) != 0;
        uint256 bytesAuthDataSize = ((uint8(flags & 0x02)) >> 1) + 1;
        uint256 bytesClientDataJSONSize = ((uint8(flags & 0x04)) >> 2) + 1;
        uint256 bytesChallengeIndex = ((uint8(flags & 0x08)) >> 3) + 1;
        uint256 bytesTypeIndex = ((uint8(flags & 0x10)) >> 4) + 1;

        uint256 pointer = 1;

        {
          uint256 authDataSize;
          (authDataSize, pointer) = LibBytesPointer.readUintX(_signature, pointer, bytesAuthDataSize);
          uint256 nextPointer = pointer + authDataSize;
          _webAuthnAuth.authenticatorData = _signature[pointer:nextPointer];
          pointer = nextPointer;
        }

        {
          uint256 clientDataJSONSize;
          (clientDataJSONSize, pointer) = LibBytesPointer.readUintX(_signature, pointer, bytesClientDataJSONSize);
          uint256 nextPointer = pointer + clientDataJSONSize;
          _webAuthnAuth.clientDataJSON = string(_signature[pointer:nextPointer]);
          pointer = nextPointer;
        }

        (_webAuthnAuth.challengeIndex, pointer) = LibBytesPointer.readUintX(_signature, pointer, bytesChallengeIndex);
        (_webAuthnAuth.typeIndex, pointer) = LibBytesPointer.readUintX(_signature, pointer, bytesTypeIndex);

        (_webAuthnAuth.r, pointer) = LibBytesPointer.readBytes32(_signature, pointer);
        (_webAuthnAuth.s, pointer) = LibBytesPointer.readBytes32(_signature, pointer);

        (_x, pointer) = LibBytesPointer.readBytes32(_signature, pointer);
        _y = LibBytes.readBytes32(_signature, pointer);
      } else {
        (_webAuthnAuth, _requireUserVerification, _x, _y) =
          abi.decode(_signature[1:], (WebAuthn.WebAuthnAuth, bool, bytes32, bytes32));
      }
    }
  }

  function isValidSapientSignatureCompact(bytes32 _digest, bytes calldata _signature) external view returns (bytes32) {
    (WebAuthn.WebAuthnAuth memory _webAuthnAuth, bool _requireUserVerification, bytes32 _x, bytes32 _y) =
      _decodeSignature(_signature);

    if (!WebAuthn.verify(abi.encodePacked(_digest), _requireUserVerification, _webAuthnAuth, _x, _y)) {
      revert InvalidPasskeySignature(_webAuthnAuth, _requireUserVerification, _x, _y);
    }

    return _rootForPasskey(_requireUserVerification, _x, _y);
  }

}
