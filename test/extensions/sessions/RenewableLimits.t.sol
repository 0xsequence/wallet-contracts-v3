// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Test } from "forge-std/Test.sol";

import { SessionErrors } from "src/extensions/sessions/SessionErrors.sol";
import { SessionManager } from "src/extensions/sessions/SessionManager.sol";
import { SessionSig } from "src/extensions/sessions/SessionSig.sol";
import {
  IExplicitSessionManager,
  SessionPermissions
} from "src/extensions/sessions/explicit/IExplicitSessionManager.sol";
import {
  ParameterOperation,
  ParameterRule,
  Permission,
  UsageLimit
} from "src/extensions/sessions/explicit/Permission.sol";
import { Calls } from "src/modules/Calls.sol";
import { Payload } from "src/modules/Payload.sol";

contract RenewableLimitsWallet is Calls {

  bytes32 public imageHash;

  function setImageHash(
    bytes32 value
  ) external {
    imageHash = value;
  }

  function _isValidImage(
    bytes32 value
  ) internal view override returns (bool) {
    return value == imageHash;
  }

  function _updateImageHash(
    bytes32 value
  ) internal override {
    imageHash = value;
  }

}

contract RenewableLimitsTarget {

  uint256 public spent;
  uint256 public recorded;
  bool public fail;

  function setFail(
    bool value
  ) external {
    fail = value;
  }

  function spend(
    uint256 amount
  ) external payable {
    require(!fail, "payment failed");
    spent += amount;
  }

  function record(
    uint256 value
  ) external {
    recorded = value;
  }

}

contract RenewableLimitsDecoder {

  function decode(
    bytes calldata data
  ) external pure returns (SessionSig.DecodedSignature memory sig) {
    (sig,) = SessionSig.recoverConfiguration(data);
  }

}

contract RenewableLimitsTest is Test {

  SessionManager internal manager;
  RenewableLimitsWallet internal wallet;
  RenewableLimitsTarget internal target;
  RenewableLimitsDecoder internal decoder;
  SessionPermissions internal permission;
  uint256 internal constant SESSION_KEY = 123;
  address internal constant IDENTITY_SIGNER = address(0xCAFE);

  function setUp() public {
    vm.warp(1_000_000);
    manager = new SessionManager();
    wallet = new RenewableLimitsWallet();
    target = new RenewableLimitsTarget();
    decoder = new RenewableLimitsDecoder();
    permission.signer = vm.addr(SESSION_KEY);
    permission.chainId = block.chainid;
    permission.valueLimit = 1 ether;
    permission.start = uint64(block.timestamp);
    permission.period = 1 days;
    permission.permissions.push();
    permission.permissions[0].target = address(target);
    permission.permissions[0].rules
      .push(
        ParameterRule({
          cumulative: false,
          operation: ParameterOperation.EQUAL,
          value: bytes32(target.spend.selector),
          offset: 0,
          mask: bytes32(bytes4(0xffffffff))
        })
      );
    permission.permissions[0].rules
      .push(
        ParameterRule({
          cumulative: true,
          operation: ParameterOperation.LESS_THAN_OR_EQUAL,
          value: bytes32(uint256(100)),
          offset: 4,
          mask: bytes32(type(uint256).max)
        })
      );
    permission.permissions.push();
    permission.permissions[1].target = address(target);
    permission.permissions[1].rules
      .push(
        ParameterRule({
          cumulative: false,
          operation: ParameterOperation.EQUAL,
          value: bytes32(target.record.selector),
          offset: 0,
          mask: bytes32(bytes4(0xffffffff))
        })
      );
    vm.deal(address(wallet), 10 ether);
    _configure();
  }

  function test_decodeRenewableAndLegacyPermissions(
    bool renewable,
    bool nested
  ) public {
    if (!renewable) {
      permission.start = 0;
      permission.period = 0;
    }
    bytes memory config = _configuration(renewable);
    bytes32 imageHash = _sessionImageHash(renewable);
    if (nested) {
      config = abi.encodePacked(uint8(0x22), uint16(config.length), config);
    }
    SessionSig.DecodedSignature memory sig = decoder.decode(config);
    assertEq(sig.imageHash, imageHash);
    assertEq(sig.sessionPermissions.length, 1);
    assertEq(keccak256(abi.encode(sig.sessionPermissions[0])), keccak256(abi.encode(permission)));
  }

  function test_rejectsZeroRenewalPeriod() public {
    permission.period = 0;
    bytes memory config = _configuration(true);
    vm.expectRevert(SessionErrors.InvalidRenewalPeriod.selector);
    decoder.decode(config);
  }

  function test_fixedIntervalBoundaries(
    uint64 start,
    uint64 period,
    uint256 skipped
  ) public {
    start = uint64(bound(start, 1, type(uint64).max));
    period = uint64(bound(period, 1, type(uint32).max));
    skipped = bound(skipped, 1, 1000);
    permission.start = start;
    permission.period = period;
    vm.warp(start);
    _configure();
    _execute(_payload(40, 0));
    _execute(_payload(60, 0));
    assertEq(_ruleUsage(), 100);
    bytes32 firstUsageHash = _ruleUsageHash();

    Payload.Decoded memory payload = _payload(1, 0);
    vm.warp(uint256(start) + period - 1);
    vm.expectRevert(SessionErrors.InvalidPermission.selector);
    _execute(payload);

    vm.warp(uint256(start) + uint256(period) * skipped);
    assertEq(_ruleUsage(), 0);
    payload = _payload(101, 0);
    vm.expectRevert(SessionErrors.InvalidPermission.selector);
    _execute(payload);
    _execute(_payload(100, 0));
    assertEq(_ruleUsage(), 100);
    assertEq(_ruleUsageHash(), firstUsageHash);
    assertEq(manager.getLimitUsageForPeriod(address(wallet), firstUsageHash, 1), 0);
    assertEq(manager.getLimitUsage(address(wallet), firstUsageHash), _packedUsage(100));
  }

  function test_nativeLimitRenewsAlongsideParameterLimit() public {
    _execute(_payload(10, 0.4 ether));
    _execute(_payload(10, 0.6 ether));
    assertEq(_valueUsage(), 1 ether);
    assertEq(_ruleUsage(), 20);
    Payload.Decoded memory payload = _payload(1, 1);
    vm.expectRevert(SessionErrors.InvalidValue.selector);
    _execute(payload);
    vm.warp(uint256(permission.start) + permission.period);
    assertEq(_valueUsage(), 0);
    assertEq(_ruleUsage(), 0);
    _execute(_payload(100, 1 ether));
    assertEq(_ruleUsage(), 100);
    assertEq(_valueUsage(), 1 ether);
  }

  function test_countsEveryCallInBatch(
    uint256 a,
    uint256 b
  ) public {
    a = bound(a, 0, 100);
    b = bound(b, 0, 100);
    Payload.Decoded memory payload = _payload(a + b, 0);
    Payload.Call[] memory calls = new Payload.Call[](3);
    calls[0] = payload.calls[0];
    calls[1] = _spendCall(a, 0);
    calls[2] = _spendCall(b, 0);
    payload.calls = calls;
    if (a + b > 100) {
      vm.expectRevert(SessionErrors.InvalidPermission.selector);
      _execute(payload);
      assertEq(_ruleUsage(), 0);
    } else {
      _execute(payload);
      assertEq(_ruleUsage(), a + b);
      assertEq(target.spent(), a + b);
    }
  }

  function test_preservesGeneralPermissionsAndPerCallRules() public {
    Payload.Decoded memory payload;
    payload.kind = Payload.KIND_TRANSACTIONS;
    payload.calls = new Payload.Call[](1);
    payload.calls[0].to = address(target);
    payload.calls[0].data = abi.encodeCall(target.record, (12345));
    payload.calls[0].behaviorOnError = Payload.BEHAVIOR_REVERT_ON_ERROR;
    _execute(payload);
    assertEq(target.recorded(), 12345);
    assertEq(_ruleUsage(), 0);

    payload = _payload(1, 0);
    payload.calls[1].data = abi.encodeWithSelector(bytes4(0x11223344), uint256(1));
    vm.expectRevert(SessionErrors.InvalidPermission.selector);
    _execute(payload);
  }

  function test_legacyLimitsRemainLifetime() public {
    permission.start = 0;
    permission.period = 0;
    _configure();
    _execute(_payload(40, 0.4 ether));
    vm.warp(block.timestamp + 365 days);
    _execute(_payload(60, 0.6 ether));
    assertEq(_ruleUsage(), 100);
    assertEq(_valueUsage(), 1 ether);
    Payload.Decoded memory payload = _payload(1, 0);
    vm.expectRevert(SessionErrors.InvalidPermission.selector);
    _execute(payload);
    payload = _payload(0, 1);
    vm.expectRevert(SessionErrors.InvalidValue.selector);
    _execute(payload);
  }

  function test_rejectsCallsBeforeStartAndAfterDeadline() public {
    permission.deadline = permission.start + permission.period;
    _configure();
    Payload.Decoded memory payload = _payload(10, 0);
    vm.warp(uint256(permission.start) - 1);
    vm.expectPartialRevert(SessionErrors.SessionNotStarted.selector);
    _execute(payload);
    vm.warp(permission.start);
    _execute(payload);
    vm.warp(permission.deadline);
    _execute(_payload(100, 0));
    payload = _payload(0, 0);
    vm.warp(uint256(permission.deadline) + 1);
    vm.expectPartialRevert(SessionErrors.SessionExpired.selector);
    _execute(payload);
  }

  function test_renewalScheduleRequiresWalletAuthorization(
    uint8 change
  ) public {
    change = uint8(bound(change, 0, 2));
    if (change == 0) {
      permission.start--;
    } else if (change == 1) {
      permission.period++;
    } else {
      permission.start = 0;
      permission.period = 0;
    }
    Payload.Decoded memory payload = _payload(10, 0);
    vm.expectPartialRevert(Calls.InvalidSignature.selector);
    _execute(payload);
  }

  function test_oldPeriodSignatureCannotConsumeNewPeriod() public {
    Payload.Decoded memory payload = _payload(10, 0);
    bytes memory signature = _signature(payload);
    vm.warp(uint256(permission.start) + permission.period);
    vm.expectRevert(SessionErrors.InvalidLimitUsageIncrement.selector);
    wallet.execute(_pack(payload), signature);
    assertEq(_ruleUsage(), 0);
  }

  function test_rejectsLifetimeAndWrongPeriodAccounting(
    bool native,
    bool lifetime
  ) public {
    Payload.Decoded memory payload = _payload(10, native ? 1 : 0);
    UsageLimit[] memory limits = abi.decode(_stripSelector(payload.calls[0].data), (UsageLimit[]));
    uint256 index = native ? 1 : 0;
    limits[index].usageAmount = (limits[index].usageAmount & type(uint192).max) | (uint256(lifetime ? 0 : 2) << 192);
    payload.calls[0].data = abi.encodeCall(IExplicitSessionManager.incrementUsageLimit, (limits));
    vm.expectRevert(SessionErrors.InvalidLimitUsageIncrement.selector);
    _execute(payload);
  }

  function test_cannotDecreaseCurrentPeriodUsage(
    bool lifetime
  ) public {
    if (lifetime) {
      permission.start = 0;
      permission.period = 0;
      _configure();
    }
    _execute(_payload(40, 0));
    UsageLimit[] memory limits = new UsageLimit[](1);
    limits[0] = UsageLimit(_ruleUsageHash(), _packedUsage(39));
    vm.prank(address(wallet));
    vm.expectRevert(SessionErrors.InvalidLimitUsageIncrement.selector);
    manager.incrementUsageLimit(limits);
    assertEq(_ruleUsage(), 40);
  }

  function test_failedCallRollsBackPeriodUsage() public {
    target.setFail(true);
    Payload.Decoded memory payload = _payload(10, 0.1 ether);
    vm.expectPartialRevert(Calls.Reverted.selector);
    _execute(payload);
    assertEq(_ruleUsage(), 0);
    assertEq(_valueUsage(), 0);
    assertEq(wallet.readNonce(0), 0);
    target.setFail(false);
    _execute(payload);
    assertEq(_ruleUsage(), 10);
    assertEq(_valueUsage(), 0.1 ether);
  }

  function test_usageIsIsolatedByWalletAndSchedule() public {
    _execute(_payload(40, 0));
    bytes32 originalHash = _ruleUsageHash();
    UsageLimit[] memory limits = new UsageLimit[](1);
    limits[0] = UsageLimit(originalHash, _packedUsage(100));
    vm.prank(address(0xBEEF));
    manager.incrementUsageLimit(limits);
    assertEq(_ruleUsage(), 40);

    permission.period++;
    _configure();
    _execute(_payload(100, 0));
    assertEq(_ruleUsage(), 100);
    permission.period--;
    _configure();
    assertEq(_ruleUsage(), 40);
    _execute(_payload(60, 0));
    assertEq(manager.getLimitUsage(address(wallet), originalHash), _packedUsage(100));
  }

  function test_mixedLifetimeAndRenewableSigners() public {
    bytes memory config = _configuration(true);
    bytes32 sessionImageHash = _sessionImageHash(true);
    uint64 start = permission.start;
    uint64 period = permission.period;
    bytes32 ruleHash = _ruleUsageHash();
    bytes32 valueHash = _valueUsageHash();

    permission.signer = vm.addr(456);
    permission.start = 0;
    permission.period = 0;
    bytes memory otherPermissions = _packedPermissions(false);
    config = abi.encodePacked(config, uint8(0), otherPermissions);
    sessionImageHash = keccak256(abi.encode(sessionImageHash, keccak256(abi.encodePacked(uint8(0), otherPermissions))));
    _configureWithSessionHash(sessionImageHash);
    bytes32 lifetimeRuleHash = _ruleUsageHash();
    bytes32 lifetimeValueHash = _valueUsageHash();

    permission.signer = vm.addr(SESSION_KEY);
    permission.start = start;
    permission.period = period;
    for (uint256 attempt = 0; attempt < 2; attempt++) {
      UsageLimit[] memory limits = new UsageLimit[](4);
      limits[0] = UsageLimit(_ruleUsageHash(), _packedUsage(100));
      limits[1] = UsageLimit(_valueUsageHash(), _packedUsage(1 ether));
      limits[2] = UsageLimit(lifetimeRuleHash, 100 * (attempt + 1));
      limits[3] = UsageLimit(lifetimeValueHash, 1 ether * (attempt + 1));
      Payload.Decoded memory payload;
      payload.kind = Payload.KIND_TRANSACTIONS;
      payload.nonce = wallet.readNonce(0);
      payload.calls = new Payload.Call[](3);
      payload.calls[0].to = address(manager);
      payload.calls[0].data = abi.encodeCall(IExplicitSessionManager.incrementUsageLimit, (limits));
      payload.calls[0].behaviorOnError = Payload.BEHAVIOR_REVERT_ON_ERROR;
      payload.calls[1] = _spendCall(100, 1 ether);
      payload.calls[2] = _spendCall(100, 1 ether);

      bytes memory signature = abi.encodePacked(uint24(config.length), config, uint8(0));
      bytes32 payloadHash = Payload.hashFor(payload, address(wallet));
      for (uint256 i = 0; i < payload.calls.length; i++) {
        (uint8 v, bytes32 rs, bytes32 s) =
          vm.sign(i == 2 ? 456 : SESSION_KEY, keccak256(abi.encodePacked(payloadHash, i)));
        signature = abi.encodePacked(signature, uint8(0), rs, bytes32(uint256(s) | (uint256(v - 27) << 255)));
      }
      signature = abi.encodePacked(hex"000199", address(manager), uint16(signature.length), signature);
      if (attempt == 1) {
        vm.expectRevert(SessionErrors.InvalidPermission.selector);
      }
      wallet.execute(_pack(payload), signature);
      vm.warp(uint256(start) + period);
    }
    assertEq(manager.getLimitUsageForPeriod(address(wallet), ruleHash, 1), 100);
    assertEq(manager.getLimitUsageForPeriod(address(wallet), valueHash, 1), 1 ether);
    assertEq(manager.getLimitUsage(address(wallet), lifetimeRuleHash), 100);
    assertEq(manager.getLimitUsage(address(wallet), lifetimeValueHash), 1 ether);
    assertEq(_ruleUsage(), 0);
    assertEq(_valueUsage(), 0);
  }

  function test_ignoredFailureRetainsOriginalAccountingBehavior() public {
    target.setFail(true);
    Payload.Decoded memory payload = _payload(10, 0.1 ether);
    payload.calls[1].behaviorOnError = Payload.BEHAVIOR_IGNORE_ERROR;
    _execute(payload);
    assertEq(_ruleUsage(), 10);
    assertEq(_valueUsage(), 0.1 ether);
    assertEq(target.spent(), 0);
  }

  function test_reusesStorageAcrossPeriods() public {
    bytes32 ruleHash = _ruleUsageHash();
    bytes32 valueHash = _valueUsageHash();
    vm.record();
    _execute(_payload(100, 1 ether));
    (, bytes32[] memory firstWrites) = vm.accesses(address(manager));
    // One packed slot for each of the parameter and native-value counters.
    assertEq(firstWrites.length, 2);

    for (uint256 i = 1; i <= 8; i++) {
      vm.warp(uint256(permission.start) + uint256(permission.period) * i * 1000);
      assertEq(_ruleUsage(), 0);
      assertEq(_valueUsage(), 0);
      vm.record();
      _execute(_payload(i, i * 0.01 ether));
      (, bytes32[] memory writes) = vm.accesses(address(manager));
      assertEq(writes, firstWrites);
      assertEq(_ruleUsageHash(), ruleHash);
      assertEq(_valueUsageHash(), valueHash);
      assertEq(_ruleUsage(), i);
      assertEq(_valueUsage(), i * 0.01 ether);
      assertEq(manager.getLimitUsageForPeriod(address(wallet), ruleHash, 1), 0);
    }
  }

  function test_cannotMoveCounterToEarlierPeriod() public {
    vm.warp(uint256(permission.start) + permission.period);
    _execute(_payload(40, 0));
    UsageLimit[] memory limits = new UsageLimit[](1);
    limits[0] = UsageLimit(_ruleUsageHash(), (uint256(1) << 192) | 100);
    vm.prank(address(wallet));
    vm.expectRevert(SessionErrors.InvalidLimitUsageIncrement.selector);
    manager.incrementUsageLimit(limits);
    assertEq(_ruleUsage(), 40);
  }

  function test_failedRenewalPreservesPreviousPeriod() public {
    _execute(_payload(40, 0.4 ether));
    bytes32 usageHash = _ruleUsageHash();
    vm.warp(uint256(permission.start) + permission.period);
    target.setFail(true);
    Payload.Decoded memory payload = _payload(10, 0.1 ether);
    vm.expectPartialRevert(Calls.Reverted.selector);
    _execute(payload);
    assertEq(_ruleUsage(), 0);
    assertEq(_valueUsage(), 0);
    assertEq(manager.getLimitUsageForPeriod(address(wallet), usageHash, 1), 40);
    target.setFail(false);
    _execute(payload);
    assertEq(_ruleUsage(), 10);
    assertEq(_valueUsage(), 0.1 ether);
    assertEq(manager.getLimitUsageForPeriod(address(wallet), usageHash, 1), 0);
  }

  function test_amountPackingBounds(
    bool native
  ) public {
    uint256 maximum = type(uint192).max;
    permission.permissions[0].rules[1].value = bytes32(type(uint256).max);
    permission.valueLimit = type(uint256).max;
    vm.deal(address(wallet), maximum + 1);
    _configure();
    _execute(_payload(native ? 0 : maximum, native ? maximum : 0));
    assertEq(native ? _valueUsage() : _ruleUsage(), maximum);
    Payload.Decoded memory payload = _payload(native ? 0 : 1, native ? 1 : 0);
    vm.expectRevert(SessionErrors.InvalidLimitUsageIncrement.selector);
    _execute(payload);
    assertEq(native ? _valueUsage() : _ruleUsage(), maximum);
  }

  function test_periodPackingBounds() public {
    vm.warp(uint256(permission.start) + uint256(permission.period) * (type(uint64).max - 1));
    _execute(_payload(40, 0));
    assertEq(_ruleUsage(), 40);
    bytes32 usageHash = _ruleUsageHash();
    uint256 packed = manager.getLimitUsage(address(wallet), usageHash);
    assertEq(packed >> 192, type(uint64).max);
    vm.warp(block.timestamp + permission.period);
    Payload.Decoded memory payload = _payload(10, 0);
    vm.expectRevert(SessionErrors.InvalidLimitUsageIncrement.selector);
    _execute(payload);
    assertEq(manager.getLimitUsage(address(wallet), usageHash), packed);
  }

  function test_legacyAmountsRetainFullWidth() public {
    permission.start = 0;
    permission.period = 0;
    permission.permissions[0].rules[1].value = bytes32(type(uint256).max);
    _configure();
    _execute(_payload(type(uint256).max, 0));
    assertEq(_ruleUsage(), type(uint256).max);
    assertEq(manager.getLimitUsage(address(wallet), _ruleUsageHash()), type(uint256).max);
  }

  function _configure() internal {
    _configureWithSessionHash(_sessionImageHash(permission.period != 0));
  }

  function _configureWithSessionHash(
    bytes32 sessionImageHash
  ) internal {
    bytes32 imageHash =
      keccak256(abi.encodePacked("Sequence sapient config:\n", address(manager), uint256(1), sessionImageHash));
    imageHash = keccak256(abi.encode(imageHash, uint256(1)));
    imageHash = keccak256(abi.encode(imageHash, uint256(0)));
    wallet.setImageHash(keccak256(abi.encode(imageHash, uint256(0))));
  }

  function _sessionImageHash(
    bool renewable
  ) internal view returns (bytes32) {
    bytes32 identity = keccak256(abi.encodePacked(uint8(4), IDENTITY_SIGNER));
    bytes32 leaf = keccak256(abi.encodePacked(uint8(renewable ? 5 : 0), _packedPermissions(renewable)));
    return keccak256(abi.encode(identity, leaf));
  }

  function _configuration(
    bool renewable
  ) internal view returns (bytes memory) {
    return abi.encodePacked(uint8(0x40), IDENTITY_SIGNER, uint8(renewable ? 0x50 : 0), _packedPermissions(renewable));
  }

  function _packedPermissions(
    bool renewable
  ) internal view returns (bytes memory encoded) {
    encoded = abi.encodePacked(permission.signer, permission.chainId, permission.valueLimit, permission.deadline);
    if (renewable) {
      encoded = abi.encodePacked(encoded, permission.start, permission.period);
    }
    encoded = abi.encodePacked(encoded, uint8(permission.permissions.length));
    for (uint256 i = 0; i < permission.permissions.length; i++) {
      Permission memory p = permission.permissions[i];
      encoded = abi.encodePacked(encoded, p.target, uint8(p.rules.length));
      for (uint256 j = 0; j < p.rules.length; j++) {
        ParameterRule memory rule = p.rules[j];
        encoded = abi.encodePacked(
          encoded, uint8(uint8(rule.operation) << 1 | (rule.cumulative ? 1 : 0)), rule.value, rule.offset, rule.mask
        );
      }
    }
  }

  function _scope(
    bytes32 base
  ) internal view returns (bytes32) {
    if (permission.period == 0) {
      return base;
    }
    bytes32 usageNamespace = keccak256(abi.encode(permission.start, permission.period));
    return keccak256(abi.encode(base, usageNamespace));
  }

  function _ruleUsageHash() internal view returns (bytes32) {
    return _scope(keccak256(abi.encode(permission.signer, permission.permissions[0], uint256(1))));
  }

  function _valueUsageHash() internal view returns (bytes32) {
    return _scope(keccak256(abi.encode(permission.signer, manager.VALUE_TRACKING_ADDRESS())));
  }

  function _ruleUsage() internal view returns (uint256) {
    return manager.getLimitUsageForPeriod(address(wallet), _ruleUsageHash(), _usagePeriod());
  }

  function _valueUsage() internal view returns (uint256) {
    return manager.getLimitUsageForPeriod(address(wallet), _valueUsageHash(), _usagePeriod());
  }

  function _usagePeriod() internal view returns (uint256) {
    return permission.period == 0 ? 0 : (block.timestamp - permission.start) / permission.period + 1;
  }

  function _packedUsage(
    uint256 amount
  ) internal view returns (uint256) {
    return (_usagePeriod() << 192) | amount;
  }

  function _payload(
    uint256 amount,
    uint256 value
  ) internal view returns (Payload.Decoded memory payload) {
    payload.kind = Payload.KIND_TRANSACTIONS;
    payload.nonce = wallet.readNonce(0);
    payload.calls = new Payload.Call[](2);
    uint256 nativeTotal = _valueUsage() + value;
    UsageLimit[] memory limits = new UsageLimit[](nativeTotal > 0 ? 2 : 1);
    limits[0] = UsageLimit(_ruleUsageHash(), _packedUsage(_ruleUsage() + amount));
    if (nativeTotal > 0) {
      limits[1] = UsageLimit(_valueUsageHash(), _packedUsage(nativeTotal));
    }
    payload.calls[0].to = address(manager);
    payload.calls[0].data = abi.encodeCall(IExplicitSessionManager.incrementUsageLimit, (limits));
    payload.calls[0].behaviorOnError = Payload.BEHAVIOR_REVERT_ON_ERROR;
    payload.calls[1] = _spendCall(amount, value);
  }

  function _spendCall(
    uint256 amount,
    uint256 value
  ) internal view returns (Payload.Call memory call) {
    call.to = address(target);
    call.data = abi.encodeCall(target.spend, (amount));
    call.value = value;
    call.behaviorOnError = Payload.BEHAVIOR_REVERT_ON_ERROR;
  }

  function _signature(
    Payload.Decoded memory payload
  ) internal view returns (bytes memory) {
    bytes memory config = _configuration(permission.period != 0);
    bytes memory signature = abi.encodePacked(uint24(config.length), config, uint8(0));
    bytes32 payloadHash = Payload.hashFor(payload, address(wallet));
    for (uint256 i = 0; i < payload.calls.length; i++) {
      uint8 index = bytes4(payload.calls[i].data) == target.record.selector ? 1 : 0;
      bytes32 hash = keccak256(abi.encodePacked(payloadHash, i));
      (uint8 v, bytes32 r, bytes32 s) = vm.sign(SESSION_KEY, hash);
      signature = abi.encodePacked(signature, index, r, bytes32(uint256(s) | (uint256(v - 27) << 255)));
    }
    return abi.encodePacked(hex"000199", address(manager), uint16(signature.length), signature);
  }

  function _execute(
    Payload.Decoded memory payload
  ) internal {
    wallet.execute(_pack(payload), _signature(payload));
  }

  function _pack(
    Payload.Decoded memory payload
  ) internal pure returns (bytes memory packed) {
    packed = abi.encodePacked(uint8(0x0f), uint56(payload.nonce), uint8(payload.calls.length));
    for (uint256 i = 0; i < payload.calls.length; i++) {
      Payload.Call memory call = payload.calls[i];
      uint8 flags = 0x06 | uint8(call.behaviorOnError << 6);
      packed = abi.encodePacked(packed, flags, call.to, call.value, uint24(call.data.length), call.data);
    }
  }

  function _stripSelector(
    bytes memory data
  ) internal pure returns (bytes memory result) {
    result = new bytes(data.length - 4);
    for (uint256 i = 0; i < result.length; i++) {
      result[i] = data[i + 4];
    }
  }

}
