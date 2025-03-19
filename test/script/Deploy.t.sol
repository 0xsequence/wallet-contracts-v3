// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Test } from "forge-std/Test.sol";
import { Deploy } from "script/Deploy.s.sol";
import { DeployMocks } from "script/DeployMocks.s.sol";
// import { Factory } from "src/Factory.sol";
// import { Guest } from "src/Guest.sol";
import { Stage1Module } from "src/Stage1Module.sol";
// import { Stage2Module } from "src/Stage2Module.sol";
// import { SessionManager } from "src/extensions/sessions/SessionManager.sol";
import { console } from "forge-std/console.sol";

contract DeployTest is Test {

  Deploy public deployer;
  DeployMocks public deployerMocks;

  function setUp() external {
    deployer = new Deploy();
    deployerMocks = new DeployMocks();
    vm.mockCall(address(deployer), abi.encodeWithSignature("PRIVATE_KEY()"), abi.encode(uint256(1)));
    deployer.run();
    deployerMocks.run();
  }

  function testContractsDeployed() public {
    console.log("Factory address:", address(deployer.factory()));
    // Verify all contracts are deployed
    assertTrue(
      address(deployer.factory()) == address(0x4B755c6A321C86bD35bBbb5CD56321FE48b51d1e), "Factory not deployed"
    );
    assertTrue(
      address(deployer.stage1Module()) == address(0x486300225986f854a03815B5C9f11d0abd83f6F9),
      "Stage1Module not deployed"
    );
    assertTrue(
      address(deployer.stage2Module()) == address(0x50184E6a3c237Cfd1cCf359A8f9F2D0Fdc262f0B),
      "Stage2Module not deployed"
    );
    assertTrue(address(deployer.guest()) == address(0x2F2FED5893257F470308a64e041cbAd46501f68a), "Guest not deployed");
    assertTrue(
      address(deployer.sessionManager()) == address(0x486300225986f854a03815B5C9f11d0abd83f6F9),
      "SessionManager not deployed"
    );
  }

  function testStageModulesInitialization() public {
    // Verify Stage modules are initialized with correct factory address
    assertEq(address(deployer.stage1Module()), address(deployer.factory()), "Stage1Module factory mismatch");
    assertEq(address(deployer.stage2Module()), address(deployer.factory()), "Stage2Module factory mismatch");
  }

  function testWalletExecution() public {
    console.log("Deploying wallet...");
    console.log("Factory address:", address(deployer.factory()));
    console.log("Stage1Module address:", address(deployer.stage1Module()));
    Stage1Module wallet = Stage1Module(
      payable(
        deployer.factory().deploy(
          address(deployer.stage1Module()), bytes32(0x7a111a5baa8cf173ef51929208d2f015e440ac01269de7b5d1e360ebcec01e3c)
        )
      )
    );
    console.log("Wallet address:", address(wallet));
    console.log("Wallet code length:", address(wallet).code.length);

    console.logBool(address(deployer.stage1Module()).code.length > 0);
    console.logAddress(address(deployer.stage1Module()));

    wallet.execute(
      hex"130004e6efbd92ea142ef5d55c41f772c6a5441e1e17ad000084ad387c8a00000000000000000000000000000000000000000000000000000000000008cf000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000033322550000000000000000000000000000000000000000000000000000000000",
      hex"040001117e5f4552091a69125d5dfcb7b8c2659029395bdf80fd4ecc15aa893cb973418da8faf16c198f54534638e89147ce42290883812dd5"
    );
  }

  function testWalletExecutionV2() public {
    console.log("Deploying wallet...");
    console.log("Factory address:", address(deployer.factory()));
    console.log("Stage1Module address:", address(deployer.stage1Module()));
    Stage1Module wallet = Stage1Module(
      payable(
        deployer.factory().deploy(
          address(deployer.stage1Module()), bytes32(0x80e4418878f543de205b1cd2a89c275e6da6b75c4369c8695e543fab4f35421c)
        )
      )
    );
    console.log("Wallet address:", address(wallet));
    console.logBytes(address(wallet).code);
    console.log("Wallet code length:", address(wallet).code.length);
    assertEq(address(wallet), address(0x51fE6c57bB03E8cdE85c1eDF607a2FB9CB1E4f51));

    console.logBool(address(deployer.stage1Module()).code.length > 0);
    console.logAddress(address(deployer.stage1Module()));

    wallet.execute(
      hex"130044e6efbd92ea142ef5d55c41f772c6a5441e1e17ad000084ad387c8a00000000000000000000000000000000000000000000000000000000000008cf000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000033322550000000000000000000000000000000000000000000000000000000000",
      hex"040001117e5f4552091a69125d5dfcb7b8c2659029395bdf80f06f38ffd885b3be0e9aac1aabfd2c6897f54ebe49c7745203871ad8f38b2bfc"
    );
  }

}
