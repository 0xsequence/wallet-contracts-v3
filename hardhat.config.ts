import { HardhatUserConfig } from 'hardhat/config'
import "@nomicfoundation/hardhat-foundry";

const config: HardhatUserConfig = {
  solidity: {
    version: '0.8.28',
    settings: {
      optimizer: {
        enabled: true,
        runs: 500000
      }
    }
  },
}

export default config
