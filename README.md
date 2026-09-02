Sequence v3 wallet contracts
============================

Sequence v3 wallet contracts, with implicit and explicit smart sessions.

## Development Setup

Install dependencies

```sh
pnpm install
```

Git hooks will be automatically installed.

## Testing

Install the [Sequence v3 SDK](https://github.com/0xsequence/sequence.js) and run a server using the following command:

```sh
cd ../sequence.js
pnpm build:packages
pnpm dev:server
```

Copy the `env.sample` file to `.env` and set the environment variables.

```sh
cp .env.sample .env
# Edit .env
```

Run tests

```sh
forge test
```

Run coverage (ignoring scripts and test files).

```sh
forge coverage --no-match-coverage "(script|test)"
# Or to generate and view in browser
forge coverage --no-match-coverage "(script|test)" --report lcov && genhtml -o report --branch-coverage lcov.info && py -m http.server -d report
```

Deploy contracts

```sh
forge script Deploy --rpc-url <xxx> --broadcast
```

> [!NOTE]
> Deployments use ERC-2470 for counter factual deployments.

## Simulator and Estimator

`Simulator` and `Estimator` are helpers for `eth_call` only. They are meant to be used with a state override that replaces a wallet's code with theirs, and the on-chain deployments only exist so that the bytecode can be copied.

Neither contract has any access control. `Simulator.simulate` is permissionless and performs arbitrary calls, including `delegatecall`, from the contract's address, and `Estimator` accepts any image hash so every signature passes. They must not hold assets and must not be set as a wallet implementation.
