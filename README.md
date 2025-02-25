# Sequence v3 - Contracts + SDK

Sequence v3 contracts and SDKs, with implicit and explicit smart sessions.

## Development Setup

Install dependencies

```sh
pnpm install
```

Git hooks will be automatically installed.

## Testing

Install the [Sequence Core SDK](https://github.com/0xsequence/sequence-core) and run a server using the following command:

```sh
cd ../sequence-core
pnpm build
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

Deploy contracts

```sh
forge script Deploy --rpc-url <xxx> --broadcast
```


> [!NOTE]
> Deployments use ERC-2470 for counter factual deployments.
