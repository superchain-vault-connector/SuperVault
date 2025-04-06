# SuperVault

## 🚀 Getting Started

### 1. Install prerequisites: `foundry`

`supersim` requires `anvil` to be installed.

Follow [this guide](https://book.getfoundry.sh/getting-started/installation) to install Foundry.

### 2. Clone and navigate to the repository:

```sh
git clone git@github.com:superchain-vault-connector/SuperVault.git
cd SuperVault
```

### 3. Install project dependencies using pnpm:

```sh
pnpm i
```

### 4. Initialize .env files:

```sh
pnpm init:env
```

### 5. Start the development environment:

This command will:

- Start the `supersim` local development environment
- Deploy the smart contracts to the test networks
- Launch the example frontend application

```sh
pnpm dev
```