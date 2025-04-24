# Concurrent Lurk

## Usage

### Setting up

Make sure you have the `linera` binary in your `PATH`. The commit you need is at `https://github.com/lurk-lab/linera-protocol/tree/whz/concurrent-lurk`.

For scripting purposes, we also assume that the BASH function `linera_spawn` is defined.
From the root of Linera repository, this can be achieved as follows:

```bash
export PATH="$PWD/target/debug:$PATH"
source /dev/stdin <<<"$(linera net helper 2>/dev/null)"
```

Start the local Linera network and run a faucet:

```bash
FAUCET_PORT=8079
FAUCET_URL=http://localhost:$FAUCET_PORT
linera --send-timeout-ms 4000 --recv-timeout-ms 4000 net up --with-faucet --faucet-port $FAUCET_PORT &
LINERA_TMP_DIR=$(mktemp -d) && sleep 7
echo "LINERA_TMP_DIR=$LINERA_TMP_DIR"
```

Create the user wallet and add chains to it:

```bash
FAUCET_PORT=8079
FAUCET_URL=http://localhost:$FAUCET_PORT

export LINERA_WALLET_1="$LINERA_TMP_DIR/wallet_1.json"
export LINERA_STORAGE_1="rocksdb:$LINERA_TMP_DIR/client_1.db"

linera --with-wallet 1 wallet init --faucet $FAUCET_URL

INFO=($(linera --with-wallet 1 wallet request-chain --faucet $FAUCET_URL))

export LURKSCRIPT_LINERA_LOG_FILE="./debug/log.txt"
export LURKSCRIPT_LINERA_WALLET=1
export LURKSCRIPT_LINERA_CHAIN_ID=$(echo $INFO | awk '{print $1}')
export LURKSCRIPT_LINERA_CONTRACT_WASM="./assets/concurrent_lurk_contract.wasm"
export LURKSCRIPT_LINERA_SERVICE_WASM="./assets/concurrent_lurk_service.wasm"
export LURKSCRIPT_LINERA_PORT=8082

export LURKSCRIPT_LINERA_OWNER=$(linera -w1 keygen)

# FOR DEBUGGING
# linera -w1 --wait-for-outgoing-messages publish-and-create assets/concurrent_lurk_contract.wasm assets/concurrent_lurk_service.wasm $LURKSCRIPT_LINERA_CHAIN_ID
```

### Weird mutation Linera bug

Run the following commands:
```bash
npm run start
```
