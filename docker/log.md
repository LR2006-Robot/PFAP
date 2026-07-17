# Docker Deployment Troubleshooting Log

```Shell
cd dockerfile
docker build -t pfap:latest -f dockerfile .
docker run -d --name pfap-node --network host pfap:latest tail -f /dev/null

# Both terminals must be opened using the following command
docker exec -it pfap-node bash
```

## 1. `admin.addPeer` IP Connection Issue

In Docker, if multiple connections are required, you generally need to configure the `network` manually. Since this project only needs two terminals to connect, it can be omitted. If the container was started without `--network host`, you need to manually replace the IP in `"enode://<id>@<ip>:2008"` with `127.0.0.1`.

## 2. `net.peerCount` Returns `0`

First check whether Issue 1 is resolved. If not, run the following command in both terminals and compare the output. If they differ, it means the two terminals are not using the same `pow.json` or `init` was not successful — re-initialize.

```JavaScript
admin.nodeInfo.protocols.eth.genesis
```

If the outputs differ, re-initialize both terminals and restart both `geth console` instances (addresses remain unchanged).

```Shell
exit

# Clear previous chain data (keep keystore accounts)
rm -rf signer1/data/geth signer1/data/geth.ipc
rm -rf signer2/data/geth signer2/data/geth.ipc

# Initialize with the same pow.json
geth --datadir signer1/data init pow.json
geth --datadir signer2/data init pow.json
```

## 3. `authentication needed: password or unlock`

When starting `geth`, the `--unlock` address was missing the `0x` prefix, causing the unlock to fail. Manually unlock permanently instead.

```JavaScript
personal.unlockAccount(eth.accounts[0], "password", 0)
```

## 4. signer2 `not enough balance`

Check whether signer2 has no ETH to pay gas fees. If so, transfer ETH directly.

```JavaScript
// Terminal 2
eth.getBalance(eth.accounts[0])
eth.accounts[0]

// Terminal 1
eth.sendPublicTransaction({from: eth.accounts[0], to: "0x<signer2_address>", value: web3.toWei(100, "ether")})
miner.start()

// Terminal 2 — verify receipt
eth.getBalance(eth.accounts[0])
```
