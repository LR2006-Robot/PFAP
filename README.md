# PFAP Docker image (Ubuntu 24.04)

This directory is the Docker **build context** for the Ubuntu 24.04 port of
PFAP. The project source lives in [`PFAP/`](./PFAP/) — start with
[`PFAP/README.md`](./PFAP/README.md) for the build, the RPC API and the porting
notes, and [`PFAP/docs/PROJECT_DOCUMENTATION.md`](./PFAP/docs/PROJECT_DOCUMENTATION.md)
for the architecture reference.

```
docker/
├── dockerfile          Ubuntu 24.04 image definition
├── new_version.log     toolchain versions on the 24.04 host
├── old_version.log     toolchain versions in the original 18.04 container
├── output              full transcript of a successful `./build.sh all`
└── PFAP/               project source (copied into the image at build time)
```

## What the image contains

`FROM ubuntu:24.04`, with the apt sources rewritten to the Aliyun mirror, plus
`build-essential cmake git wget ca-certificates libgmp3-dev libproc2-dev
libboost-all-dev libssl-dev pkg-config sudo golang-go python3`.

The image differs from the 18.04 one in two ways beyond the base:

- **Go comes from apt** (`golang-go`, 1.22.2) instead of a `dl.google.com`
  tarball, so there is no `GOROOT` / `GOPATH` setup — Go's defaults
  (`GOPATH=/root/go`) are used and only `/root/go/bin` is added to `PATH`.
- **The source is `COPY`ed, not cloned.** `COPY ./PFAP /root/code/PFAP` means
  the image is built from your local working tree — local edits are picked up,
  and no network access to the repo is needed. It also means the build context
  must be this directory.

`RUN ./build.sh all` executes the full build (libsnark-vnt → pk/vk → install
`.so` to `/usr/local/lib` → install keys to `/usr/local/prfKey` → geth), so the
resulting image is ready to run nodes with no further setup.

> `LD_LIBRARY_PATH` is deliberately not set: `build.sh` runs `ldconfig` after
> installing the shared libraries, and `/usr/local/lib` is in the default loader
> path on Ubuntu 24.04. Export it manually only if you move the `.so` files.

## Build and run

```bash
cd docker
docker build -t pfap:latest -f dockerfile .
docker run -d --name pfap-node --network host pfap:latest tail -f /dev/null
```

The build takes a while — libsnark plus the trusted-setup key generation for
four circuits dominates. Every terminal you need (one per node) must attach to
the same container:

```bash
docker exec -it pfap-node bash
```

Inside the container the project is at `/root/code/PFAP`, and the two-node
walkthrough is [`test/pow/TRANSFER_TEST.md`](./PFAP/test/pow/TRANSFER_TEST.md).
Note that its paths assume `~/code/PFAP`, which matches the container layout.

Exposed ports: `2007 2008` (the two test nodes), `8545` (HTTP RPC), `30303`
(devp2p).

## Troubleshooting

These are the failure modes actually hit while bringing the two-node test up
inside Docker. They are container/network issues, not port-specific — the 18.04
image behaved the same way.

### 1. `admin.addPeer` never connects

Multi-container setups need explicit network configuration. Since this project
only needs two terminals into one container, starting with `--network host`
avoids the whole problem. If the container was started **without**
`--network host`, replace the IP in `"enode://<id>@<ip>:2008"` with `127.0.0.1`.

### 2. `net.peerCount` returns `0`

First confirm issue 1 is resolved. Then compare the genesis hash in both
terminals:

```javascript
admin.nodeInfo.protocols.eth.genesis
```

If the two differ, the nodes were initialized from different `pow.json` files or
`init` did not succeed. Re-initialize both and restart the consoles — the
accounts in `keystore/` are preserved, so the unlock addresses stay the same:

```bash
exit

# Clear previous chain data (keep keystore accounts)
rm -rf signer1/data/geth signer1/data/geth.ipc
rm -rf signer2/data/geth signer2/data/geth.ipc

# Initialize both from the same genesis
geth --datadir signer1/data init pow.json
geth --datadir signer2/data init pow.json
```

### 3. `authentication needed: password or unlock`

The `--unlock` address was passed without the `0x` prefix, so the unlock silently
failed. Either fix the flag or unlock permanently from the console:

```javascript
personal.unlockAccount(eth.accounts[0], "password", 0)
```

### 4. signer2: `not enough balance`

signer2 has no ETH for gas. Mine on signer1 and send it some:

```javascript
// Terminal 2
eth.getBalance(eth.accounts[0])
eth.accounts[0]

// Terminal 1
eth.sendPublicTransaction({from: eth.accounts[0], to: "0x<signer2_address>", value: web3.toWei(100, "ether")})
miner.start()

// Terminal 2 — verify receipt
eth.getBalance(eth.accounts[0])
```

### 5. `/usr/bin/env: 'bash\r': No such file or directory`

`build.sh` was saved with CRLF line endings — this is what broke the first
24.04 image build. The file in this tree is LF; if you edit it on Windows, make
sure your editor does not convert it back.
