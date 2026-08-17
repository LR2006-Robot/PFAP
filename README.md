# PFAP 项目文档（Ubuntu 24.04 / Docker 版）

> **PFAP**（基于 [BlockMaze](https://github.com/Agzs/BlockMaze)）是一个构建在以太坊 geth 分叉之上的匿名支付系统，使用 zk-SNARK 零知识证明实现隐私保护交易。
>
> 本文档描述的是 **Ubuntu 24.04 移植版**。相对于原 Ubuntu 18.04 版本，ZK 电路与 geth 集成逻辑**完全未变**，改动仅限于工具链适配，详见 [13. Ubuntu 24.04 移植说明](#13-ubuntu-2404-移植说明)。构建、运行与 RPC 用法见 [`../README.md`](../README.md)。

---

## 目录

- [1. 项目概述](#1-项目概述)
- [2. 目录结构](#2-目录结构)
- [3. ZK 电路详解](#3-zk-电路详解)
  - [3.1 CreateAccount（创建账户）](#31-createaccount创建账户)
  - [3.2 Mint（铸币）](#32-mint铸币)
  - [3.3 Redeem（赎回）](#33-redeem赎回)
  - [3.4 Transfer（转账）](#34-transfer转账)
  - [3.5 承诺结构与序列号链](#35-承诺结构与序列号链)
  - [3.6 双哈希策略](#36-双哈希策略)
- [4. 全局状态 Merkle 树](#4-全局状态-merkle-树)
- [5. Go ↔ C++ CGO 桥接架构](#5-go--c-cgo-桥接架构)
- [6. Go 层：geth 集成](#6-go-层geth-集成)
- [7. 交易流程](#7-交易流程)
  - [7.1 Transfer 两方协作流程](#71-transfer-两方协作流程)
- [8. 构建系统](#8-构建系统)
  - [8.1 构建步骤](#81-构建步骤)
  - [8.2 共享库清单](#82-共享库清单)
  - [8.3 密钥生成](#83-密钥生成)
- [9. Docker 部署](#9-docker-部署)
- [10. 测试环境](#10-测试环境)
- [11. 关键文件索引](#11-关键文件索引)
- [12. 技术栈与依赖](#12-技术栈与依赖)
- [13. Ubuntu 24.04 移植说明](#13-ubuntu-2404-移植说明)

---

## 1. 项目概述

BlockMaze 实现了以下核心隐私特性：

- **余额隐藏**：账户余额通过 SHA-256 密码学承诺隐藏，链上不存储明文余额
- **匿名转账**：消费通过 zk-SNARK 证明授权，不泄露转账金额和参与方身份
- **防双花**：每次消费使用唯一的序列号（sn），通过全局稀疏 Merkle 树标记已使用的承诺
- **确定性序列号链**：`sn_{i+1} = SHA256(sk_A, sn_i)`，使账户状态可顺序验证

系统包含 **4 个 ZK 电路**，通过 **Go ↔ C++ CGO 桥接**集成到 geth 客户端中。

---

## 2. 目录结构

```
PFAP/
├── go-ethereum/                    # geth 客户端分叉（含自定义 ZK 交易类型）
│   ├── cmd/geth/                   # geth 主程序入口
│   ├── zktx/zktx.go                # ZK 交易逻辑：CGO 桥接、序列号状态机
│   ├── internal/ethapi/api.go      # JSON-RPC API 端点
│   ├── core/                       # 核心区块链逻辑
│   ├── crypto/                     # 以太坊原生密码学
│   └── vendor/                     # Go 依赖（vendor 模式）
│
├── libsnark-vnt/                   # C++ ZK 电路库
│   ├── CMakeLists.txt              # 顶层 CMake（曲线=CURVE_ALT_BN128, 标准=C++11）
│   ├── src/
│   │   ├── CMakeLists.txt          # 构建目标定义
│   │   ├── createAccount/          # 电路①：创建 ZK 账户
│   │   │   ├── circuit/            #   电路约束实现
│   │   │   ├── createaccountcgo.cpp #  CGO 桥接（证明生成/验证）
│   │   │   ├── getpvk.cpp          #   密钥生成器
│   │   │   └── main.cpp            #   独立测试入口
│   │   ├── mint/                   # 电路②：普通余额 → ZK 余额
│   │   │   ├── circuit/
│   │   │   │   ├── gadget.tcc      #   电路约束（sn链、余额加法、承诺哈希、Merkle验证）
│   │   │   │   ├── commitment.tcc  #   SHA-256 CMTA 小工具（576位消息→256位摘要）
│   │   │   │   └── merkle.tcc      #   SHA-256 Merkle 树小工具（传统树，已弃用）
│   │   │   ├── mintcgo.cpp         #   CGO 桥接
│   │   │   └── getpvk.cpp          #   密钥生成器
│   │   ├── redeem/                 # 电路③：ZK 余额 → 普通余额
│   │   ├── transfer/               # 电路④：ZK → ZK 转账（最复杂，~42万约束）
│   │   │   └── circuit/
│   │   │       └── gadget.tcc      #   电路约束（cmt_S、类型条件加减、Merkle验证）
│   │   ├── smt/                    # 全局 Poseidon 稀疏 Merkle 树
│   │   │   ├── smtcgo.cpp          #   CGO 桥接（单例、线程安全）
│   │   │   └── smtcgo.hpp          #   C 接口声明
│   │   ├── poseidon/               # Poseidon 哈希原语
│   │   │   ├── poseidon.hpp        #   原生 Poseidon 置换（x⁵ S盒、MDS混合）
│   │   │   ├── poseidon_gadget.tcc #   电路内 Poseidon 小工具
│   │   │   ├── poseidon_smt.hpp    #   原生 SMT 实现（深度256、懒加载哈希）
│   │   │   └── cmt_existence_gadget.tcc # 承诺存在性证明小工具
│   │   ├── crypto/                 # 密码学原语（SHA-256/512、RIPEMD-160、HMAC、Equihash）
│   │   ├── compat/                 # glibc 兼容层
│   │   ├── deposit/                # [遗留] 旧存款电路
│   │   └── send/                   # [遗留] 旧发送电路
│   └── depends/
│       └── libsnark/               # libsnark + libff + libfqfft
│
├── test/pow/                       # PoW 测试网络（5 签名者）
│   ├── pow.json                    # Genesis 配置
│   ├── TRANSFER_TEST.md            # 端到端转账测试指南
│   ├── pubParams.txt               # 公共参数
│   └── signer[1-5]/                # 签名者数据目录
│
├── build.sh                        # 一键构建/安装脚本
├── prfKey/                         # 生成的 proving/verification key（构建后产生）
├── output                          # 一次成功 `./build.sh all` 的完整日志
└── docs/
    ├── PROJECT_DOCUMENTATION.md    # 本文档
    └── images/                     # README 中引用的操作录屏
```

> **注意**：本版本把项目放在 Docker 构建上下文内部，`docker/` 是 `PFAP/` 的**上级**目录而非子目录：
>
> ```
> PFAP-for-Ubuntu24.04-with-docker/
> └── docker/
>     ├── dockerfile          # Ubuntu 24.04 镜像定义（构建上下文 = 该目录）
>     ├── README.md           # 镜像构建/运行说明与 Docker 排障记录
>     ├── new_version.log     # 24.04 宿主机工具链版本
>     ├── old_version.log     # 原 18.04 容器工具链版本
>     └── PFAP/               # ← 项目本体，上面的目录树即从这里开始
> ```
>
> 构建本身不依赖具体路径：`build.sh` 会把 `$GOPATH/src/github.com/ethereum/go-ethereum` 软链到本仓库的 `go-ethereum/`，因此仓库可以放在任意位置（测试文档统一假设为 `~/code/PFAP`）。

---

## 3. ZK 电路详解

### 电路总览

| 电路 | 交易类型 | 公共输入 | 约束数 | 用途 |
|------|----------|----------|--------|------|
| CreateAccount | 创建账户 | `cmt_A` | ~101,027 | 创建初始余额为 0 的 ZK 账户 |
| Mint | 铸币 | `cmt_A_new, value_s, sn_A_old, rt_cmt` | ~265,872 | 普通余额 → ZK 余额 |
| Redeem | 赎回 | `cmt_A_new, value_s, sn_A_old, rt_cmt` | ~265,939 | ZK 余额 → 普通余额 |
| Transfer | 转账 | `cmt_S, cmt_X_new, sn_X_old, rt_cmt, type` | ~291,249 | ZK → ZK 直接转账 |

### 3.1 CreateAccount（创建账户）

最简电路，无 Merkle 证明：

```
sn_A  = SHA256(sk_A, r_A)                  # 初始序列号
cmt_A = SHA256(value=0, sn_A, r_A)         # 零值承诺
```

- **公共输入**：仅 `cmt_A`
- **无 Merkle 证明**：新账户不需要证明其承诺已在树中

### 3.2 Mint（铸币）

普通余额转换为 ZK 余额：

```
sn_A_new  = SHA256(sk_A, sn_A_old)                          # 确定性序列号链
value_new = value_old + value_s                              # 余额累加
cmt_A_old = SHA256(value_old, sn_A_old, r_A_old)             # 旧承诺
cmt_A_new = SHA256(value_new, sn_A_new, r_A_new)             # 新承诺
path      = Merkle证明(cmt_A_old, rt_cmt)                    # 旧承诺在树中的存在性证明
```

- **公共输入**：`sn_A_old`, `rt_cmt`, `cmt_A_new`, `value_s`
- **私有输入**：`sk_A`, `value_old`, `r_A_old`, `r_A_new`, Merkle 路径节点

### 3.3 Redeem（赎回）

ZK 余额转换回普通余额（与 Mint 对称）：

```
sn_A_new  = SHA256(sk_A, sn_A_old)
value_new = value_old - value_s                              # 余额递减
cmt_A_old = SHA256(value_old, sn_A_old, r_A_old)
cmt_A_new = SHA256(value_new, sn_A_new, r_A_new)
path      = Merkle证明(cmt_A_old, rt_cmt)
```

- **公共输入**：`sn_A_old`, `rt_cmt`, `cmt_A_new`, `value_s`

### 3.4 Transfer（转账）

最复杂的电路，支持两方协作的 ZK 转账：

```
cmt_S     = SHA256(value_s, r_s)                              # 转账金额承诺
sn_A_new  = SHA256(sk_A, sn_A_old)                            # 序列号链
value_new = value_old + (2*type - 1) * value_s                # type=0减, type=1加
┃ type=0 时: value_old ≥ value_s                             # 超额消费检查
cmt_A_old = SHA256(value_old, sn_A_old, r_A_old)
cmt_A_new = SHA256(value_new, sn_A_new, r_A_new)
path_A    = Merkle证明(cmt_A_old, rt_cmt)
```

- **`type` 参数**：`0` = 付款方电路（强制 `value_old ≥ value_s`），`1` = 收款方电路
- **公共输入**：`cmt_S`, `sn_A_old`, `cmt_A_new`, `rt_cmt`, `type`
- **约束数**：~291,249 个 R1CS 约束

### 3.5 承诺结构与序列号链

#### 账户承诺

```
cmt_A = SHA256(value || sn || r)    # 576 位消息，跨两个 SHA-256 压缩块
```

- `value`：64 位余额
- `sn`：256 位序列号
- `r`：256 位随机数（致盲因子）

#### 转账金额承诺

```
cmt_S = SHA256(value_s || r_s)      # 320 位消息，单 SHA-256 压缩块
```

- `value_s`：64 位转账金额
- `r_s`：256 位随机数

#### 序列号链

```
sn_0 = SHA256(sk_A, r_0)            # 初始序列号
sn_i = SHA256(sk_A, sn_{i-1})       # 后续序列号
```

序列号链是确定性且可顺序验证的，每次消费后序列号递推至下一个。

### 3.6 双哈希策略

| 用途 | 哈希函数 | 原因 |
|------|----------|------|
| **承诺提交** | SHA-256 | 安全性经过广泛验证，电路内实现为 R1CS 约束 |
| **Merkle 树节点** | Poseidon | SNARK 友好（$t=3, \alpha=5, R_F=8, R_P=57$），大幅减少约束数 |
| **SMT 键计算** | Poseidon | `path = Poseidon(cmt)`，生成 256 位稀疏 Merkle 树键 |

> **注意**：Go 端的 `GenCMT()` 和 `ComputePRF()` 调用 **C++ 的 SHA-256** 而非 Go 的 `crypto/sha256`，以确保电路内外的哈希计算完全一致。

---

## 4. 全局状态 Merkle 树

### 设计规格

| 属性 | 值 |
|------|-----|
| 数据结构 | 稀疏 Merkle 树（SMT） |
| 深度 | 256 |
| 哈希函数 | Poseidon（2→1） |
| 叶子值 | 0（未使用）或 1（已使用） |
| 键 | `Poseidon(cmt)` 的 256 位大端表示 |
| 并发 | 线程安全（`std::mutex`），全局单例 |

### 核心特性

- **稀疏存储**：仅存储已占用的节点，空子树预计算
- **防双花**：每个承诺被使用后，其叶子标记为 1，后续不可再次使用
- **懒加载哈希**：未初始化的子树返回预计算默认值，避免存储 $2^{256}$ 个节点

### C 接口（`smtcgo.hpp`）

| 函数 | 作用 |
|------|------|
| `smtInsertCMT(cmt_hex)` | 在 `path = Poseidon(cmt)` 处标记叶子为 1（幂等） |
| `smtGetRoot()` | 返回当前根节点（64 字符 hex） |
| `smtProve(cmt_hex)` | 生成成员证明：`{found, 256路径位, 256兄弟节点, root}` |
| `smtReset()` | 清空树（测试/新链） |

---

## 5. Go ↔ C++ CGO 桥接架构

### 架构图

```
┌─ Go 层（go-ethereum/zktx/zktx.go）────────────────────┐
│                                                         │
│  ZK 操作接口：                                           │
│  GenMintProof()     → C.genMintproof()                  │
│  VerifyMintProof()  → C.verifyMintproof()               │
│  GenCMT()           → C.genCMT()                        │
│  ComputePRF()       → C.computePRF()                    │
│  InsertCMT()        → C.smtInsertCMT()                  │
│  GetSMTRoot()       → C.smtGetRoot()                    │
│                                                         │
│  CGO 链接：                                              │
│  #cgo LDFLAGS: -L/usr/local/lib                         │
│    -lzk_mint -lzk_redeem -lzk_transfer                  │
│    -lzk_createaccount -lzk_smt -lff -lsnark             │
│    -lstdc++ -lgmp -lgmpxx                               │
├─────────────────────────────────────────────────────────┤
│                     CGO 边界 (extern "C")                 │
│   mintcgo.hpp / transfercgo.hpp / smtcgo.hpp / ...      │
├─────────────────────────────────────────────────────────┤
│ C++ 层（libsnark-vnt/src/）                              │
│                                                         │
│  电路小工具 (gadget.tcc)                                  │
│      ↓                                                  │
│  SHA-256 / Poseidon 原语                                 │
│      ↓                                                  │
│  R1CS 约束系统                                           │
│      ↓                                                  │
│  libsnark Prover / Verifier                              │
│      ↓                                                  │
│  证明序列化 ↔ 文件/字符串                                 │
└─────────────────────────────────────────────────────────┘
```

### 数据流示例（Mint 证明生成）

1. Go 将所有值转换为 hex 字符串
2. 拼接 CMT 数组为单个 hex 字符串
3. 调用 `C.genMintproof(value, value_old, sn_old, r_old, sn, r, cmtA_old, cmtA, value_s, sk, cmtArray, n, RT)`
4. C++ 端：
   - 加载 pk/vk 文件
   - 构建 protoboard 并连接电路小工具
   - 分配见证数据
   - 调用 `r1cs_gg_ppzksnark_prover(pk, primary_input, auxiliary_input)`
   - 序列化证明为 hex 字符串返回
5. Go 接收证明字符串（`[]byte`），用于网络传输或验证

---

## 6. Go 层：geth 集成

### JSON-RPC API

| RPC 方法 | 函数 | 用途 |
|----------|------|------|
| `eth.sendCreateAccountTransaction` | `SendCreateAccountTransaction` | 部署 ZK 账户 |
| `eth.sendMintTransaction` | `SendMintTransaction` | 普通余额 → ZK 余额 |
| `eth.sendRedeemTransaction` | `SendRedeemTransaction` | ZK 余额 → 普通余额 |
| `eth.sendTransferTransaction` | `SendTransferTransaction` | ZK → ZK 转账（由收款方提交） |
| `eth.getPayerNextState` | `GetPayerNextState` | 付款方本地生成证明（不广播） |
| `eth.getAccountState` | 查询账户状态 | 余额/承诺/最后交易区块 |

### 账户状态结构（`zktx/zktx.go`）

```go
type ZKAccountState struct {
    SequenceNumber       ZKSequence  // 当前已确认状态（sn, cmt, random, value, valid）
    SequenceNumberAfter  ZKSequence  // 下一个待处理状态
    SequenceNumberBackup ZKSequence  // getPayerNextState 之前的备份
    AccountSK            []byte      // ZK 密钥 sk_A
}

type ZKSequence struct {
    Sn    []byte  // 序列号
    Cmt   []byte  // 承诺
    R     []byte  // 随机数
    Value uint64  // 余额
    Valid bool    // 是否有效
}
```

---

## 7. 交易流程

### 7.1 Transfer 两方协作流程

```
┌──────────────┐                    ┌──────────────┐
│   付款方 A    │                    │   收款方 B    │
├──────────────┤                    ├──────────────┤
│ 1. 调用       │                    │              │
│ getPayerNext  │                    │              │
│ State(rs,val) │                    │              │
│              │                    │              │
│ 2. 本地生成   │                    │              │
│ proof_A      │                    │              │
│ (type=0)     │                    │              │
│              │                    │              │
│ 3. ──payerData──→               │              │
│ {cmtANew,     │                    │              │
│  snAOld,      │                    │              │
│  proofA}      │                    │              │
│              │                    │ 4. 调用       │
│              │                    │ sendTransfer  │
│              │                    │ Transaction   │
│              │                    │              │
│              │                    │ 5. 网络验证   │
│              │                    │ proof_A +     │
│              │                    │ 生成 proof_B  │
│              │                    │ (type=1)     │
└──────────────┘                    └──────────────┘
```

#### 详细步骤

1. **付款方 A** 调用 `eth.getPayerNextState(rs, valueS)`：
   - 本地生成 `proof_A`（type=0，证明有足够余额）
   - 返回 `{cmtANew, snAOld, proofA}`

2. **付款方 A** 将 `payerData` 通过带外通道发送给收款方 B

3. **收款方 B** 调用 `eth.sendTransferTransaction({from, value, rs, cmtANew, snAOld, proofA})`：
   - 交易提交至网络
   - 链上验证 `proof_A` 并生成 `proof_B`（type=1，收款方余额增加）

4. 双方调用 `eth.getAccountState()` 验证最终状态

---

## 8. 构建系统

### 8.1 构建步骤

`build.sh` 支持以下子命令：

| 命令 | 作用 |
|------|------|
| `./build.sh all` | 完整构建（6 阶段） |
| `./build.sh libsnark` | 仅编译 C++ ZK 电路库 |
| `./build.sh keys` | 仅重新生成 pk/vk |
| `./build.sh geth` | 仅构建 geth 客户端 |
| `./build.sh quick` | 快速构建（仅 geth，Go 代码修改后使用） |
| `./build.sh clean` | 清理构建产物 |

#### 完整构建流程（`all`）

| 阶段 | 脚本函数 | 操作 |
|------|----------|------|
| 1 | `build_libsnark` | `cmake -DCURVE=ALT_BN128 .. && make -j$(nproc)` |
| 2 | `generate_keys` | 运行 4 个密钥生成器，产出 8 个 pk/vk 文件 |
| 3 | `install_libs` | 将 7 个 .so 复制到 `/usr/local/lib/`，`ldconfig` |
| 4 | `install_keys` | 将 prfKey 复制到 `/usr/local/prfKey/` |
| 5 | `build_geth` | `GO111MODULE=off go install -tags generic -v ./cmd/geth` |
| 6 | `install_tests` | `uv sync` 设置 Python 测试环境 |

### 8.2 共享库清单

| 库文件 | 源文件 | 用途 |
|--------|--------|------|
| `libzk_smt.so` | `smt/smtcgo.cpp` | 全局 Poseidon 稀疏 Merkle 树 |
| `libzk_createaccount.so` | `createAccount/createaccountcgo.cpp` | 创建账户证明生成/验证 |
| `libzk_mint.so` | `mint/mintcgo.cpp` | Mint 证明生成/验证 |
| `libzk_redeem.so` | `redeem/redeemcgo.cpp` | Redeem 证明生成/验证 |
| `libzk_transfer.so` | `transfer/transfercgo.cpp` | Transfer 证明生成/验证 |
| `libsnark.so` | `depends/libsnark/` | 核心 libsnark（R1CS、QAP 转换） |
| `libff.so` | `depends/libff/` | 有限域运算、椭圆曲线（ALT_BN128） |

### 8.3 密钥生成

密钥生成器可执行文件：

| 可执行文件 | 输出文件 |
|------------|----------|
| `createaccount_key` | `createaccountpk.txt`, `createaccountvk.txt` |
| `mint_key` | `mintpk.txt`, `mintvk.txt` |
| `redeem_key` | `redeempk.txt`, `redeemvk.txt` |
| `transfer_key` | `transferpk.txt`, `transfervk.txt` |

> **重要**：同一网络上的所有 geth 节点必须使用完全相同的 `prfKey` 文件，否则证明验证失败。任何电路变更都会使 pk/vk 失效。

---

## 9. Docker 部署

镜像在构建阶段就跑完 `./build.sh all`，因此即开即用，包含完整的 geth + ZK 共享库 + pk/vk 密钥。

```dockerfile
FROM ubuntu:24.04

# apt 源改为阿里云镜像 + 安装构建依赖
RUN sed -i 's|http://archive.ubuntu.com/ubuntu/|http://mirrors.aliyun.com/ubuntu/|g' /etc/apt/sources.list && \
	apt-get update && apt-get install -y --no-install-recommends \
	build-essential cmake git wget ca-certificates \
	libgmp3-dev libproc2-dev libboost-all-dev libssl-dev pkg-config \
	sudo golang-go python3 \
	&& rm -rf /var/lib/apt/lists/*

# 复制本地源码树（不是 git clone），因此构建上下文必须是 docker/ 目录
WORKDIR /root/code
COPY ./PFAP /root/code/PFAP

WORKDIR /root/code/PFAP
RUN chmod +x build.sh && ./build.sh all

ENV PATH="/root/go/bin:$PATH"
EXPOSE 2007 2008 8545 30303
CMD ["/bin/bash"]
```

与 18.04 镜像的三处关键差异：

| 项 | 18.04 镜像 | 24.04 镜像 |
|----|-----------|-----------|
| Go 来源 | `wget dl.google.com/go/go1.10.8...tar.gz` 解压到 `/usr/local/go`，手工设置 `GOROOT`/`GOPATH` | apt 的 `golang-go`（1.22.2），沿用 Go 默认的 `GOPATH=/root/go`，只把 `/root/go/bin` 加进 `PATH` |
| 源码获取 | `git clone` 仓库到 `$GOPATH/src/github.com/PFAP` | `COPY ./PFAP /root/code/PFAP`，直接打包本地工作树 |
| `LD_LIBRARY_PATH` | 显式 `ENV LD_LIBRARY_PATH=/usr/local/lib` | 不设置：`build.sh` 装完 `.so` 会执行 `ldconfig`，而 `/usr/local/lib` 在 24.04 的默认加载路径中 |

### 构建与运行

```bash
cd docker
docker build -t pfap:latest -f dockerfile .
docker run -d --name pfap-node --network host pfap:latest tail -f /dev/null

# 每个节点开一个终端，都连到同一个容器
docker exec -it pfap-node bash
```

容器内项目位于 `/root/code/PFAP`，与 `test/pow/TRANSFER_TEST.md` 假设的 `~/code/PFAP` 一致。`--network host` 用于让两个节点通过 `admin.addPeer` 直接互联；若未加该参数，需把 `enode://<id>@<ip>:2008` 中的 IP 换成 `127.0.0.1`。

完整的镜像说明与 Docker 排障记录见 [`../../README.md`](../../README.md)。

---

## 10. 测试环境

**位置**：`test/pow/`

### 配置

| 项目 | 值 |
|------|-----|
| 共识算法 | PoW（工作量证明） |
| Chain ID | 4 |
| 签名者数量 | 5（signer1 ~ signer5） |
| Genesis 文件 | `pow.json` |

### 文件结构

```
test/pow/
├── pow.json                 # Genesis 配置
├── pubParams.txt            # 公共参数
├── TRANSFER_TEST.md         # 端到端转账测试指南
├── instructions.txt         # 测试说明
├── signer1/
│   ├── passwd.txt           # 账户密码
│   └── data/keystore/       # 密钥文件
├── signer2/
├── signer3/
├── signer4/
└── signer5/
```

### 启动示例

```bash
geth --datadir signer2/data \
     --networkid 55661 \
     --port 2008 \
     --unlock 0x53d52ca38aaa1b11bc266bd33a7bddc58b82353e \
     --password signer2/passwd.txt \
     console 2>> signer2.log
```

---

## 11. 关键文件索引

| 文件 | 作用 |
|------|------|
| `build.sh` | 一键构建/安装脚本（6 阶段 + 5 子命令） |
| `go-ethereum/zktx/zktx.go` | Go 端 ZK 核心：CGO 桥接、序列号状态机、证明生成/验证 |
| `go-ethereum/internal/ethapi/api.go` | JSON-RPC API 端点定义 |
| `libsnark-vnt/CMakeLists.txt` | 顶层 CMake（ALT_BN128 曲线、C++11 标准） |
| `libsnark-vnt/src/CMakeLists.txt` | 构建目标：5 个共享库 + 4 个密钥生成器 |
| `libsnark-vnt/src/mint/circuit/gadget.tcc` | Mint 电路约束实现 |
| `libsnark-vnt/src/transfer/circuit/gadget.tcc` | Transfer 电路约束实现（最复杂） |
| `libsnark-vnt/src/mint/circuit/commitment.tcc` | SHA-256 CMTA 小工具 |
| `libsnark-vnt/src/poseidon/poseidon.hpp` | 原生 Poseidon 置换 |
| `libsnark-vnt/src/poseidon/poseidon_gadget.tcc` | 电路内 Poseidon 小工具 |
| `libsnark-vnt/src/poseidon/poseidon_smt.hpp` | 稀疏 Merkle 树实现 |
| `libsnark-vnt/src/poseidon/cmt_existence_gadget.tcc` | 承诺存在性证明小工具 |
| `libsnark-vnt/src/smt/smtcgo.cpp` | SMT CGO 桥接 |
| `libsnark-vnt/src/mint/mintcgo.cpp` | Mint CGO 实现 |
| `libsnark-vnt/src/mint/getpvk.cpp` | Mint 密钥生成器 |
| `libsnark-vnt/src/crypto/` | SHA-256/512、RIPEMD-160、HMAC、Equihash |
| `../dockerfile` | Docker 镜像定义（Ubuntu 24.04，位于 `PFAP/` 上级目录） |
| `../README.md` | 镜像构建/运行说明与 Docker 排障记录 |
| `test/pow/pow.json` | 测试网络 Genesis 配置 |
| `test/pow/TRANSFER_TEST.md` | 端到端转账测试指南 |
| `output` | 一次成功 `./build.sh all` 的完整构建日志 |

---

## 12. 技术栈与依赖

### 编译环境

| 组件 | 版本/要求 |
|------|-----------|
| OS | Ubuntu 24.04 |
| C++ 编译器 | GCC 13.3.0 |
| C++ 标准 | C++11 |
| Go | 1.22.2 |
| CMake | ≥3.10 |
| 椭圆曲线 | ALT_BN128 |

### 系统依赖（apt 安装）

```
build-essential cmake git
libgmp3-dev libproc2-dev
libboost-all-dev (≥1.40)
libssl-dev (OpenSSL 3.0.13)
pkg-config
```

### C++ 库

| 库 | 用途 |
|----|------|
| libsnark | zk-SNARK 框架（R1CS、QAP、GG-PPR） |
| libff | 有限域运算、ALT_BN128 曲线 |
| libfqfft | 快速傅里叶变换（QAP 多项式计算） |
| GMP | 大整数运算 |
| Boost | program_options |
| OpenSSL | SHA-256 等密码学原语 |

### Go 依赖

- geth v1.8.x 分叉（基于 commit `040dd5bd`）
- Vendor 模式（`GO111MODULE=off`，Go 1.22 默认开启 module 模式，必须显式关闭）
- 构建标签 `generic`（选用纯 Go 的 bn256 实现，见第 13 节）
- `go-bindata`（JS 资源绑定，可选；缺失时跳过 JS 重新绑定）

---

## 13. Ubuntu 24.04 移植说明

### 13.1 结论：核心逻辑未变

相对 Ubuntu 18.04 版本，以下目录**逐字节完全一致**，没有任何逻辑改动：

- `go-ethereum/zktx/`、`go-ethereum/merkle/`、`go-ethereum/core/`、`go-ethereum/miner/`、`go-ethereum/consensus/`、`go-ethereum/internal/`
- `libsnark-vnt/src/` 下的全部电路实现：`poseidon/`、`smt/`、各电路的 `circuit/*.tcc`、`Note.h`、`commitment.tcc` 等
- `test/pow/pow.json`（Genesis 配置）

因此**证明系统、承诺结构、序列号链、Merkle 树语义均未改变**，两个版本的 pk/vk 与链数据互相兼容。所有改动都属于工具链适配。

### 13.2 改动清单

| 类别 | 18.04 | 24.04 | 原因 |
|------|-------|-------|------|
| 内存分析依赖 | `libprocps-dev`，`pkg_check_modules(libprocps)` | `libproc2-dev`，`libproc2` | procps-ng 4.x 更名，`<proc/readproc.h>` 已移除；`libff` 的 `print_mem()` 改为直接解析 `/proc/self/status` 的 `VmSize` |
| CMake 最低版本 | 2.8（4 个 `CMakeLists.txt` + gtest 的 2.6.4） | 3.10，并加 `-Wno-deprecated-declarations` | CMake 3.28 已移除对 `< 3.5` 的兼容 |
| gtest 探测 Python | `find_package(PythonInterp)` | `find_package(Python3 COMPONENTS Interpreter)` | `PythonInterp` 模块已删除 |
| C++ 警告即错误 | — | 对仅用于 `assert()` 的变量加 `(void)x;`；hex 字符转换补 `return 0;`；`FConst(const FConst&) = default` | GCC 13 在 `-Wall -Wextra -Wfatal-errors` 下会因 `-Wunused-variable`、`-Wreturn-type`、隐式拷贝构造弃用而中断编译 |
| C++ 语法收紧 | `return{a, b}`、`catch (std::out_of_range)` | `std::make_pair` / `std::make_tuple`、`catch (const std::out_of_range&)` | GCC 13 不再接受 gadgetlib2 的旧写法 |
| Go 版本 | 1.10.8（dl.google.com tarball） | 1.22.2（apt `golang-go`） | 24.04 上无法安装/支持 1.10 |
| geth 构建命令 | `go install ./cmd/geth` | `GO111MODULE=off go install -tags generic ./cmd/geth` | Go 1.22 默认 module 模式；`generic` 标签让 `crypto/bn256` 改用 `bn256_generic.go`（Google 纯 Go 实现），绕开在 Go 1.22 下无法编译的 Cloudflare 汇编实现 |
| `crypto/bn256/bn256_fast.go` | `// +build amd64 arm64` | `// +build amd64,arm64,!generic` | 逗号是「与」，该条件恒不成立，等于彻底停用 Cloudflare 实现；同时新增 `bn256_generic.go` 顶替 |
| `duk_logging.c` | `date_buf[32]` | `date_buf[64]` | GCC 13 的 `-Wformat-truncation` |
| 行尾符 | `build.sh` 为 CRLF | LF | CRLF 会让容器报 ``/usr/bin/env: 'bash\r': No such file or directory`` |
| 依赖安装提示 | 未含 `libproc2-dev` | `check_deps` 的报错信息补上 `libproc2-dev` | 与新依赖保持一致 |

### 13.3 bn256 的性能取舍

`-tags generic` 使 `crypto/bn256` 从 Cloudflare 的汇编实现切换到 Google 的纯 Go 实现。同时 `bn256_fast.go` 的构建标签被改为 `amd64,arm64,!generic`（逗号为「与」），该条件恒不成立，等价于永久停用汇编版本。

- **影响范围**：仅 `bn256Add` / `bn256ScalarMul` / `bn256Pairing` 三个以太坊预编译合约，运行速度下降。
- **不受影响**：ZK 证明的生成与验证走 libsnark/libff（C++，仍以 `-march=native` 编译），性能与 18.04 版本一致。
- 本项目的测试链不使用这三个预编译合约，因此实际无感知。

### 13.4 参考记录

- [`../../old_version.log`](../../old_version.log)：原 18.04 容器的工具链版本
- [`../../new_version.log`](../../new_version.log)：24.04 宿主机的工具链版本
- [`../output`](../output)：一次成功 `./build.sh all` 的完整日志（GCC 13.3.0、CMake 3.28、libproc2 4.0.4、Boost 1.83、OpenSSL 3.0.13）

---

> **文档版本**：v1.1（Ubuntu 24.04 移植版）  
> **最后更新**：2026-08-17  
> **对应目录**：`PFAP-for-Ubuntu24.04-with-docker/docker/PFAP`
