# varwof-types

> AIC、能力声明、主体标识、委托授权等核心共享类型定义库（含 AIC-JWT 的 DA claim set `da.ver=3`）

[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/varwof/types)](https://pkg.go.dev/github.com/varwof/types)

> ⚠️ **预览版** — 不可用于生产环境。API 和功能可能在正式发布前发生变更。

[English](README.md)

## 什么是 varwof-types？

为 varwof PKI 套件提供核心共享类型定义：AIC、Capability、PrincipalUid、DelegationAuthorization、PrincipalAuthorization 等。零外部依赖，被 core、gateway-core、register 等所有模块引用。

## 快速开始

```go
import pki "github.com/varwof/types"

aic, err := pki.ParseAIC(cert)
err = pki.ValidateAIC(aic)
matched := pki.MatchCapability("acme/mysql-v1:query:users", "acme/mysql-v1:query:*")
```

## 安装

```bash
go get github.com/varwof/types@v0.7.0
```

## 核心类型

| 类型 | 说明 |
|------|------|
| `AIC` | Agent Identity Certificate 扩展结构 |
| `Capability` | 能力声明（schemeId + capabilityId） |
| `PrincipalUid` | 主体标识（SPKI 公钥哈希） |
| `DelegationAuthorization` | 委托授权签名；DA 版本 2 在 `DelegationAuthTBS` 中携带由主体签名的 `AgentKeyBinding`（agent SPKI 哈希绑定）——v1 必须缺席、v2 必须携带，新签发一律 v2 |
| `SupervisionEvent` | 统一监督事件（事前/事中/事后：consent/denied/step_up/approval/break_glass/override） |
| `PrincipalAuthorization` | 主体授权策略 |

### 委托授权（DA）版本

两个载体对同一委托授权谱系使用不同的版本号（AIC-JWT -02 §5.4）：

| 载体 | 当前 | 旧版 | agent 密钥绑定 |
|---|---|---|---|
| X.509 AIC（`DelegationAuthTBS.version`） | v2 | v1 | `AgentKeyBinding`：`keyHash` = `hashAlgo(agent SPKI)`，哈希算法默认 SHA-256；v2 必须携带，v1 必须缺席 |
| AIC-JWT（`da.ver`） | 3 | 2 | `agent_key_binding`：`{hash_alg, key_hash}`，`key_hash` = base64url(`hash_alg(SPKI DER)`）；`da.ver=3` 必须携带，`da.ver=2` 必须缺席 |

对应关系：X.509 AIC DA v1 <-> JWT `da.ver=2`；X.509 AIC DA v2 <-> JWT
`da.ver=3`。新签发的委托在两个载体都使用当前版本，其它版本值一律拒绝。

types 是 varwof 生态的**类型基础层**。本项目是 [Open Invention Network](https://openinventionnetwork.com/) 成员。

## 链接

| | |
|---|---|
| 主页 | https://varwof.com |
| 社区 | https://varwof.org |
| IETF 草案 | [draft-wei-aic-identity-cert](https://datatracker.ietf.org/doc/draft-wei-aic-identity-cert/) |
| AIC X.509（文档副本） | [draft-wei-aic-identity-cert-02.md](docs/draft-wei-aic-identity-cert-02.md)（另有 `.xml` / `.txt` / `.html`） |
| AIC-JWT（文档副本） | [draft-wei-aic-jwt-02.md](docs/draft-wei-aic-jwt-02.md)（另有 `.xml` / `.txt` / `.html`） |
| 许可证 | Apache-2.0 |
| 成员 | [Open Invention Network](https://openinventionnetwork.com/) |

## 社区

问题、反馈与移植状态：[AIC Discussions](https://github.com/varwof/aic-jwt/discussions)
