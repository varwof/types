# varwof-types

> AIC、能力声明、主体标识、委托授权等核心共享类型定义库

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
matched := pki.MatchCapability("oracle/mysql:query:users", "oracle/*:query:*")
```

## 安装

```bash
go get github.com/varwof/types@v0.1.0
```

## 核心类型

| 类型 | 说明 |
|------|------|
| `AIC` | Agent Identity Certificate 扩展结构 |
| `Capability` | 能力声明（schemeId + capabilityId） |
| `PrincipalUid` | 主体标识（SPKI 公钥哈希） |
| `DelegationAuthorization` | 委托授权签名 |
| `PrincipalAuthorization` | 主体授权策略 |

types 是 varwof 生态的**类型基础层**。本项目是 [Open Invention Network](https://openinventionnetwork.com/) 成员。

## 链接

| | |
|---|---|
| 主页 | https://varwof.com |
| 社区 | https://varwof.org |
| IETF 草案 | [draft-wei-aic-identity-cert](https://datatracker.ietf.org/doc/draft-wei-aic-identity-cert/) |
| 许可证 | Apache-2.0 |
| 成员 | [Open Invention Network](https://openinventionnetwork.com/) |
