# 阿里云安全组白名单助手（Tauri + React + Ant Design）

桌面程序目标：
- 支持多组阿里云账号（AccessKey）
- 支持多组安全组目标
- 一键获取当前公网 IPv4，并批量同步到 ECS 安全组入方向规则

## 已实现能力

- 账号管理：`AccessKeyId`、`AccessKeySecret`、可选 `SecurityToken`
- 目标管理：`SecurityGroupId`、可选 `RegionId`、可选 `ruleId`
- 规则更新逻辑：
  - 有 `ruleId`：优先直接修改对应规则 `SourceCidrIp`
  - 无 `ruleId`：仅按“描述完全一致”匹配已有规则
  - 不匹配或匹配多条：跳过，不执行修改
- 多账号多目标批量执行，返回每条结果和 `RequestId`
- 本地配置保存（浏览器 localStorage）

## 使用的真实阿里云 API

- `GetCallerIdentity`（STS）
- `DescribeRegions`
- `DescribeSecurityGroups`
- `DescribeSecurityGroupAttribute`
- `ModifySecurityGroupRule`

> 所有请求通过阿里云 OpenAPI V3 签名（`ACS3-HMAC-SHA256`）调用。

## 本地运行

```bash
npm install
npm run tauri dev
```

## 页面填写建议

1. 先在“账号配置”里填好 AK/SK，点“验证”。
2. 在“目标规则”里填 `SecurityGroupId`，推荐同时填写 `RegionId`（更快更稳）。
3. 如果已知规则 ID，填 `ruleId` 可精准修改。
4. 没有 `ruleId` 时，必须填“描述”，且与云上规则描述完全一致。
5. 点“一键同步全部目标”。

## 注意事项

- `AccessKeySecret` 保存在本机 localStorage，仅建议在你自己的设备上使用。
- 如果描述匹配到 0 条或多条规则，程序会跳过该目标，不会误改。
- 若规则授权对象不是 IPv4 CIDR（例如来源安全组），无法直接改 `SourceCidrIp`。
