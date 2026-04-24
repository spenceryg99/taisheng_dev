# 运维桌面助手（Tauri + React + Ant Design）

桌面程序包含两个独立模块：
- 阿里云安全组白名单批量同步
- SSH 快捷命令查看与一键连接

阿里云模块目标：
- 支持多组阿里云账号（AccessKey）
- 支持多组安全组目标
- 一键获取当前公网 IPv4，并批量同步到 ECS 安全组入方向规则
- 支持按白名单分组名覆盖 PolarDB 集群 IP 白名单

## 已实现能力

- 账号管理：`AccessKeyId`、`AccessKeySecret`、可选 `SecurityToken`
- 目标管理：必填 `SecurityGroupId` + 描述；可选 `RegionId`、`ruleId`
- PolarDB 白名单管理：必填 `DBClusterId` + `DBClusterIPArrayName`（白名单分组名），将分组 IP 覆盖为当前公网 IP
- 规则更新逻辑：
  - 有 `ruleId`：优先直接修改对应规则 `SourceCidrIp`
  - 无 `ruleId`：仅按“描述完全一致”匹配已有规则
  - 不匹配或匹配多条：跳过，不执行修改
- PolarDB 更新逻辑：
  - 按白名单分组名精确匹配已有分组
  - 仅覆盖该分组，不影响其他分组
  - 分组不存在时跳过，不自动新建
- 多账号多目标批量执行，返回每条结果和 `RequestId`
- 本地配置保存（浏览器 localStorage）
- SSH 配置读取：
  - 读取 `~/.ssh/config`，支持 `Include`
  - 列出所有显式 `Host` 别名（跳过通配符）
  - 展示解析后的 `HostName`、`Port`、`User`、`IdentityFile`、`ProxyJump`
  - 可按别名逐条隐藏/显示，默认仅显示已启用项
  - 一键在系统终端执行 `ssh <alias>`

## 使用的真实阿里云 API

- `GetCallerIdentity`（STS）
- `DescribeRegions`
- `DescribeSecurityGroups`
- `DescribeSecurityGroupAttribute`
- `ModifySecurityGroupRule`
- `DescribeDBClusters`
- `DescribeDBClusterAccessWhitelist`
- `ModifyDBClusterAccessWhitelist`

> 所有请求通过阿里云 OpenAPI V3 签名（`ACS3-HMAC-SHA256`）调用。

## 本地运行

```bash
npm install
npm run tauri dev
```

## 页面说明

- 顶部可切换两大页面：`阿里云白名单` / `SSH 快捷连接`
- 应用启动后会自动检测公网 IPv4，也可手动点击“获取本机公网 IP”
- 账号与目标中的可选字段默认折叠在展开行里

## 阿里云模块填写建议

1. 先在“账号配置”里填好 AK/SK，点“验证”。
2. 在“目标规则”里填 `SecurityGroupId`，推荐同时填写 `RegionId`（更快更稳）。
3. 如果已知规则 ID，填 `ruleId` 可精准修改。
4. 没有 `ruleId` 时，必须填“描述”，且与云上规则描述完全一致。
5. 点“一键同步全部目标”。

## 注意事项

- `AccessKeySecret` 保存在本机 localStorage，仅建议在你自己的设备上使用。
- 如果描述匹配到 0 条或多条规则，程序会跳过该目标，不会误改。
- 若规则授权对象不是 IPv4 CIDR（例如来源安全组），无法直接改 `SourceCidrIp`。
- SSH 一键连接依赖系统已安装 `ssh` 命令与终端程序。
