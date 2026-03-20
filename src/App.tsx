import { useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Alert,
  Button,
  Card,
  ConfigProvider,
  Input,
  Layout,
  Select,
  Space,
  Tabs,
  Table,
  Tag,
  Typography,
  message,
  theme,
} from "antd";
import type { ColumnsType } from "antd/es/table";
import {
  CloudSyncOutlined,
  DownloadOutlined,
  PlusOutlined,
  ReloadOutlined,
  SaveOutlined,
  SafetyCertificateOutlined,
  ThunderboltOutlined,
} from "@ant-design/icons";

type Nullable<T> = T | null;

type StatusType = "info" | "success" | "warning" | "error";

interface AccountInput {
  id: string;
  name: string;
  accessKeyId: string;
  accessKeySecret: string;
  securityToken: Nullable<string>;
  defaultRegionId: Nullable<string>;
}

interface TargetInput {
  id: string;
  name: string;
  accountId: string;
  securityGroupId: string;
  regionId: Nullable<string>;
  ruleId: Nullable<string>;
  description: Nullable<string>;
}

interface SyncRequest {
  accounts: AccountInput[];
  targets: TargetInput[];
  ipOverride: Nullable<string>;
}

interface PublicIpResponse {
  ip: string;
  cidr: string;
}

interface AccountIdentityResponse {
  accountId?: string;
  userId?: string;
}

interface TargetSyncResult {
  targetId: string;
  targetName?: string;
  accountId: string;
  accountName?: string;
  securityGroupId: string;
  regionId?: string;
  ruleId?: string;
  action: string;
  success: boolean;
  requestId?: string;
  code?: string;
  message: string;
}

interface SyncResponse {
  publicIp: string;
  cidr: string;
  results: TargetSyncResult[];
}

interface PersistedState {
  accounts: AccountInput[];
  targets: TargetInput[];
}

const STORAGE_KEY = "aliyun-whitelist-config-v2";

function uid(prefix: string): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return `${prefix}-${crypto.randomUUID()}`;
  }
  return `${prefix}-${Date.now()}-${Math.floor(Math.random() * 1e8)}`;
}

function normalizeNullable(value: Nullable<string>): Nullable<string> {
  if (value === null || value === undefined) {
    return null;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function blankAccount(): AccountInput {
  return {
    id: uid("acct"),
    name: "",
    accessKeyId: "",
    accessKeySecret: "",
    securityToken: null,
    defaultRegionId: null,
  };
}

function blankTarget(accountId: string): TargetInput {
  return {
    id: uid("target"),
    name: "",
    accountId,
    securityGroupId: "",
    regionId: null,
    ruleId: null,
    description: null,
  };
}

function ensureBaseRows(
  accountRows: AccountInput[],
  targetRows: TargetInput[]
): { accounts: AccountInput[]; targets: TargetInput[] } {
  const accounts = accountRows.length > 0 ? accountRows : [blankAccount()];
  const fallbackAccountId = accounts[0].id;

  const targetsDraft = targetRows.length > 0 ? targetRows : [blankTarget(fallbackAccountId)];
  const accountSet = new Set(accounts.map((item) => item.id));

  const targets = targetsDraft.map((target) => ({
    ...target,
    accountId: accountSet.has(target.accountId) ? target.accountId : fallbackAccountId,
  }));

  return { accounts, targets };
}

function statusColor(status: StatusType): "success" | "error" | "warning" | "info" {
  if (status === "success") {
    return "success";
  }
  if (status === "error") {
    return "error";
  }
  if (status === "warning") {
    return "warning";
  }
  return "info";
}

export default function App() {
  const [messageApi, messageContext] = message.useMessage();

  const [accounts, setAccounts] = useState<AccountInput[]>([]);
  const [targets, setTargets] = useState<TargetInput[]>([]);
  const [results, setResults] = useState<TargetSyncResult[]>([]);

  const [detectedCidr, setDetectedCidr] = useState("");
  const [ipOverride, setIpOverride] = useState("");

  const [status, setStatus] = useState<{ type: StatusType; text: string }>({
    type: "info",
    text: "等待执行。",
  });

  const [syncing, setSyncing] = useState(false);
  const [detectingIp, setDetectingIp] = useState(false);
  const [verifyingAccountId, setVerifyingAccountId] = useState<string | null>(null);
  const bootstrappedRef = useRef(false);

  const accountOptions = useMemo(
    () =>
      accounts.map((item) => ({
        label: item.name?.trim() || item.id,
        value: item.id,
      })),
    [accounts]
  );

  const persistConfig = (
    nextAccounts: AccountInput[] = accounts,
    nextTargets: TargetInput[] = targets,
    shouldToast = true
  ): void => {
    const payload: PersistedState = {
      accounts: nextAccounts,
      targets: nextTargets,
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
    if (shouldToast) {
      messageApi.success("配置已保存到本地");
      setStatus({ type: "success", text: "配置已保存到本地。" });
    }
  };

  const loadConfig = (shouldToast = true): void => {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      const base = ensureBaseRows([], []);
      setAccounts(base.accounts);
      setTargets(base.targets);
      if (shouldToast) {
        messageApi.info("本地没有找到配置，已创建默认行");
      }
      return;
    }

    try {
      const parsed = JSON.parse(raw) as PersistedState;
      const loadedAccounts = (parsed.accounts ?? []).map((item) => ({
        ...blankAccount(),
        ...item,
        id: item.id || uid("acct"),
        securityToken: normalizeNullable(item.securityToken),
        defaultRegionId: normalizeNullable(item.defaultRegionId),
      }));

      const loadedTargets = (parsed.targets ?? []).map((item) => ({
        ...blankTarget(loadedAccounts[0]?.id ?? ""),
        ...item,
        id: item.id || uid("target"),
        regionId: normalizeNullable(item.regionId),
        ruleId: normalizeNullable(item.ruleId),
        description: normalizeNullable(item.description),
      }));

      const ensured = ensureBaseRows(loadedAccounts, loadedTargets);
      setAccounts(ensured.accounts);
      setTargets(ensured.targets);
      if (shouldToast) {
        messageApi.success("已加载本地配置");
        setStatus({ type: "success", text: "已加载本地配置。" });
      }
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      const base = ensureBaseRows([], []);
      setAccounts(base.accounts);
      setTargets(base.targets);
      messageApi.error(`加载配置失败: ${detail}`);
      setStatus({ type: "error", text: `加载配置失败：${detail}` });
    }
  };

  useEffect(() => {
    if (bootstrappedRef.current) {
      return;
    }
    bootstrappedRef.current = true;

    loadConfig(false);

    void (async () => {
      setDetectingIp(true);
      setStatus({ type: "info", text: "启动时自动检测公网 IPv4..." });
      try {
        const response = await invoke<PublicIpResponse>("detect_public_ip");
        setDetectedCidr(response.cidr);
        setStatus({ type: "success", text: `公网 IP 已自动更新：${response.cidr}` });
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        setStatus({ type: "warning", text: `自动检测失败，可手动重试：${detail}` });
      } finally {
        setDetectingIp(false);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const updateAccount = (id: string, patch: Partial<AccountInput>): void => {
    setAccounts((prev) => prev.map((item) => (item.id === id ? { ...item, ...patch } : item)));
  };

  const updateTarget = (id: string, patch: Partial<TargetInput>): void => {
    setTargets((prev) => prev.map((item) => (item.id === id ? { ...item, ...patch } : item)));
  };

  const handleAddAccount = (): void => {
    setAccounts((prev) => [...prev, blankAccount()]);
  };

  const handleDeleteAccount = (id: string): void => {
    setAccounts((prevAccounts) => {
      const removed = prevAccounts.find((item) => item.id === id);
      const nextAccounts = prevAccounts.filter((item) => item.id !== id);
      const ensuredAccounts = nextAccounts.length > 0 ? nextAccounts : [blankAccount()];
      const fallbackAccountId = ensuredAccounts[0].id;

      setTargets((prevTargets) => {
        const patched = prevTargets.map((item) => {
          if (removed && item.accountId === removed.id) {
            return { ...item, accountId: fallbackAccountId };
          }
          return item;
        });
        return patched.length > 0 ? patched : [blankTarget(fallbackAccountId)];
      });

      return ensuredAccounts;
    });
  };

  const handleAddTarget = (): void => {
    const fallbackAccountId = accounts[0]?.id || uid("acct-fallback");
    setTargets((prev) => [...prev, blankTarget(fallbackAccountId)]);
  };

  const handleDeleteTarget = (id: string): void => {
    setTargets((prev) => {
      const next = prev.filter((item) => item.id !== id);
      return next.length > 0 ? next : [blankTarget(accounts[0]?.id || "")];
    });
  };

  const detectPublicIp = async (): Promise<void> => {
    setDetectingIp(true);
    setStatus({ type: "info", text: "正在检测公网 IPv4..." });
    try {
      const response = await invoke<PublicIpResponse>("detect_public_ip");
      setDetectedCidr(response.cidr);
      setStatus({ type: "success", text: `公网 IP 检测成功：${response.cidr}` });
      messageApi.success(`已检测到公网 IP: ${response.cidr}`);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      setStatus({ type: "error", text: `公网 IP 检测失败：${detail}` });
      messageApi.error(`检测失败: ${detail}`);
    } finally {
      setDetectingIp(false);
    }
  };

  const verifyAccount = async (account: AccountInput): Promise<void> => {
    if (!account.accessKeyId.trim() || !account.accessKeySecret.trim()) {
      messageApi.warning("请先填写 AccessKey ID 和 AccessKey Secret");
      return;
    }

    setVerifyingAccountId(account.id);
    setStatus({ type: "info", text: `正在验证账号 ${account.name || account.id}...` });
    try {
      const response = await invoke<AccountIdentityResponse>("verify_account", {
        account,
      });
      const accountId = response.accountId || "-";
      const userId = response.userId || "-";
      setStatus({
        type: "success",
        text: `账号验证成功：AccountId=${accountId}, UserId=${userId}`,
      });
      messageApi.success(`账号 ${account.name || account.id} 验证通过`);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      setStatus({ type: "error", text: `账号验证失败：${detail}` });
      messageApi.error(`账号验证失败: ${detail}`);
    } finally {
      setVerifyingAccountId(null);
    }
  };

  const validateBeforeSync = (): string | null => {
    if (accounts.length === 0) {
      return "至少需要 1 个账号";
    }
    if (targets.length === 0) {
      return "至少需要 1 个目标";
    }

    for (const account of accounts) {
      if (!account.accessKeyId.trim() || !account.accessKeySecret.trim()) {
        return "每个账号都必须填写 AccessKey ID 和 AccessKey Secret";
      }
    }

    for (const target of targets) {
      if (!target.securityGroupId.trim()) {
        return "每个目标都必须填写 SecurityGroupId";
      }
      if (!target.accountId) {
        return "每个目标都必须绑定账号";
      }
      if (!target.ruleId && !target.description?.trim()) {
        return "未填写 ruleId 的目标必须填写描述（且与云上规则描述完全一致）";
      }
    }

    return null;
  };

  const syncAllTargets = async (): Promise<void> => {
    const validationError = validateBeforeSync();
    if (validationError) {
      messageApi.warning(validationError);
      setStatus({ type: "warning", text: validationError });
      return;
    }

    const request: SyncRequest = {
      accounts,
      targets,
      ipOverride: normalizeNullable(ipOverride),
    };

    setSyncing(true);
    setStatus({ type: "info", text: "正在同步全部目标，请稍候..." });

    try {
      const response = await invoke<SyncResponse>("sync_all", { request });
      setDetectedCidr(response.cidr);
      setResults(response.results);

      const mergedTargets = targets.map((item) => {
        const result = response.results.find((row) => row.targetId === item.id);
        if (!result || !result.success) {
          return item;
        }
        return {
          ...item,
          regionId: result.regionId ?? item.regionId,
          ruleId: result.ruleId ?? item.ruleId,
        };
      });
      setTargets(mergedTargets);
      persistConfig(accounts, mergedTargets, false);

      const skippedCount = response.results.filter((row) => row.action === "skipped").length;
      const successCount = response.results.filter(
        (row) => row.success && row.action !== "skipped"
      ).length;
      const failCount = response.results.filter((row) => !row.success).length;

      const summary = `同步完成：成功 ${successCount} 条，跳过 ${skippedCount} 条，失败 ${failCount} 条，当前 IP ${response.cidr}`;
      setStatus({ type: failCount > 0 ? "warning" : "success", text: summary });
      if (failCount > 0) {
        messageApi.warning(summary);
      } else {
        messageApi.success(summary);
      }
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      setStatus({ type: "error", text: `同步失败：${detail}` });
      messageApi.error(`同步失败: ${detail}`);
    } finally {
      setSyncing(false);
    }
  };

  const accountColumns: ColumnsType<AccountInput> = [
    {
      title: "名称",
      dataIndex: "name",
      render: (_, record) => (
        <Input
          value={record.name}
          placeholder="例如 生产账号"
          onChange={(event) => updateAccount(record.id, { name: event.target.value })}
        />
      ),
    },
    {
      title: "AccessKey ID",
      dataIndex: "accessKeyId",
      render: (_, record) => (
        <Input
          value={record.accessKeyId}
          placeholder="LTAI..."
          onChange={(event) => updateAccount(record.id, { accessKeyId: event.target.value })}
        />
      ),
    },
    {
      title: "AccessKey Secret",
      dataIndex: "accessKeySecret",
      render: (_, record) => (
        <Input
          value={record.accessKeySecret}
          placeholder="Secret"
          onChange={(event) =>
            updateAccount(record.id, { accessKeySecret: event.target.value })
          }
        />
      ),
    },
    {
      title: "操作",
      key: "actions",
      render: (_, record) => (
        <Space>
          <Button
            icon={<SafetyCertificateOutlined />}
            loading={verifyingAccountId === record.id}
            onClick={() => void verifyAccount(record)}
          >
            验证
          </Button>
          <Button danger onClick={() => handleDeleteAccount(record.id)}>
            删除
          </Button>
        </Space>
      ),
    },
  ];

  const targetColumns: ColumnsType<TargetInput> = [
    {
      title: "名称",
      dataIndex: "name",
      render: (_, record) => (
        <Input
          value={record.name}
          placeholder="例如 运维 SSH"
          onChange={(event) => updateTarget(record.id, { name: event.target.value })}
        />
      ),
    },
    {
      title: "账号",
      dataIndex: "accountId",
      render: (_, record) => (
        <Select
          value={record.accountId}
          options={accountOptions}
          onChange={(value) => updateTarget(record.id, { accountId: value })}
        />
      ),
    },
    {
      title: "SecurityGroupId",
      dataIndex: "securityGroupId",
      render: (_, record) => (
        <Input
          value={record.securityGroupId}
          placeholder="sg-xxxx"
          onChange={(event) =>
            updateTarget(record.id, { securityGroupId: event.target.value })
          }
        />
      ),
    },
    {
      title: "描述（需完全一致）",
      dataIndex: "description",
      render: (_, record) => (
        <Input
          value={record.description || ""}
          placeholder="与云上规则描述完全一致"
          onChange={(event) =>
            updateTarget(record.id, {
              description: normalizeNullable(event.target.value),
            })
          }
        />
      ),
    },
    {
      title: "操作",
      key: "actions",
      render: (_, record) => (
        <Button danger onClick={() => handleDeleteTarget(record.id)}>
          删除
        </Button>
      ),
    },
  ];

  const resultColumns: ColumnsType<TargetSyncResult> = [
    {
      title: "目标",
      dataIndex: "targetName",
      render: (_, record) => record.targetName || record.targetId,
    },
    {
      title: "账号",
      dataIndex: "accountName",
      render: (_, record) => record.accountName || record.accountId,
    },
    {
      title: "安全组",
      dataIndex: "securityGroupId",
    },
    {
      title: "结果",
      dataIndex: "success",
      render: (_, record) => {
        if (record.action === "skipped") {
          return <Tag color="default">跳过</Tag>;
        }
        return record.success ? <Tag color="success">成功</Tag> : <Tag color="error">失败</Tag>;
      },
    },
    {
      title: "说明",
      dataIndex: "message",
      render: (_, record) => {
        if (record.code) {
          return `[${record.code}] ${record.message}`;
        }
        return record.message;
      },
    },
  ];

  return (
    <ConfigProvider
      theme={{
        algorithm: theme.defaultAlgorithm,
        token: {
          colorPrimary: "#0f8a8a",
          borderRadius: 12,
          colorBgLayout: "#f3f6fa",
        },
      }}
    >
      {messageContext}
      <Layout className="app-layout">
        <div className="app-bg-glow app-bg-glow-left" />
        <div className="app-bg-glow app-bg-glow-right" />

        <Layout.Content className="app-content">
          <Card className="topbar-card" bordered={false}>
            <div className="topbar-inner">
              <div className="topbar-left">
                <Typography.Text strong className="topbar-title">
                  阿里云安全组白名单助手
                </Typography.Text>
                <Typography.Text className="topbar-desc">
                  按 SecurityGroupId + 描述精确匹配后更新白名单 IP
                </Typography.Text>
              </div>
              <Space wrap>
                <Tag color="blue">{detectedCidr || "IP: 未检测"}</Tag>
                <Button
                  icon={<ReloadOutlined />}
                  loading={detectingIp}
                  onClick={() => void detectPublicIp()}
                >
                  检测公网 IPv4
                </Button>
                <Button
                  type="primary"
                  icon={<CloudSyncOutlined />}
                  loading={syncing}
                  onClick={() => void syncAllTargets()}
                >
                  一键同步
                </Button>
              </Space>
            </div>
          </Card>

          <Tabs
            className="main-tabs"
            items={[
              {
                key: "run",
                label: "运行",
                children: (
                  <div className="panel-stack">
                    <Card className="section-card" title="公网 IP 与执行">
                      <Space direction="vertical" size={10} className="full-width">
                        <Input
                          value={detectedCidr}
                          readOnly
                          placeholder="尚未检测"
                          addonBefore="自动检测结果"
                        />
                        <Input
                          value={ipOverride}
                          onChange={(event) => setIpOverride(event.target.value)}
                          placeholder="例如 1.2.3.4 或 1.2.3.4/32"
                          addonBefore="手动覆盖（可空）"
                        />
                        <Alert
                          type={statusColor(status.type)}
                          showIcon
                          icon={<ThunderboltOutlined />}
                          message={status.text}
                        />
                        <Table<TargetSyncResult>
                          rowKey={(record) =>
                            `${record.targetId}-${record.requestId || record.action}`
                          }
                          columns={resultColumns}
                          dataSource={results}
                          size="small"
                          pagination={{ pageSize: 6, showSizeChanger: false }}
                          locale={{ emptyText: "暂无执行结果" }}
                          tableLayout="fixed"
                          expandable={{
                            expandedRowRender: (record) => (
                              <div className="result-detail-grid">
                                <div className="detail-item">
                                  <span>动作</span>
                                  <b>{record.action}</b>
                                </div>
                                <div className="detail-item">
                                  <span>地域</span>
                                  <b>{record.regionId || "-"}</b>
                                </div>
                                <div className="detail-item">
                                  <span>ruleId</span>
                                  <b>{record.ruleId || "-"}</b>
                                </div>
                                <div className="detail-item">
                                  <span>RequestId</span>
                                  <b>{record.requestId || "-"}</b>
                                </div>
                              </div>
                            ),
                          }}
                        />
                      </Space>
                    </Card>
                  </div>
                ),
              },
              {
                key: "accounts",
                label: "账号配置",
                children: (
                  <div className="panel-stack">
                    <Card
                      className="section-card"
                      title="账号配置"
                      extra={
                        <Space wrap>
                          <Button icon={<PlusOutlined />} onClick={handleAddAccount}>
                            新增账号
                          </Button>
                          <Button icon={<SaveOutlined />} onClick={() => persistConfig()}>
                            保存
                          </Button>
                          <Button icon={<DownloadOutlined />} onClick={() => loadConfig()}>
                            加载
                          </Button>
                        </Space>
                      }
                    >
                      <Typography.Paragraph type="secondary" className="section-help">
                        AccessKey 保存在本机 localStorage，仅建议在你自己的设备使用。
                      </Typography.Paragraph>
                      <Table<AccountInput>
                        rowKey="id"
                        columns={accountColumns}
                        dataSource={accounts}
                        size="small"
                        pagination={{ pageSize: 6, showSizeChanger: false }}
                        tableLayout="fixed"
                        expandable={{
                          expandedRowRender: (record) => (
                            <div className="optional-grid">
                              <Input
                                value={record.securityToken || ""}
                                placeholder="临时凭证可填"
                                addonBefore="STS Token（可选）"
                                onChange={(event) =>
                                  updateAccount(record.id, {
                                    securityToken: normalizeNullable(event.target.value),
                                  })
                                }
                              />
                              <Input
                                value={record.defaultRegionId || ""}
                                placeholder="例如 cn-hangzhou"
                                addonBefore="默认地域（可选）"
                                onChange={(event) =>
                                  updateAccount(record.id, {
                                    defaultRegionId: normalizeNullable(event.target.value),
                                  })
                                }
                              />
                            </div>
                          ),
                        }}
                      />
                    </Card>
                  </div>
                ),
              },
              {
                key: "targets",
                label: "目标规则",
                children: (
                  <div className="panel-stack">
                    <Card
                      className="section-card"
                      title="目标规则"
                      extra={
                        <Button icon={<PlusOutlined />} onClick={handleAddTarget}>
                          新增目标
                        </Button>
                      }
                    >
                      <Typography.Paragraph type="secondary" className="section-help">
                        只填 SecurityGroupId + 描述即可。描述必须与云上规则完全一致。
                      </Typography.Paragraph>
                      <Table<TargetInput>
                        rowKey="id"
                        columns={targetColumns}
                        dataSource={targets}
                        size="small"
                        pagination={{ pageSize: 8, showSizeChanger: false }}
                        tableLayout="fixed"
                        expandable={{
                          expandedRowRender: (record) => (
                            <div className="optional-grid">
                              <Input
                                value={record.regionId || ""}
                                placeholder="可空自动探测"
                                addonBefore="地域（可选）"
                                onChange={(event) =>
                                  updateTarget(record.id, {
                                    regionId: normalizeNullable(event.target.value),
                                  })
                                }
                              />
                              <Input
                                value={record.ruleId || ""}
                                placeholder="sgr-xxxx"
                                addonBefore="ruleId（可选）"
                                onChange={(event) =>
                                  updateTarget(record.id, {
                                    ruleId: normalizeNullable(event.target.value),
                                  })
                                }
                              />
                            </div>
                          ),
                        }}
                      />
                    </Card>
                  </div>
                ),
              },
            ]}
          />
        </Layout.Content>
      </Layout>
    </ConfigProvider>
  );
}
