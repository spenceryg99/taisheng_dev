import { useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Button,
  Card,
  ConfigProvider,
  Input,
  Layout,
  Segmented,
  Select,
  Space,
  Table,
  Tag,
  Tooltip,
  Typography,
  message,
  theme,
} from "antd";
import { Theme } from "@radix-ui/themes";
import type { ColumnsType } from "antd/es/table";
import {
  CloudSyncOutlined,
  DeleteOutlined,
  DownloadOutlined,
  EyeInvisibleOutlined,
  EyeOutlined,
  LinkOutlined,
  MoonOutlined,
  PlusOutlined,
  ReloadOutlined,
  SaveOutlined,
  SafetyCertificateOutlined,
  SunOutlined,
} from "@ant-design/icons";

type Nullable<T> = T | null;
type StatusType = "info" | "success" | "warning" | "error";
type ModuleKey = "aliyun" | "ssh";
type SshViewMode = "enabled" | "all";
type ThemeMode = "light" | "dark";

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
  carrier?: string | null;
  location?: string | null;
  isp?: string | null;
  org?: string | null;
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

interface SshShortcutRow {
  alias: string;
  hostName?: string | null;
  port?: string | null;
  user?: string | null;
  identityFile?: string | null;
  proxyJump?: string | null;
  sourceFile?: string | null;
  sourceLine?: number | null;
  error?: string | null;
}

const STORAGE_KEY = "aliyun-whitelist-config-v2";
const SSH_HIDDEN_STORAGE_KEY = "ssh-hidden-aliases-v1";
const THEME_MODE_STORAGE_KEY = "desktop-theme-mode-v2";

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

function readHiddenSshAliases(): string[] {
  const raw = localStorage.getItem(SSH_HIDDEN_STORAGE_KEY);
  if (!raw) {
    return [];
  }
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      return [];
    }
    return Array.from(
      new Set(
        parsed.filter(
          (item): item is string => typeof item === "string" && item.trim().length > 0
        )
      )
    );
  } catch {
    return [];
  }
}

function readThemeMode(): ThemeMode {
  try {
    const raw = localStorage.getItem(THEME_MODE_STORAGE_KEY);
    return raw === "light" ? "light" : "dark";
  } catch {
    return "dark";
  }
}

export default function App() {
  const [messageApi, messageContext] = message.useMessage();
  const [moduleKey, setModuleKey] = useState<ModuleKey>("aliyun");

  const [accounts, setAccounts] = useState<AccountInput[]>([]);
  const [targets, setTargets] = useState<TargetInput[]>([]);
  const [results, setResults] = useState<TargetSyncResult[]>([]);

  const [detectedCidr, setDetectedCidr] = useState("");
  const [detectedLocation, setDetectedLocation] = useState("");
  const [detectedCarrier, setDetectedCarrier] = useState("");
  const [ipOverride, setIpOverride] = useState("");

  const [, setStatus] = useState<{ type: StatusType; text: string }>({
    type: "info",
    text: "等待执行。",
  });

  const [syncing, setSyncing] = useState(false);
  const [detectingIp, setDetectingIp] = useState(false);
  const [verifyingAccountId, setVerifyingAccountId] = useState<string | null>(null);

  const [sshLoading, setSshLoading] = useState(false);
  const [openingSshAlias, setOpeningSshAlias] = useState<string | null>(null);
  const [sshKeyword, setSshKeyword] = useState("");
  const [sshShortcuts, setSshShortcuts] = useState<SshShortcutRow[]>([]);
  const [sshViewMode, setSshViewMode] = useState<SshViewMode>("enabled");
  const [hiddenSshAliases, setHiddenSshAliases] = useState<string[]>([]);
  const [aliyunSection, setAliyunSection] = useState<"run" | "accounts" | "targets">("run");
  const [showAccountEditor, setShowAccountEditor] = useState(false);
  const [showTargetEditor, setShowTargetEditor] = useState(false);
  const [themeMode, setThemeMode] = useState<ThemeMode>(() => readThemeMode());

  const bootstrappedRef = useRef(false);
  const sshBootstrappedRef = useRef(false);
  const runSectionRef = useRef<HTMLDivElement | null>(null);
  const accountSectionRef = useRef<HTMLDivElement | null>(null);
  const targetSectionRef = useRef<HTMLDivElement | null>(null);

  const accountOptions = useMemo(
    () =>
      accounts.map((item) => ({
        label: item.name?.trim() || item.id,
        value: item.id,
      })),
    [accounts]
  );

  const hiddenAliasSet = useMemo(() => new Set(hiddenSshAliases), [hiddenSshAliases]);
  const detectedLocationDisplay = useMemo(() => {
    const location = detectedLocation.trim();
    const carrier = detectedCarrier.trim();
    if (!location) {
      return "";
    }
    if (carrier && location.endsWith(carrier)) {
      return location.slice(0, location.length - carrier.length).trim();
    }
    return location;
  }, [detectedCarrier, detectedLocation]);

  const detectedLocationText = useMemo(
    () => detectedLocationDisplay || "位置未检测",
    [detectedLocationDisplay]
  );
  const detectedCarrierText = useMemo(
    () => detectedCarrier.trim() || "运营商未检测",
    [detectedCarrier]
  );
  const enabledSshCount = useMemo(
    () => sshShortcuts.filter((row) => !hiddenAliasSet.has(row.alias)).length,
    [sshShortcuts, hiddenAliasSet]
  );
  const hiddenSshCount = useMemo(
    () => sshShortcuts.filter((row) => hiddenAliasSet.has(row.alias)).length,
    [sshShortcuts, hiddenAliasSet]
  );

  const filteredSshRows = useMemo(() => {
    const baseRows =
      sshViewMode === "enabled"
        ? sshShortcuts.filter((row) => !hiddenAliasSet.has(row.alias))
        : sshShortcuts;
    const keyword = sshKeyword.trim().toLowerCase();
    if (!keyword) {
      return baseRows;
    }
    return baseRows.filter((row) =>
      [row.alias, row.hostName, row.port, row.user, row.sourceFile]
        .map((item) => (item || "").toLowerCase())
        .some((item) => item.includes(keyword))
    );
  }, [hiddenAliasSet, sshKeyword, sshShortcuts, sshViewMode]);

  const firstVisibleAlias = useMemo(
    () => sshShortcuts.find((row) => !hiddenAliasSet.has(row.alias))?.alias ?? null,
    [hiddenAliasSet, sshShortcuts]
  );

  const firstHiddenAlias = useMemo(
    () => sshShortcuts.find((row) => hiddenAliasSet.has(row.alias))?.alias ?? null,
    [hiddenAliasSet, sshShortcuts]
  );

  const isDarkMode = themeMode === "dark";

  const antdThemeConfig = useMemo(
    () => ({
      algorithm: isDarkMode ? theme.darkAlgorithm : theme.defaultAlgorithm,
      token: {
        colorPrimary: isDarkMode ? "#2563EB" : "#2563EB",
        colorInfo: isDarkMode ? "#2563EB" : "#2563EB",
        colorBgLayout: isDarkMode ? "#071629" : "#F3F7FF",
        colorBgContainer: isDarkMode ? "#0F2038" : "#FFFFFF",
        colorText: isDarkMode ? "#E6F0FF" : "#10203B",
        colorTextSecondary: isDarkMode ? "#A8C1E2" : "#5B6B86",
        colorBorder: isDarkMode ? "#2B4D75" : "#D5E3F8",
        borderRadius: 2,
        fontSize: 13,
        controlHeight: 30,
        wireframe: false,
      },
    }),
    [isDarkMode]
  );

  const toggleThemeMode = (): void => {
    setThemeMode((prev) => {
      const next: ThemeMode = prev === "dark" ? "light" : "dark";
      localStorage.setItem(THEME_MODE_STORAGE_KEY, next);
      return next;
    });
  };

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

  const detectPublicIp = async (): Promise<void> => {
    setDetectingIp(true);
    setStatus({ type: "info", text: "正在检测公网 IPv4..." });
    try {
      const response = await invoke<PublicIpResponse>("detect_public_ip");
      setDetectedCidr(response.cidr);
      setDetectedLocation(response.location || "");
      setDetectedCarrier(response.carrier || response.isp || "");
      setIpOverride(response.cidr);
      const detail = [response.cidr, response.location]
        .filter((item) => item && item.trim().length > 0)
        .join(" · ");
      setStatus({ type: "success", text: `公网 IP 检测成功：${detail}` });
      messageApi.success(`已检测到公网 IP: ${detail}`);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      setStatus({ type: "error", text: `公网 IP 检测失败：${detail}` });
      messageApi.error(`检测失败: ${detail}`);
    } finally {
      setDetectingIp(false);
    }
  };

  const loadSshShortcuts = async (showToast = true): Promise<void> => {
    setSshLoading(true);
    try {
      const rows = await invoke<SshShortcutRow[]>("list_ssh_shortcuts");
      setSshShortcuts(rows);
      const aliasSet = new Set(rows.map((item) => item.alias));
      setHiddenSshAliases((prev) => {
        const next = prev.filter((alias) => aliasSet.has(alias));
        if (next.length !== prev.length) {
          localStorage.setItem(SSH_HIDDEN_STORAGE_KEY, JSON.stringify(next));
        }
        return next;
      });
      if (showToast) {
        messageApi.success(`已加载 ${rows.length} 条 SSH 快捷配置`);
      }
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      messageApi.error(`读取 SSH 配置失败: ${detail}`);
    } finally {
      setSshLoading(false);
    }
  };

  const openSshTerminal = async (alias: string): Promise<void> => {
    setOpeningSshAlias(alias);
    try {
      await invoke("open_ssh_terminal", { alias });
      messageApi.success(`已启动终端并执行 ssh ${alias}`);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      messageApi.error(`打开终端失败: ${detail}`);
    } finally {
      setOpeningSshAlias(null);
    }
  };

  const toggleSshAliasVisibility = (alias: string): void => {
    setHiddenSshAliases((prev) => {
      const exists = prev.includes(alias);
      const next = exists ? prev.filter((item) => item !== alias) : [...prev, alias];
      localStorage.setItem(SSH_HIDDEN_STORAGE_KEY, JSON.stringify(next));
      messageApi.success(exists ? `已显示 ${alias}` : `已隐藏 ${alias}`);
      return next;
    });
  };

  const resetSshAliasVisibility = (): void => {
    setHiddenSshAliases([]);
    localStorage.removeItem(SSH_HIDDEN_STORAGE_KEY);
    messageApi.success("已恢复显示全部 SSH 快捷连接");
  };

  useEffect(() => {
    if (bootstrappedRef.current) {
      return;
    }
    bootstrappedRef.current = true;

    loadConfig(false);
    setHiddenSshAliases(readHiddenSshAliases());

    void (async () => {
      setDetectingIp(true);
      setStatus({ type: "info", text: "启动时自动检测公网 IPv4..." });
      try {
        const response = await invoke<PublicIpResponse>("detect_public_ip");
        setDetectedCidr(response.cidr);
        setDetectedLocation(response.location || "");
        setDetectedCarrier(response.carrier || response.isp || "");
        setIpOverride(response.cidr);
        const detail = [response.cidr, response.location]
          .filter((item) => item && item.trim().length > 0)
          .join(" · ");
        setStatus({ type: "success", text: `公网 IP 已自动更新：${detail}` });
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        setStatus({ type: "warning", text: `自动检测失败，可手动重试：${detail}` });
      } finally {
        setDetectingIp(false);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (moduleKey !== "ssh" || sshBootstrappedRef.current) {
      return;
    }
    sshBootstrappedRef.current = true;
    void loadSshShortcuts(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [moduleKey]);

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

  const verifyAccount = async (account: AccountInput): Promise<void> => {
    if (!account.accessKeyId.trim() || !account.accessKeySecret.trim()) {
      messageApi.warning("请先填写 AccessKey ID 和 AccessKey Secret");
      return;
    }

    setVerifyingAccountId(account.id);
    setStatus({ type: "info", text: `正在验证账号 ${account.name || account.id}...` });
    try {
      const response = await invoke<AccountIdentityResponse>("verify_account", { account });
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

  const scrollToAliyunSection = (section: "run" | "accounts" | "targets"): void => {
    setAliyunSection(section);
    if (section === "accounts") {
      setShowAccountEditor(true);
    }
    if (section === "targets") {
      setShowTargetEditor(true);
    }
    const refMap = {
      run: runSectionRef,
      accounts: accountSectionRef,
      targets: targetSectionRef,
    } as const;
    refMap[section].current?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const accountColumns: ColumnsType<AccountInput> = [
    {
      title: "名称",
      dataIndex: "name",
      width: "18%",
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
      width: "30%",
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
      width: "32%",
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
      width: "20%",
      render: (_, record) => (
        <Space size={6} wrap>
          <Tooltip title="验证账号">
            <Button
              size="small"
              shape="circle"
              className="icon-action-btn"
              icon={<SafetyCertificateOutlined />}
              loading={verifyingAccountId === record.id}
              onClick={() => void verifyAccount(record)}
            />
          </Tooltip>
          <Tooltip title="删除账号">
            <Button
              size="small"
              shape="circle"
              danger
              className="icon-action-btn"
              icon={<DeleteOutlined />}
              onClick={() => handleDeleteAccount(record.id)}
            />
          </Tooltip>
        </Space>
      ),
    },
  ];

  const targetColumns: ColumnsType<TargetInput> = [
    {
      title: "名称",
      dataIndex: "name",
      width: "18%",
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
      width: "20%",
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
      width: "26%",
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
      width: "24%",
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
      width: "12%",
      render: (_, record) => (
        <Tooltip title="删除目标">
          <Button
            size="small"
            shape="circle"
            danger
            className="icon-action-btn"
            icon={<DeleteOutlined />}
            onClick={() => handleDeleteTarget(record.id)}
          />
        </Tooltip>
      ),
    },
  ];

  const resultColumns: ColumnsType<TargetSyncResult> = [
    {
      title: "目标",
      dataIndex: "targetName",
      width: "15%",
      render: (_, record) => record.targetName || record.targetId,
    },
    {
      title: "账号",
      dataIndex: "accountName",
      width: "15%",
      render: (_, record) => record.accountName || record.accountId,
    },
    {
      title: "安全组",
      dataIndex: "securityGroupId",
      width: "20%",
    },
    {
      title: "结果",
      dataIndex: "success",
      width: "10%",
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
      width: "40%",
      render: (_, record) => {
        if (record.code) {
          return `[${record.code}] ${record.message}`;
        }
        return record.message;
      },
    },
  ];

  const sshColumns: ColumnsType<SshShortcutRow> = [
    {
      title: "快捷命令",
      dataIndex: "alias",
      width: "20%",
      render: (_, record) => (
        <Space>
          <Typography.Text strong>{record.alias}</Typography.Text>
          {hiddenAliasSet.has(record.alias) ? <Tag>已隐藏</Tag> : null}
          {record.error ? <Tag color="warning">配置异常</Tag> : null}
        </Space>
      ),
    },
    {
      title: "Host/IP",
      dataIndex: "hostName",
      width: "24%",
      render: (_, record) => record.hostName || "-",
    },
    {
      title: "端口",
      dataIndex: "port",
      width: "10%",
      render: (_, record) => record.port || "-",
    },
    {
      title: "用户",
      dataIndex: "user",
      width: "12%",
      render: (_, record) => record.user || "-",
    },
    {
      title: "显示",
      key: "visibility",
      width: "14%",
      render: (_, record) => {
        const isHidden = hiddenAliasSet.has(record.alias);
        return (
          <Tooltip title={isHidden ? "显示该快捷连接" : "隐藏该快捷连接"}>
            <Button
              size="small"
              shape="circle"
              className="icon-action-btn"
              icon={isHidden ? <EyeOutlined /> : <EyeInvisibleOutlined />}
              onClick={() => toggleSshAliasVisibility(record.alias)}
            />
          </Tooltip>
        );
      },
    },
    {
      title: "操作",
      key: "actions",
      width: "20%",
      render: (_, record) => (
        <Tooltip title={`连接 ${record.alias}`}>
          <Button
            size="small"
            icon={<LinkOutlined />}
            loading={openingSshAlias === record.alias}
            onClick={() => void openSshTerminal(record.alias)}
          >
            连接
          </Button>
        </Tooltip>
      ),
    },
  ];

  const aliyunPage = (
    <div className="workspace-stack">
      <Card className="topbar-card" bordered={false}>
        <div className="topbar-inner">
          <div className="topbar-left">
            <div className="topbar-title-col">
              <Typography.Text strong className="topbar-title">
                SP工具箱
              </Typography.Text>
              <Typography.Text className="topbar-desc">白名单同步</Typography.Text>
            </div>
          </div>
          <div className="topbar-right">
            <Space wrap className="topbar-actions">
              <Button
                size="small"
                className="topbar-btn topbar-btn-ip"
                icon={<ReloadOutlined />}
                loading={detectingIp}
                onClick={() => void detectPublicIp()}
              >
                获取本机公网 IP
              </Button>
              <Button
                size="small"
                className="topbar-btn topbar-btn-account"
                icon={<DownloadOutlined />}
                onClick={() => scrollToAliyunSection("accounts")}
              >
                账号配置
              </Button>
              <Button
                size="small"
                className="topbar-btn topbar-btn-sync"
                type="primary"
                icon={<CloudSyncOutlined />}
                loading={syncing}
                onClick={() => void syncAllTargets()}
              >
                一键同步
              </Button>
            </Space>
          </div>
        </div>
      </Card>

      <div className="stat-row">
        <div className="stat-card stat-card-ip">
          <div className="ip-stat-stack">
            <div className="ip-stat-main">IP：{detectedCidr || "未检测"}</div>
            <div className="ip-stat-meta-row">
              <span className="ip-stat-location">{detectedLocationText}</span>
              <span className="ip-stat-sep">•</span>
              <span className="ip-stat-carrier">{detectedCarrierText}</span>
            </div>
          </div>
        </div>
        <div className="stat-card stat-card-account">账号 {accounts.length}</div>
        <div className="stat-card stat-card-rule">规则 {targets.length}</div>
      </div>

      <div className="aliyun-tab-row">
        <button
          type="button"
          className={aliyunSection === "run" ? "active" : ""}
          onClick={() => scrollToAliyunSection("run")}
        >
          运行
        </button>
        <button
          type="button"
          className={aliyunSection === "accounts" ? "active" : ""}
          onClick={() => scrollToAliyunSection("accounts")}
        >
          账号配置
        </button>
        <button
          type="button"
          className={aliyunSection === "targets" ? "active" : ""}
          onClick={() => scrollToAliyunSection("targets")}
        >
          目标规则
        </button>
      </div>

      <div ref={runSectionRef} className="anchor-offset">
        <Card className="section-card" bordered={false}>
          <Typography.Title level={4} className="section-block-title">
            执行结果
          </Typography.Title>
          <Typography.Paragraph type="secondary" className="section-help">
            替换 IP：手动覆盖 IP，可空，例如 1.2.3.4/32
          </Typography.Paragraph>
          <Input
            className="run-inline-input"
            value={ipOverride}
            onChange={(event) => setIpOverride(event.target.value)}
            placeholder="手动覆盖 IP，可空，例如 1.2.3.4/32"
            addonBefore="替换 IP"
          />
          <div className="section-splitter" />
          <Table<TargetSyncResult>
            className="modern-table"
            rowKey={(record) => `${record.targetId}-${record.requestId || record.action}`}
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
        </Card>
      </div>

      <div ref={accountSectionRef} className="anchor-offset">
        <Card className="section-card" bordered={false}>
          <div className="section-title-row">
            <Typography.Title level={4} className="section-block-title">
              账号配置
            </Typography.Title>
            <Button
              size="small"
              type="text"
              className="section-toggle-btn"
              onClick={() => setShowAccountEditor((prev) => !prev)}
            >
              {showAccountEditor ? "收起编辑" : "展开编辑"}
            </Button>
          </div>
          <Typography.Paragraph type="secondary" className="section-help">
            AccessKey 保存在本机 localStorage，仅建议在你自己的设备使用。
          </Typography.Paragraph>
          <Typography.Paragraph type="secondary" className="section-help">
            操作：新增账号 / 保存 / 加载 / 验证账号
          </Typography.Paragraph>
          {showAccountEditor ? (
            <>
              <Space wrap className="section-toolbar">
                <Button size="small" icon={<PlusOutlined />} onClick={handleAddAccount}>
                  新增账号
                </Button>
                <Button size="small" icon={<SaveOutlined />} onClick={() => persistConfig()}>
                  保存
                </Button>
                <Button size="small" icon={<DownloadOutlined />} onClick={() => loadConfig()}>
                  加载
                </Button>
              </Space>
              <div className="section-splitter" />
              <Table<AccountInput>
                className="modern-table"
                rowKey="id"
                columns={accountColumns}
                dataSource={accounts}
                size="small"
                pagination={{ pageSize: 6, showSizeChanger: false }}
                tableLayout="fixed"
                expandable={{
                  expandedRowRender: (record) => (
                    <div className="optional-grid optional-panel">
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
            </>
          ) : null}
        </Card>
      </div>

      <div ref={targetSectionRef} className="anchor-offset">
        <Card className="section-card" bordered={false}>
          <div className="section-title-row">
            <Typography.Title level={4} className="section-block-title">
              目标规则
            </Typography.Title>
            <Button
              size="small"
              type="text"
              className="section-toggle-btn"
              onClick={() => setShowTargetEditor((prev) => !prev)}
            >
              {showTargetEditor ? "收起编辑" : "展开编辑"}
            </Button>
          </div>
          <Typography.Paragraph type="secondary" className="section-help">
            只填 SecurityGroupId + 描述即可。描述必须与云上规则完全一致。
          </Typography.Paragraph>
          <Typography.Paragraph type="secondary" className="section-help">
            操作：新增目标 / 删除目标
          </Typography.Paragraph>
          {showTargetEditor ? (
            <>
              <Space wrap className="section-toolbar">
                <Button size="small" icon={<PlusOutlined />} onClick={handleAddTarget}>
                  新增目标
                </Button>
              </Space>
              <div className="section-splitter" />
              <Table<TargetInput>
                className="modern-table"
                rowKey="id"
                columns={targetColumns}
                dataSource={targets}
                size="small"
                pagination={{ pageSize: 8, showSizeChanger: false }}
                tableLayout="fixed"
                expandable={{
                  expandedRowRender: (record) => (
                    <div className="optional-grid optional-panel">
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
            </>
          ) : null}
        </Card>
      </div>
    </div>
  );

  const sshPage = (
    <div className="workspace-stack">
      <Card className="topbar-card" bordered={false}>
        <div className="topbar-inner">
          <div className="topbar-left">
            <div className="topbar-title-col">
              <Typography.Text strong className="topbar-title">
                SP工具箱
              </Typography.Text>
              <Typography.Text className="topbar-desc">SSH 快捷连接</Typography.Text>
            </div>
          </div>
          <div className="topbar-right topbar-right-ssh">
            <Space wrap className="topbar-actions">
              <Input
                className="ssh-topbar-search"
                value={sshKeyword}
                onChange={(event) => setSshKeyword(event.target.value)}
                placeholder="搜索别名 / Host / 用户 / 端口"
                allowClear
              />
              <Segmented<SshViewMode>
                size="small"
                className="ssh-view-switch"
                value={sshViewMode}
                onChange={(value) => setSshViewMode(value as SshViewMode)}
                options={[
                  { label: "仅显示启用", value: "enabled" },
                  { label: "显示全部", value: "all" },
                ]}
              />
              {hiddenSshCount > 0 ? (
                <Button size="small" className="topbar-btn topbar-btn-ssh-reset" onClick={resetSshAliasVisibility}>
                  全部设为显示
                </Button>
              ) : null}
              <Button
                size="small"
                className="topbar-btn topbar-btn-ssh-refresh"
                icon={<ReloadOutlined />}
                loading={sshLoading}
                onClick={() => void loadSshShortcuts(true)}
              >
                刷新 SSH 列表
              </Button>
            </Space>
          </div>
        </div>
      </Card>

      <div className="ssh-metric-row">
        <div className="ssh-metric-chip ssh-metric-chip-visible">显示 {enabledSshCount} / 全部 {sshShortcuts.length}</div>
        <div className="ssh-metric-chip ssh-metric-chip-hidden">已隐藏 {hiddenSshCount}</div>
      </div>

      <Card className="section-card" title="SSH 快捷连接列表">
        <Table<SshShortcutRow>
          className="modern-table"
          rowKey="alias"
          columns={sshColumns}
          dataSource={filteredSshRows}
          size="small"
          loading={sshLoading}
          pagination={{ pageSize: 10, showSizeChanger: false }}
          tableLayout="fixed"
          locale={{ emptyText: "未读取到 SSH 快捷配置" }}
          expandable={{
            expandedRowRender: (record) => (
              <div className="result-detail-grid">
                <div className="detail-item">
                  <span>IdentityFile</span>
                  <b>{record.identityFile || "-"}</b>
                </div>
                <div className="detail-item">
                  <span>ProxyJump</span>
                  <b>{record.proxyJump || "-"}</b>
                </div>
                <div className="detail-item">
                  <span>来源配置</span>
                  <b>
                    {record.sourceFile
                      ? `${record.sourceFile}${record.sourceLine ? `:${record.sourceLine}` : ""}`
                      : "-"}
                  </b>
                </div>
                <div className="detail-item">
                  <span>解析状态</span>
                  <b>{record.error || "正常"}</b>
                </div>
              </div>
            ),
          }}
        />
      </Card>
      <div className="ssh-toggle-row">
        <Space wrap>
          <Button
            size="small"
            onClick={() => {
              if (firstHiddenAlias) {
                toggleSshAliasVisibility(firstHiddenAlias);
              }
            }}
            disabled={!firstHiddenAlias}
          >
            显示该快捷连接
          </Button>
          <Button
            size="small"
            onClick={() => {
              if (firstVisibleAlias) {
                toggleSshAliasVisibility(firstVisibleAlias);
              }
            }}
            disabled={!firstVisibleAlias}
          >
            隐藏该快捷连接
          </Button>
          <Typography.Text type="secondary">
            当前示例：{firstVisibleAlias || "-"} 显示，{firstHiddenAlias || "-"} 隐藏
          </Typography.Text>
        </Space>
      </div>
    </div>
  );

  return (
    <Theme
      appearance={isDarkMode ? "dark" : "light"}
      accentColor="blue"
      grayColor="slate"
      panelBackground="translucent"
      radius="small"
      scaling="100%"
    >
      <ConfigProvider theme={antdThemeConfig}>
        {messageContext}
        <Layout className={`app-layout ${isDarkMode ? "theme-dark" : "theme-light"}`}>
          <Layout.Content className="app-content">
            <div className="app-shell">
              <aside className="left-rail">
                <div className="left-rail-top">
                  <div className="left-rail-brand">CO</div>
                  <div className="left-rail-menu">
                    <Tooltip title="阿里云白名单">
                      <button
                        type="button"
                        className="left-rail-switch-btn"
                        onClick={() => setModuleKey("aliyun")}
                        aria-label="切换到阿里云白名单"
                      >
                        <SafetyCertificateOutlined
                          className={`left-rail-item ${moduleKey === "aliyun" ? "active" : ""}`}
                        />
                      </button>
                    </Tooltip>
                    <Tooltip title="SSH 快捷连接">
                      <button
                        type="button"
                        className="left-rail-switch-btn"
                        onClick={() => setModuleKey("ssh")}
                        aria-label="切换到 SSH 快捷连接"
                      >
                        <LinkOutlined className={`left-rail-item ${moduleKey === "ssh" ? "active" : ""}`} />
                      </button>
                    </Tooltip>
                  </div>
                </div>
                <div className="left-rail-foot">
                  <Tooltip title={isDarkMode ? "切换为浅色模式" : "切换为深色模式"}>
                    <button
                      type="button"
                      className="left-rail-switch-btn"
                      onClick={toggleThemeMode}
                      aria-label={isDarkMode ? "切换为浅色模式" : "切换为深色模式"}
                    >
                      {isDarkMode ? (
                        <SunOutlined className="left-rail-item active" />
                      ) : (
                        <MoonOutlined className="left-rail-item" />
                      )}
                    </button>
                  </Tooltip>
                </div>
              </aside>
              <div className="app-workspace">{moduleKey === "aliyun" ? aliyunPage : sshPage}</div>
            </div>
          </Layout.Content>
        </Layout>
      </ConfigProvider>
    </Theme>
  );
}
