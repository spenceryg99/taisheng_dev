import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import {
  Button,
  Card,
  ConfigProvider,
  Drawer,
  Input,
  Layout,
  Modal,
  Popconfirm,
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
  SettingOutlined,
  SunOutlined,
  UploadOutlined,
} from "@ant-design/icons";

type Nullable<T> = T | null;
type StatusType = "info" | "success" | "warning" | "error";
type ModuleKey = "aliyun" | "ssh";
type SshViewMode = "enabled" | "all";
type ThemeMode = "light" | "dark";
type SshConnectionState = "unknown" | "success" | "failed";
type AliyunTargetType = "ecsSecurityGroup" | "polardbClusterWhitelist";

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
  targetType: AliyunTargetType;
  securityGroupId: string;
  dbClusterId: string;
  dbClusterIpArrayName: Nullable<string>;
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
  targetType: AliyunTargetType;
  resourceId: string;
  whitelistGroupName?: string | null;
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

type AliyunFeature = "whitelist" | "dns" | "domain" | "ssl" | "ecs";

interface DnsDomainInfo {
  domainName: string;
  domainId?: string;
  punyCode?: string;
  recordCount?: number;
  aliDomain?: boolean;
  instanceId?: string;
  versionCode?: string;
}

interface DnsRecord {
  recordId: string;
  domainName: string;
  rr: string;
  recordType: string;
  value: string;
  ttl?: number;
  status?: string;
  locked?: boolean;
  weight?: number;
  line?: string;
  remark?: string;
}

interface DnsRecordInput {
  recordId?: string;
  domainName: string;
  rr: string;
  recordType: string;
  value: string;
  ttl?: number;
  priority?: number;
  line?: string;
}

interface DomainInfo {
  domainName: string;
  instanceId?: string;
  registrationDate?: string;
  expirationDate?: string;
  expirationDateStatus?: string;
  domainStatus?: string;
  premiumDns?: boolean;
  remark?: string;
}

interface CasCertContent {
  orderId: number;
  cert?: string;
  privateKey?: string;
  message?: string;
}

interface EcsInstance {
  instanceId: string;
  instanceName?: string;
  status?: string;
  regionId: string;
  zoneId?: string;
  instanceType?: string;
  creationTime?: string;
  expiredTime?: string;
  privateIpAddress?: string;
  publicIpAddress?: string;
  vpcId?: string;
  tags?: string;
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

interface SshShortcutMeta {
  expireAt: string | null;
  remark: string;
}

interface SshConnectionTestResult {
  alias: string;
  status: SshConnectionState;
  exitCode?: number | null;
  output: string;
  checkedAt: string;
}

interface ConfigBackupPayload {
  aliyun: PersistedState;
  hiddenSshAliases: string[];
  sshShortcutMetaMap: Record<string, SshShortcutMeta>;
  themeMode: ThemeMode;
}

interface ConfigBackupFile {
  schema: "sp-toolbox-config";
  version: number;
  exportedAt: string;
  data: ConfigBackupPayload;
}

const STORAGE_KEY = "aliyun-whitelist-config-v2";
const SSH_HIDDEN_STORAGE_KEY = "ssh-hidden-aliases-v1";
const SSH_META_STORAGE_KEY = "ssh-shortcut-meta-v1";
const THEME_MODE_STORAGE_KEY = "desktop-theme-mode-v2";
const CONFIG_BACKUP_SCHEMA = "sp-toolbox-config";
const ALIYUN_TARGET_TYPE_OPTIONS: { label: string; value: AliyunTargetType }[] = [
  { label: "ECS 安全组", value: "ecsSecurityGroup" },
  { label: "PolarDB 集群白名单", value: "polardbClusterWhitelist" },
];

const DNS_RECORD_TYPE_OPTIONS = [
  "A", "CNAME", "MX", "TXT", "AAAA", "NS", "SRV", "CAA", "PTR", "显性URL", "隐性URL",
];

const ALIYUN_FEATURE_OPTIONS: { label: string; value: AliyunFeature }[] = [
  { label: "白名单同步", value: "whitelist" },
  { label: "域名解析", value: "dns" },
  { label: "域名信息", value: "domain" },
  { label: "SSL证书", value: "ssl" },
  { label: "ECS实例", value: "ecs" },
];

function aliyunTargetTypeLabel(targetType: AliyunTargetType): string {
  return (
    ALIYUN_TARGET_TYPE_OPTIONS.find((item) => item.value === targetType)?.label || "未知类型"
  );
}

function aliyunTargetResourceLabel(targetType: AliyunTargetType): string {
  return targetType === "polardbClusterWhitelist" ? "DBClusterId" : "SecurityGroupId";
}

function aliyunTargetMatchFieldLabel(targetType: AliyunTargetType): string {
  return targetType === "polardbClusterWhitelist" ? "白名单分组名" : "描述（需完全一致）";
}

function aliyunTargetResourceHint(targetType: AliyunTargetType): string {
  return targetType === "polardbClusterWhitelist" ? "PolarDB 集群" : "ECS 入方向规则";
}

function aliyunTargetMatchHint(targetType: AliyunTargetType): string {
  return targetType === "polardbClusterWhitelist" ? "按分组名覆盖" : "按描述精确匹配";
}

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

function pad2(input: number): string {
  return input < 10 ? `0${input}` : String(input);
}

function formatDateStampText(date: Date): string {
  const y = date.getFullYear();
  const m = pad2(date.getMonth() + 1);
  const d = pad2(date.getDate());
  const h = pad2(date.getHours());
  const min = pad2(date.getMinutes());
  const sec = pad2(date.getSeconds());
  return `${y}${m}${d}-${h}${min}${sec}`;
}

function formatDateText(date: Date): string {
  const y = date.getFullYear();
  const m = pad2(date.getMonth() + 1);
  const d = pad2(date.getDate());
  return `${y}-${m}-${d}`;
}

function isRecordObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function extractCasOrders(response: Record<string, unknown>): Record<string, unknown>[] {
  const candidates: unknown[] = [
    response.CertificateOrderIdList,
    response.X509CertificateList,
    response.Data,
    response.List,
    response,
  ];
  for (const candidate of candidates) {
    if (Array.isArray(candidate)) return candidate as Record<string, unknown>[];
    if (isRecordObject(candidate)) {
      for (const key of [
        "X509Certificate",
        "CertificateOrderId",
        "Certificate",
        "orders",
        "list",
      ]) {
        const nested = candidate[key];
        if (Array.isArray(nested)) return nested as Record<string, unknown>[];
      }
    }
  }
  return [];
}

function daysUntil(dateStr: string | undefined): number | null {
  if (!dateStr) return null;
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return null;
  return Math.ceil((d.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
}

function casField(obj: Record<string, unknown>, ...keys: string[]): unknown {
  for (const key of keys) {
    if (key in obj) return obj[key];
  }
  const lowerMap: Record<string, string> = {};
  for (const k of Object.keys(obj)) {
    lowerMap[k.toLowerCase()] = k;
  }
  for (const key of keys) {
    const matched = lowerMap[key.toLowerCase()];
    if (matched) return obj[matched];
  }
  return undefined;
}



function sshStatusText(status: SshConnectionState): string {
  switch (status) {
    case "success":
      return "连接成功";
    case "failed":
      return "连接失败";
    default:
      return "未知";
  }
}

function makeUnknownSshStatus(alias: string): SshConnectionTestResult {
  return {
    alias,
    status: "unknown",
    exitCode: null,
    output: "尚未测试该连接",
    checkedAt: "",
  };
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
    targetType: "ecsSecurityGroup",
    securityGroupId: "",
    dbClusterId: "",
    dbClusterIpArrayName: null,
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

function normalizeSshMetaExpireAt(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }
  return /^\d{4}-\d{2}-\d{2}$/.test(trimmed) ? trimmed : null;
}

function normalizeSshMetaRemark(value: unknown): string {
  if (typeof value !== "string") {
    return "";
  }
  return value.trim();
}

function normalizeSshShortcutMetaMap(input: unknown): Record<string, SshShortcutMeta> {
  if (!isRecordObject(input)) {
    return {};
  }
  const normalized: Record<string, SshShortcutMeta> = {};
  Object.entries(input).forEach(([alias, value]) => {
    const aliasText = alias.trim();
    if (!aliasText || !isRecordObject(value)) {
      return;
    }
    const expireAt = normalizeSshMetaExpireAt(value.expireAt);
    const remark = normalizeSshMetaRemark(value.remark);
    if (!expireAt && !remark) {
      return;
    }
    normalized[aliasText] = { expireAt, remark };
  });
  return normalized;
}

function readSshShortcutMetaMap(): Record<string, SshShortcutMeta> {
  const raw = localStorage.getItem(SSH_META_STORAGE_KEY);
  if (!raw) {
    return {};
  }
  try {
    const parsed = JSON.parse(raw);
    return normalizeSshShortcutMetaMap(parsed);
  } catch {
    return {};
  }
}

function persistSshShortcutMetaMap(metaMap: Record<string, SshShortcutMeta>): void {
  const normalized = normalizeSshShortcutMetaMap(metaMap);
  if (Object.keys(normalized).length === 0) {
    localStorage.removeItem(SSH_META_STORAGE_KEY);
    return;
  }
  localStorage.setItem(SSH_META_STORAGE_KEY, JSON.stringify(normalized));
}

function readThemeMode(): ThemeMode {
  try {
    const raw = localStorage.getItem(THEME_MODE_STORAGE_KEY);
    return raw === "light" ? "light" : "dark";
  } catch {
    return "dark";
  }
}

const _initialTheme = readThemeMode();
document.body.classList.add(`theme-${_initialTheme}`);

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
  const [sshShortcutMetaMap, setSshShortcutMetaMap] = useState<Record<string, SshShortcutMeta>>(
    () => readSshShortcutMetaMap()
  );
  const [sshConnectionStatusMap, setSshConnectionStatusMap] = useState<
    Record<string, SshConnectionTestResult>
  >({});
  const [testingSshAlias, setTestingSshAlias] = useState<string | null>(null);
  const [testingAllSsh, setTestingAllSsh] = useState(false);
  const [deletingSshAlias, setDeletingSshAlias] = useState<string | null>(null);
  const [aliyunSection, setAliyunSection] = useState<"run" | "accounts" | "targets">("run");
  const [showAccountEditor, setShowAccountEditor] = useState(false);
  const [showTargetEditor, setShowTargetEditor] = useState(false);

  const [aliyunFeature, setAliyunFeature] = useState<AliyunFeature>("whitelist");
  const [aliyunActiveAccountId, setAliyunActiveAccountId] = useState("");
  const [dnsDomains, setDnsDomains] = useState<DnsDomainInfo[]>([]);
  const [dnsSelectedDomain, setDnsSelectedDomain] = useState("");
  const [dnsRecords, setDnsRecords] = useState<DnsRecord[]>([]);
  const [dnsLoading, setDnsLoading] = useState(false);
  const [dnsRecordModalOpen, setDnsRecordModalOpen] = useState(false);
  const [dnsEditingRecord, setDnsEditingRecord] = useState<DnsRecordInput | null>(null);
  const [dnsSavingRecord, setDnsSavingRecord] = useState(false);
  const [domainList, setDomainList] = useState<DomainInfo[]>([]);
  const [domainLoading, setDomainLoading] = useState(false);
  const [casOrders, setCasOrders] = useState<Record<string, unknown>[]>([]);
  const [casLoading, setCasLoading] = useState(false);
  const [casCertModalOpen, setCasCertModalOpen] = useState(false);
  const [casViewingOrderId, setCasViewingOrderId] = useState<number | null>(null);
  const [casViewingCert, setCasViewingCert] = useState<CasCertContent | null>(null);
  const [casLoadingCert, setCasLoadingCert] = useState(false);
  const [casFreeCertDomain, setCasFreeCertDomain] = useState("");
  const [ecsInstances, setEcsInstances] = useState<EcsInstance[]>([]);
  const [ecsLoading, setEcsLoading] = useState(false);
  const [themeMode, setThemeMode] = useState<ThemeMode>(() => readThemeMode());
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [configTransferAction, setConfigTransferAction] = useState<"import" | "export" | null>(null);

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
  const currentDateText = formatDateText(new Date());
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
  const testedSshCount = useMemo(
    () =>
      sshShortcuts.filter((row) => {
        const status = sshConnectionStatusMap[row.alias]?.status ?? "unknown";
        return status !== "unknown";
      }).length,
    [sshConnectionStatusMap, sshShortcuts]
  );
  const successSshCount = useMemo(
    () =>
      sshShortcuts.filter((row) => (sshConnectionStatusMap[row.alias]?.status ?? "unknown") === "success")
        .length,
    [sshConnectionStatusMap, sshShortcuts]
  );
  const failedSshCount = useMemo(
    () =>
      sshShortcuts.filter((row) => (sshConnectionStatusMap[row.alias]?.status ?? "unknown") === "failed")
        .length,
    [sshConnectionStatusMap, sshShortcuts]
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
    return baseRows.filter((row) => {
      const meta = sshShortcutMetaMap[row.alias];
      return [row.alias, row.hostName, row.port, row.user, row.sourceFile, meta?.expireAt, meta?.remark]
        .map((item) => (item || "").toLowerCase())
        .some((item) => item.includes(keyword));
    });
  }, [hiddenAliasSet, sshKeyword, sshShortcuts, sshShortcutMetaMap, sshViewMode]);

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

  useLayoutEffect(() => {
    document.body.className = document.body.className
      .replace(/theme-\w+/g, "")
      .replace(/\s+/g, " ")
      .trim();
    document.body.classList.add(`theme-${themeMode}`);
  }, [themeMode]);

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

      const loadedTargets = (parsed.targets ?? []).map((item) => {
        const normalizedTargetType: AliyunTargetType =
          item.targetType === "polardbClusterWhitelist"
            ? "polardbClusterWhitelist"
            : "ecsSecurityGroup";
        return {
          ...blankTarget(loadedAccounts[0]?.id ?? ""),
          ...item,
          id: item.id || uid("target"),
          targetType: normalizedTargetType,
          securityGroupId: String(item.securityGroupId ?? "").trim(),
          dbClusterId: String(item.dbClusterId ?? "").trim(),
          dbClusterIpArrayName: normalizeNullable(item.dbClusterIpArrayName),
          regionId: normalizeNullable(item.regionId),
          ruleId: normalizeNullable(item.ruleId),
          description: normalizeNullable(item.description),
        };
      });

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



  const exportConfigBackup = async (): Promise<void> => {
    try {
      const selected = await open({
        title: "选择导出目录",
        multiple: false,
        directory: true,
      });
      if (!selected || Array.isArray(selected)) {
        return;
      }
      const now = new Date();
      const fileName = `sp-toolbox-config-${formatDateStampText(now)}.json`;
      const filePath = await invoke<string>("join_file_path", {
        directory: selected,
        fileName,
      });

      const payload: ConfigBackupFile = {
        schema: CONFIG_BACKUP_SCHEMA,
        version: 1,
        exportedAt: now.toISOString(),
        data: {
          aliyun: {
            accounts,
            targets,
          },
          hiddenSshAliases,
          sshShortcutMetaMap,
          themeMode,
        },
      };

      setConfigTransferAction("export");
      const content = JSON.stringify(payload, null, 2);
      await invoke<string>("write_text_file", { path: filePath, content });
      messageApi.success(`配置已导出：${filePath}`);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      messageApi.error(`导出配置失败: ${detail}`);
    } finally {
      setConfigTransferAction(null);
    }
  };

  const importConfigBackup = async (): Promise<void> => {
    const confirmText = "导入会覆盖当前本地配置，是否继续？";
    const shouldContinue =
      typeof window === "undefined" ? true : window.confirm(confirmText);
    if (!shouldContinue) {
      return;
    }

    try {
      const selected = await open({
        title: "选择导入目录",
        multiple: false,
        directory: true,
      });
      if (!selected || Array.isArray(selected)) {
        return;
      }

      setConfigTransferAction("import");
      const backupFilePath = await invoke<string>("find_latest_config_backup_file", {
        directory: selected,
      });
      const content = await invoke<string>("read_text_file", { path: backupFilePath });
      const parsed: unknown = JSON.parse(content);
      if (!isRecordObject(parsed)) {
        throw new Error("文件内容不是有效对象");
      }

      const sourceRoot = isRecordObject(parsed.data) ? parsed.data : parsed;
      const importedLabels: string[] = [];

      const aliyunValue = sourceRoot.aliyun;
      if (
        isRecordObject(aliyunValue) &&
        Array.isArray(aliyunValue.accounts) &&
        Array.isArray(aliyunValue.targets)
      ) {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(aliyunValue));
        importedLabels.push("阿里云");
      }

      const hiddenSshAliasesValue = sourceRoot.hiddenSshAliases;
      if (Array.isArray(hiddenSshAliasesValue)) {
        const normalizedHiddenAliases = Array.from(
          new Set(
            hiddenSshAliasesValue
              .map((item) => String(item).trim())
              .filter((item) => item.length > 0)
          )
        );
        localStorage.setItem(SSH_HIDDEN_STORAGE_KEY, JSON.stringify(normalizedHiddenAliases));
        importedLabels.push("SSH 显隐");
      }

      const sshShortcutMetaValue = sourceRoot.sshShortcutMetaMap;
      if (isRecordObject(sshShortcutMetaValue)) {
        const normalizedMetaMap = normalizeSshShortcutMetaMap(sshShortcutMetaValue);
        persistSshShortcutMetaMap(normalizedMetaMap);
        importedLabels.push("SSH 备注");
      }

      const themeModeValue = sourceRoot.themeMode;
      if (themeModeValue === "light" || themeModeValue === "dark") {
        localStorage.setItem(THEME_MODE_STORAGE_KEY, themeModeValue);
        setThemeMode(themeModeValue);
        importedLabels.push("主题");
      }

      if (importedLabels.length === 0) {
        throw new Error("文件中未找到可导入的配置项");
      }

      loadConfig(false);
      setHiddenSshAliases(readHiddenSshAliases());
      setSshShortcutMetaMap(readSshShortcutMetaMap());
      messageApi.success(`配置导入成功：${importedLabels.join("、")}（${backupFilePath}）`);
      setSettingsOpen(false);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      messageApi.error(`导入配置失败: ${detail}`);
    } finally {
      setConfigTransferAction(null);
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

  const updateSshShortcutMeta = (
    alias: string,
    patch: Partial<SshShortcutMeta>
  ): void => {
    setSshShortcutMetaMap((prev) => {
      const current = prev[alias] ?? { expireAt: null, remark: "" };
      const nextExpireAt =
        patch.expireAt === undefined
          ? current.expireAt
          : normalizeSshMetaExpireAt(patch.expireAt);
      const nextRemark =
        patch.remark === undefined ? current.remark : normalizeSshMetaRemark(patch.remark);
      const next = { ...prev };
      if (!nextExpireAt && !nextRemark) {
        delete next[alias];
      } else {
        next[alias] = { expireAt: nextExpireAt, remark: nextRemark };
      }
      persistSshShortcutMetaMap(next);
      return next;
    });
  };

  const loadSshShortcuts = async (showToast = true): Promise<void> => {
    setSshLoading(true);
    try {
      const rows = await invoke<SshShortcutRow[]>("list_ssh_shortcuts");
      setSshShortcuts(rows);
      setSshConnectionStatusMap((prev) => {
        const next: Record<string, SshConnectionTestResult> = {};
        rows.forEach((row) => {
          next[row.alias] = prev[row.alias] ?? makeUnknownSshStatus(row.alias);
        });
        return next;
      });
      const aliasSet = new Set(rows.map((item) => item.alias));
      setHiddenSshAliases((prev) => {
        const next = prev.filter((alias) => aliasSet.has(alias));
        if (next.length !== prev.length) {
          localStorage.setItem(SSH_HIDDEN_STORAGE_KEY, JSON.stringify(next));
        }
        return next;
      });
      setSshShortcutMetaMap((prev) => {
        const next = Object.fromEntries(
          Object.entries(prev).filter(([alias]) => aliasSet.has(alias))
        ) as Record<string, SshShortcutMeta>;
        if (Object.keys(next).length !== Object.keys(prev).length) {
          persistSshShortcutMetaMap(next);
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

  const testSshShortcut = async (alias: string): Promise<void> => {
    setTestingSshAlias(alias);
    try {
      const result = await invoke<SshConnectionTestResult>("test_ssh_shortcut", { alias });
      setSshConnectionStatusMap((prev) => ({ ...prev, [alias]: result }));
      if (result.status === "success") {
        messageApi.success(`${alias} 连接测试成功`);
      } else {
        messageApi.error(`${alias} 连接测试失败`);
      }
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      const failed: SshConnectionTestResult = {
        alias,
        status: "failed",
        exitCode: null,
        output: detail,
        checkedAt: new Date().toISOString(),
      };
      setSshConnectionStatusMap((prev) => ({ ...prev, [alias]: failed }));
      messageApi.error(`测试 ${alias} 失败: ${detail}`);
    } finally {
      setTestingSshAlias(null);
    }
  };

  const testAllSshShortcuts = async (): Promise<void> => {
    if (sshShortcuts.length === 0) {
      messageApi.warning("没有可测试的 SSH 快捷连接");
      return;
    }
    setTestingAllSsh(true);
    try {
      const results = await invoke<SshConnectionTestResult[]>("test_all_ssh_shortcuts");
      setSshConnectionStatusMap((prev) => {
        const next = { ...prev };
        results.forEach((item) => {
          next[item.alias] = item;
        });
        return next;
      });
      const successCount = results.filter((item) => item.status === "success").length;
      const failedCount = results.length - successCount;
      if (failedCount > 0) {
        messageApi.warning(`批量测试完成：成功 ${successCount}，失败 ${failedCount}`);
      } else {
        messageApi.success(`批量测试完成：共 ${successCount} 条，全部成功`);
      }
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      messageApi.error(`批量测试失败: ${detail}`);
    } finally {
      setTestingAllSsh(false);
    }
  };

  const deleteSshShortcut = async (alias: string): Promise<void> => {
    setDeletingSshAlias(alias);
    try {
      const result = await invoke<string>("delete_ssh_shortcut", { alias });
      setHiddenSshAliases((prev) => {
        if (!prev.includes(alias)) {
          return prev;
        }
        const next = prev.filter((item) => item !== alias);
        localStorage.setItem(SSH_HIDDEN_STORAGE_KEY, JSON.stringify(next));
        return next;
      });
      setSshConnectionStatusMap((prev) => {
        const next = { ...prev };
        delete next[alias];
        return next;
      });
      setSshShortcutMetaMap((prev) => {
        if (!(alias in prev)) {
          return prev;
        }
        const next = { ...prev };
        delete next[alias];
        persistSshShortcutMetaMap(next);
        return next;
      });
      await loadSshShortcuts(false);
      messageApi.success(result || `已删除 SSH 快捷连接 ${alias}`);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      messageApi.error(`删除 ${alias} 失败: ${detail}`);
    } finally {
      setDeletingSshAlias(null);
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
    setSshShortcutMetaMap(readSshShortcutMetaMap());

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
      if (!target.accountId) {
        return "每个目标都必须绑定账号";
      }
      if (target.targetType === "polardbClusterWhitelist") {
        if (!target.dbClusterId.trim()) {
          return "PolarDB 目标必须填写 DBClusterId";
        }
        if (!target.dbClusterIpArrayName?.trim()) {
          return "PolarDB 目标必须填写白名单分组名";
        }
        continue;
      }
      if (!target.securityGroupId.trim()) {
        return "ECS 目标必须填写 SecurityGroupId";
      }
      if (!target.ruleId && !target.description?.trim()) {
        return "未填写 ruleId 的 ECS 目标必须填写描述（且与云上规则描述完全一致）";
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

  // ── 域名解析 (DNS) ──

  const aliyunActiveAccount = useMemo(
    () => accounts.find((a) => a.id === aliyunActiveAccountId) || null,
    [accounts, aliyunActiveAccountId],
  );

  const dnsDomainOptions = useMemo(
    () => dnsDomains.map((d) => ({ label: d.domainName, value: d.domainName })),
    [dnsDomains],
  );

  const loadDnsDomains = async () => {
    if (!aliyunActiveAccount) {
      messageApi.warning("请先选择账号");
      return;
    }
    setDnsLoading(true);
    try {
      const domains = await invoke<DnsDomainInfo[]>("dns_list_domains", {
        account: aliyunActiveAccount,
      });
      setDnsDomains(domains);
      if (domains.length > 0 && !dnsSelectedDomain) {
        setDnsSelectedDomain(domains[0].domainName);
      }
    } catch (err) {
      messageApi.error(`加载域名列表失败: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setDnsLoading(false);
    }
  };

  const loadDnsRecords = async (domainName?: string) => {
    const targetDomain = domainName ?? dnsSelectedDomain;
    if (!targetDomain || !aliyunActiveAccount) return;
    setDnsLoading(true);
    try {
      const records = await invoke<DnsRecord[]>("dns_list_records", {
        account: aliyunActiveAccount,
        domainName: targetDomain,
      });
      setDnsRecords(records);
    } catch (err) {
      messageApi.error(`加载解析记录失败: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setDnsLoading(false);
    }
  };

  const openDnsRecordEditor = (record?: DnsRecord) => {
    if (!dnsSelectedDomain) {
      messageApi.warning("请先选择域名");
      return;
    }
    setDnsEditingRecord(
      record
        ? {
            recordId: record.recordId,
            domainName: record.domainName,
            rr: record.rr,
            recordType: record.recordType,
            value: record.value,
            ttl: record.ttl,
            line: record.line,
          }
        : {
            domainName: dnsSelectedDomain,
            rr: "",
            recordType: "A",
            value: "",
            ttl: 600,
          },
    );
    setDnsRecordModalOpen(true);
  };

  const saveDnsRecord = async () => {
    if (!dnsEditingRecord || !aliyunActiveAccount) return;
    if (!dnsEditingRecord.rr.trim() || !dnsEditingRecord.value.trim()) {
      messageApi.warning("主机记录和记录值不能为空");
      return;
    }
    setDnsSavingRecord(true);
    try {
      const result = await invoke<string>("dns_save_record", {
        account: aliyunActiveAccount,
        input: dnsEditingRecord,
      });
      messageApi.success(result);
      setDnsRecordModalOpen(false);
      setDnsEditingRecord(null);
      await loadDnsRecords();
    } catch (err) {
      messageApi.error(`保存失败: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setDnsSavingRecord(false);
    }
  };

  const deleteDnsRecord = async (recordId: string) => {
    if (!aliyunActiveAccount) return;
    try {
      const result = await invoke<string>("dns_delete_record", {
        account: aliyunActiveAccount,
        recordId,
      });
      messageApi.success(result);
      await loadDnsRecords();
    } catch (err) {
      messageApi.error(`删除失败: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const toggleDnsRecordStatus = async (recordId: string, currentStatus: string) => {
    if (!aliyunActiveAccount) return;
    const next = currentStatus === "Enable" ? "Disable" : "Enable";
    try {
      const result = await invoke<string>("dns_set_record_status", {
        account: aliyunActiveAccount,
        recordId,
        status: next,
      });
      messageApi.success(result);
      await loadDnsRecords();
    } catch (err) {
      messageApi.error(`切换状态失败: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  // ── 域名信息 ──

  const loadDomainList = async () => {
    if (!aliyunActiveAccount) {
      messageApi.warning("请先选择账号");
      return;
    }
    setDomainLoading(true);
    try {
      const domains = await invoke<DomainInfo[]>("domain_list", {
        account: aliyunActiveAccount,
      });
      setDomainList(domains);
    } catch (err) {
      messageApi.error(`加载域名信息失败: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setDomainLoading(false);
    }
  };

  // ── SSL 证书 ──

  const loadCasOrders = async () => {
    if (!aliyunActiveAccount) {
      messageApi.warning("请先选择账号");
      return;
    }
    setCasLoading(true);
    try {
      const response = await invoke<Record<string, unknown>>("cas_list_orders", {
        account: aliyunActiveAccount,
      });
      const orders = extractCasOrders(response);
      setCasOrders(orders);
    } catch (err) {
      messageApi.error(`加载证书列表失败: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setCasLoading(false);
    }
  };

  const viewCasCert = async (orderId: number) => {
    if (!aliyunActiveAccount) return;
    setCasLoadingCert(true);
    setCasViewingOrderId(orderId);
    try {
      const cert = await invoke<CasCertContent>("cas_get_cert", {
        account: aliyunActiveAccount,
        orderId,
      });
      setCasViewingCert(cert);
      setCasCertModalOpen(true);
    } catch (err) {
      messageApi.error(`获取证书失败: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setCasLoadingCert(false);
    }
  };

  const createCasFreeCert = async () => {
    if (!aliyunActiveAccount || !casFreeCertDomain.trim()) {
      messageApi.warning("请输入域名");
      return;
    }
    try {
      await invoke("cas_create_free_cert", {
        account: aliyunActiveAccount,
        domainName: casFreeCertDomain.trim(),
      });
      messageApi.success("免费证书申请已提交，请到控制台完成域名验证");
      setCasFreeCertDomain("");
      await loadCasOrders();
    } catch (err) {
      messageApi.error(`申请失败: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  // ── ECS 实例 ──

  const loadEcsInstances = async () => {
    if (!aliyunActiveAccount) {
      messageApi.warning("请先选择账号");
      return;
    }
    setEcsLoading(true);
    try {
      const instances = await invoke<EcsInstance[]>("ecs_list_instances", {
        account: aliyunActiveAccount,
      });
      setEcsInstances(instances);
    } catch (err) {
      messageApi.error(`加载 ECS 实例失败: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setEcsLoading(false);
    }
  };

  // ── 功能区切换时自动加载 ──

  useEffect(() => {
    if (accounts.length > 0 && !aliyunActiveAccountId) {
      setAliyunActiveAccountId(accounts[0].id);
    }
  }, [accounts, aliyunActiveAccountId]);

  useEffect(() => {
    if (aliyunFeature === "dns" && aliyunActiveAccount && dnsDomains.length === 0) {
      void loadDnsDomains();
    }
    if (aliyunFeature === "domain" && aliyunActiveAccount && domainList.length === 0) {
      void loadDomainList();
    }
    if (aliyunFeature === "ssl" && aliyunActiveAccount && casOrders.length === 0) {
      void loadCasOrders();
    }
    if (aliyunFeature === "ecs" && aliyunActiveAccount && ecsInstances.length === 0) {
      void loadEcsInstances();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [aliyunFeature, aliyunActiveAccountId]);

  useEffect(() => {
    if (aliyunFeature === "dns" && dnsSelectedDomain) {
      void loadDnsRecords(dnsSelectedDomain);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dnsSelectedDomain]);

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
      title: "类型",
      dataIndex: "targetType",
      width: "16%",
      render: (_, record) => (
        <Select
          value={record.targetType}
          options={ALIYUN_TARGET_TYPE_OPTIONS}
          onChange={(value) =>
            updateTarget(record.id, {
              targetType: value,
              securityGroupId: value === "ecsSecurityGroup" ? record.securityGroupId : "",
              dbClusterId:
                value === "polardbClusterWhitelist" ? record.dbClusterId : "",
              dbClusterIpArrayName:
                value === "polardbClusterWhitelist" ? record.dbClusterIpArrayName : null,
              ruleId: value === "ecsSecurityGroup" ? record.ruleId : null,
              description: value === "ecsSecurityGroup" ? record.description : null,
            })
          }
        />
      ),
    },
    {
      title: "名称",
      dataIndex: "name",
      width: "14%",
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
      width: "16%",
      render: (_, record) => (
        <Select
          value={record.accountId}
          options={accountOptions}
          onChange={(value) => updateTarget(record.id, { accountId: value })}
        />
      ),
    },
    {
      title: "资源 ID",
      key: "resourceId",
      width: "22%",
      render: (_, record) => (
        <div className="target-field-card">
          <div className="target-field-head">
            <span className="target-field-label">
              {aliyunTargetResourceLabel(record.targetType)}
            </span>
            <span className="target-field-hint">
              {aliyunTargetResourceHint(record.targetType)}
            </span>
          </div>
          <Input
            value={
              record.targetType === "polardbClusterWhitelist"
                ? record.dbClusterId
                : record.securityGroupId
            }
            placeholder={
              record.targetType === "polardbClusterWhitelist" ? "pc-xxxx" : "sg-xxxx"
            }
            onChange={(event) =>
              updateTarget(
                record.id,
                record.targetType === "polardbClusterWhitelist"
                  ? { dbClusterId: event.target.value }
                  : { securityGroupId: event.target.value }
              )
            }
          />
        </div>
      ),
    },
    {
      title: "匹配项",
      key: "matchField",
      width: "20%",
      render: (_, record) => (
        <div className="target-field-card">
          <div className="target-field-head">
            <span className="target-field-label">
              {aliyunTargetMatchFieldLabel(record.targetType)}
            </span>
            <span className="target-field-hint">
              {aliyunTargetMatchHint(record.targetType)}
            </span>
          </div>
          <Input
            value={
              record.targetType === "polardbClusterWhitelist"
                ? record.dbClusterIpArrayName || ""
                : record.description || ""
            }
            placeholder={
              record.targetType === "polardbClusterWhitelist"
                ? "例如 spenceryg"
                : "与云上规则描述完全一致"
            }
            onChange={(event) =>
              updateTarget(
                record.id,
                record.targetType === "polardbClusterWhitelist"
                  ? {
                      dbClusterIpArrayName: normalizeNullable(event.target.value),
                    }
                  : {
                      description: normalizeNullable(event.target.value),
                    }
              )
            }
          />
        </div>
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
      title: "资源",
      key: "resourceId",
      width: "24%",
      render: (_, record) => (
        <Space direction="vertical" size={0}>
          <Typography.Text>{record.resourceId || "-"}</Typography.Text>
          <Typography.Text type="secondary">
            {aliyunTargetTypeLabel(record.targetType)}
          </Typography.Text>
        </Space>
      ),
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
      width: "36%",
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
      width: "14%",
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
      width: "16%",
      render: (_, record) => record.hostName || "-",
    },
    {
      title: "端口",
      dataIndex: "port",
      width: "6%",
      render: (_, record) => record.port || "-",
    },
    {
      title: "用户",
      dataIndex: "user",
      width: "8%",
      render: (_, record) => record.user || "-",
    },
    {
      title: "到期时间",
      key: "expireAt",
      width: "10%",
      render: (_, record) => {
        const expireAt = sshShortcutMetaMap[record.alias]?.expireAt;
        if (!expireAt) {
          return "-";
        }
        return <Tag color={expireAt < currentDateText ? "error" : "success"}>{expireAt}</Tag>;
      },
    },
    {
      title: "备注",
      key: "remark",
      width: "16%",
      render: (_, record) => {
        const remark = sshShortcutMetaMap[record.alias]?.remark;
        if (!remark) {
          return "-";
        }
        return (
          <Tooltip title={remark}>
            <Typography.Text ellipsis style={{ maxWidth: "100%" }}>
              {remark}
            </Typography.Text>
          </Tooltip>
        );
      },
    },
    {
      title: "连接状态",
      key: "connectionStatus",
      width: "10%",
      render: (_, record) => {
        const status = sshConnectionStatusMap[record.alias]?.status ?? "unknown";
        if (status === "success") {
          return <Tag color="success">成功</Tag>;
        }
        if (status === "failed") {
          return <Tag color="error">失败</Tag>;
        }
        return <Tag color="default">未知</Tag>;
      },
    },
    {
      title: "显示",
      key: "visibility",
      width: "6%",
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
      width: "14%",
      render: (_, record) => (
        <Space size={6} wrap>
          <Tooltip title={`测试 ${record.alias}`}>
            <Button
              size="small"
              icon={<ReloadOutlined />}
              loading={testingSshAlias === record.alias}
              onClick={() => void testSshShortcut(record.alias)}
            >
              测试
            </Button>
          </Tooltip>
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
          <Popconfirm
            title={`确认删除 ${record.alias} ?`}
            okText="删除"
            cancelText="取消"
            onConfirm={() => void deleteSshShortcut(record.alias)}
          >
            <Button
              size="small"
              danger
              icon={<DeleteOutlined />}
              loading={deletingSshAlias === record.alias}
            >
              删除
            </Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];



  const dnsRecordColumns: ColumnsType<DnsRecord> = [
    { title: "主机记录", dataIndex: "rr", key: "rr", width: 120,
      render: (rr: string) => <Typography.Text code>{rr}</Typography.Text> },
    { title: "类型", dataIndex: "recordType", key: "recordType", width: 80,
      render: (t: string) => <Tag>{t}</Tag> },
    { title: "记录值", dataIndex: "value", key: "value", ellipsis: true },
    { title: "TTL", dataIndex: "ttl", key: "ttl", width: 60 },
    { title: "状态", dataIndex: "status", key: "status", width: 70,
      render: (s?: string) => s === "Enable" ? <Tag color="green">启用</Tag> : <Tag color="orange">暂停</Tag> },
    { title: "操作", key: "actions", width: 210,
      render: (_: unknown, r: DnsRecord) => (
        <Space size="small">
          <Button size="small" type="link" onClick={() => openDnsRecordEditor(r)}>编辑</Button>
          <Button size="small" type="link" onClick={() => toggleDnsRecordStatus(r.recordId, r.status || "Enable")}>
            {r.status === "Enable" ? "暂停" : "启用"}
          </Button>
          <Popconfirm title="确认删除该解析记录？" onConfirm={() => deleteDnsRecord(r.recordId)}>
            <Button size="small" type="link" danger>删除</Button>
          </Popconfirm>
        </Space>
      )},
  ];

  const dnsPage = (
    <Card className="section-card" bordered={false}>
      <div className="section-title-row">
        <Typography.Title level={4} className="section-block-title">域名解析</Typography.Title>
        <Space>
          <Select size="small" style={{ minWidth: 200 }} placeholder="选择域名"
            value={dnsSelectedDomain || undefined}
            onChange={(val) => { setDnsSelectedDomain(val); void loadDnsRecords(val); }}
            options={dnsDomainOptions}
            notFoundContent="暂无域名"
          />
          <Button size="small" icon={<ReloadOutlined />} loading={dnsLoading} onClick={() => void loadDnsDomains()}>刷新域名</Button>
          <Button size="small" type="primary" icon={<PlusOutlined />} disabled={!dnsSelectedDomain} onClick={() => openDnsRecordEditor()}>添加记录</Button>
        </Space>
      </div>
      <Typography.Paragraph type="secondary">域名 <Typography.Text code>{dnsSelectedDomain || "-"}</Typography.Text> 的 DNS 解析记录，共 {dnsRecords.length} 条</Typography.Paragraph>
      <Table<DnsRecord>
        className="modern-table"
        rowKey="recordId"
        columns={dnsRecordColumns}
        dataSource={dnsRecords}
        size="small"
        loading={dnsLoading}
        pagination={{ pageSize: 15, showSizeChanger: false }}
        locale={{ emptyText: "暂无解析记录" }}
        tableLayout="fixed"
      />
      <Modal
        title={dnsEditingRecord?.recordId ? "编辑解析记录" : "添加解析记录"}
        open={dnsRecordModalOpen}
        onOk={() => void saveDnsRecord()}
        onCancel={() => { setDnsRecordModalOpen(false); setDnsEditingRecord(null); }}
        confirmLoading={dnsSavingRecord}
        okText="保存"
        cancelText="取消"
        destroyOnClose
      >
        {dnsEditingRecord && (
          <div className="dns-editor-stack">
            <div>
              <Typography.Text strong>域名：{dnsEditingRecord.domainName}</Typography.Text>
            </div>
            <Input addonBefore="主机记录" value={dnsEditingRecord.rr}
              onChange={(e) => setDnsEditingRecord({ ...dnsEditingRecord, rr: e.target.value })}
              placeholder="@ 或 www 等" />
            <div className="modal-field-row">
              <Typography.Text strong className="modal-field-label">记录类型</Typography.Text>
              <Select value={dnsEditingRecord.recordType}
                onChange={(val) => setDnsEditingRecord({ ...dnsEditingRecord, recordType: val })}
                options={DNS_RECORD_TYPE_OPTIONS.map((t) => ({ label: t, value: t }))}
                style={{ width: "100%" }} />
            </div>
            <Input addonBefore="记录值" value={dnsEditingRecord.value}
              onChange={(e) => setDnsEditingRecord({ ...dnsEditingRecord, value: e.target.value })}
              placeholder="例如 1.2.3.4 或 target.example.com" />
            <Input addonBefore="TTL（秒）" type="number" value={dnsEditingRecord.ttl ?? 600}
              onChange={(e) => setDnsEditingRecord({ ...dnsEditingRecord, ttl: parseInt(e.target.value) || 600 })}
              placeholder="600" />
          </div>
        )}
      </Modal>
    </Card>
  );

  const domainColumns: ColumnsType<DomainInfo> = [
    { title: "域名", dataIndex: "domainName", key: "domainName", width: 200,
      render: (name: string) => <Typography.Link href={`https://${name}`} target="_blank">{name}</Typography.Link> },
    { title: "注册日期", dataIndex: "registrationDate", key: "registrationDate", width: 140 },
    { title: "到期日期", dataIndex: "expirationDate", key: "expirationDate", width: 140,
      render: (date: string | undefined) => {
        const d = daysUntil(date);
        if (d === null) return date || "-";
        const expired = d < 0;
        const urgent = d >= 0 && d <= 30;
        return (
          <span>
            {date}
            {expired && <Tag color="red" style={{ marginLeft: 8 }}>已过期 {-d} 天</Tag>}
            {urgent && <Tag color="orange" style={{ marginLeft: 8 }}>即将到期 {d} 天</Tag>}
            {!expired && !urgent && <Tag color="green" style={{ marginLeft: 8 }}>正常</Tag>}
          </span>
        );
      }},
    { title: "状态", dataIndex: "domainStatus", key: "domainStatus", width: 100,
      render: (s?: string) => s === "1" ? <Tag color="green">正常</Tag> : <Tag color="default">{s || "-"}</Tag> },
  ];

  const domainPage = (
    <Card className="section-card" bordered={false}>
      <div className="section-title-row">
        <Typography.Title level={4} className="section-block-title">域名信息</Typography.Title>
        <Button size="small" icon={<ReloadOutlined />} loading={domainLoading} onClick={() => void loadDomainList()}>刷新</Button>
      </div>
      <Typography.Paragraph type="secondary">该账号下已注册的域名及到期时间，共 {domainList.length} 个域名</Typography.Paragraph>
      <Table<DomainInfo>
        className="modern-table"
        rowKey="domainName"
        columns={domainColumns}
        dataSource={domainList}
        size="small"
        loading={domainLoading}
        pagination={{ pageSize: 15, showSizeChanger: false }}
        locale={{ emptyText: "暂无域名" }}
        tableLayout="fixed"
      />
    </Card>
  );

  const casStatusInfo = (status: unknown): { label: string; color: string } => {
    const s = String(status ?? "");
    switch (s) {
      case "1": case "issue": return { label: "已签发", color: "green" };
      case "2": case "pending": return { label: "待验证", color: "orange" };
      case "0": case "unissued": return { label: "未签发", color: "default" };
      default: return { label: s, color: "default" };
    }
  };

  const sslPage = (
    <Card className="section-card" bordered={false}>
      <div className="section-title-row">
        <Typography.Title level={4} className="section-block-title">SSL 证书</Typography.Title>
        <Button size="small" icon={<ReloadOutlined />} loading={casLoading} onClick={() => void loadCasOrders()}>刷新</Button>
      </div>
      <Card size="small" className="section-inner-card" bordered={false}>
        <Typography.Title level={5}>申请免费 DV 证书</Typography.Title>
        <Space>
          <Input value={casFreeCertDomain} onChange={(e) => setCasFreeCertDomain(e.target.value)}
            placeholder="请输入域名" style={{ width: 300 }} addonBefore="域名" />
          <Button type="primary" onClick={() => void createCasFreeCert()}>申请</Button>
        </Space>
        <Typography.Paragraph type="secondary" style={{ marginTop: 8 }}>
          申请后需在 DNS 中添加 TXT 验证记录，完成后在 Aliyun 控制台点击验证完成签发
        </Typography.Paragraph>
      </Card>
      <div className="section-splitter" />
      <Table
        className="modern-table"
        rowKey={(r: Record<string, unknown>) => String(casField(r, "certificateOrderId", "CertificateOrderId", "orderId"))}
        columns={[
          { title: "订单 ID", key: "orderId", width: 100,
            render: (_: unknown, r: Record<string, unknown>) => String(casField(r, "certificateOrderId", "CertificateOrderId") ?? "-") },
          { title: "域名", key: "domain", width: 200,
            render: (_: unknown, r: Record<string, unknown>) => String(casField(r, "domain", "Domain", "commonName") ?? "-") },
          { title: "类型", key: "type", width: 80,
            render: (_: unknown, r: Record<string, unknown>) => String(casField(r, "certType", "CertType", "productName", "ProductName") ?? "-") },
          { title: "签发时间", key: "start", width: 150,
            render: (_: unknown, r: Record<string, unknown>) => String(casField(r, "certStartTime", "CertStartTime") ?? "-") },
          { title: "到期时间", key: "end", width: 150,
            render: (_: unknown, r: Record<string, unknown>) => {
              const end = String(casField(r, "certEndTime", "CertEndTime") ?? "-");
              const d = daysUntil(end);
              return (
                <span>
                  {end}
                  {d !== null && d < 0 && <Tag color="red" style={{ marginLeft: 4 }}>已过期</Tag>}
                  {d !== null && d >= 0 && d <= 30 && <Tag color="orange" style={{ marginLeft: 4 }}>{d} 天后到期</Tag>}
                </span>
              );
            }},
          { title: "状态", key: "status", width: 80,
            render: (_: unknown, r: Record<string, unknown>) => {
              const s = casStatusInfo(casField(r, "status", "Status"));
              return <Tag color={s.color}>{s.label}</Tag>;
            }},
          { title: "操作", key: "actions", width: 100,
            render: (_: unknown, r: Record<string, unknown>) => {
              const orderId = casField(r, "certificateOrderId", "CertificateOrderId");
              return (
                <Button size="small" type="link" loading={casLoadingCert && casViewingOrderId === Number(orderId)}
                  onClick={() => orderId && viewCasCert(Number(orderId))}
                  disabled={!orderId}>
                  查看证书
                </Button>
              );
            }},
        ]}
        dataSource={casOrders}
        size="small"
        loading={casLoading}
        pagination={{ pageSize: 10, showSizeChanger: false }}
        locale={{ emptyText: "暂无证书订单" }}
        tableLayout="fixed"
      />
      <Modal
        title="证书内容"
        open={casCertModalOpen}
        onCancel={() => { setCasCertModalOpen(false); setCasViewingCert(null); }}
        footer={null}
        width={700}
        destroyOnClose
      >
        {casViewingCert && (
          <div>
            <Typography.Paragraph><Typography.Text strong>证书内容：</Typography.Text></Typography.Paragraph>
            <Input.TextArea value={casViewingCert.cert || ""} readOnly rows={6} style={{ fontFamily: "monospace", fontSize: 12 }} />
            <div className="section-splitter" />
            <Typography.Paragraph><Typography.Text strong>私钥：</Typography.Text></Typography.Paragraph>
            <Input.TextArea value={casViewingCert.privateKey || ""} readOnly rows={6} style={{ fontFamily: "monospace", fontSize: 12 }} />
            {casViewingCert.message && (
              <Typography.Paragraph type="secondary" style={{ marginTop: 8 }}>
                {casViewingCert.message}
              </Typography.Paragraph>
            )}
          </div>
        )}
      </Modal>
    </Card>
  );

  const ecsStatusColor = (status: string | undefined): string => {
    switch (status) {
      case "Running": return "green";
      case "Stopped": return "error";
      case "Starting": case "Stopping": return "orange";
      default: return "default";
    }
  };

  const ecsStatusLabel = (status: string | undefined): string => {
    switch (status) {
      case "Running": return "运行中";
      case "Stopped": return "已停止";
      case "Starting": return "启动中";
      case "Stopping": return "停止中";
      default: return status || "未知";
    }
  };

  const ecsColumns: ColumnsType<EcsInstance> = [
    { title: "实例 ID", dataIndex: "instanceId", key: "instanceId", width: 150,
      render: (id: string) => <Typography.Text code>{id}</Typography.Text> },
    { title: "名称", dataIndex: "instanceName", key: "instanceName", width: 140,
      render: (name?: string) => name || "-" },
    { title: "状态", dataIndex: "status", key: "status", width: 80,
      render: (s?: string) => <Tag color={ecsStatusColor(s)}>{ecsStatusLabel(s)}</Tag> },
    { title: "地域", dataIndex: "regionId", key: "regionId", width: 120 },
    { title: "可用区", dataIndex: "zoneId", key: "zoneId", width: 100,
      render: (z?: string) => z || "-" },
    { title: "规格", dataIndex: "instanceType", key: "instanceType", width: 120,
      render: (t?: string) => t || "-" },
    { title: "到期时间", dataIndex: "expiredTime", key: "expiredTime", width: 150,
      render: (t?: string) => t || "-" },
    { title: "私网 IP", dataIndex: "privateIpAddress", key: "privateIpAddress", width: 140,
      render: (ip?: string) => ip || "-" },
    { title: "公网 IP", dataIndex: "publicIpAddress", key: "publicIpAddress", width: 140,
      render: (ip?: string) => ip || "-" },
    { title: "VPC", dataIndex: "vpcId", key: "vpcId", width: 140,
      render: (vpc?: string) => vpc ? <Typography.Text code>{vpc.slice(0, 8)}...</Typography.Text> : "-" },
    { title: "创建时间", dataIndex: "creationTime", key: "creationTime", width: 150,
      render: (t?: string) => t || "-" },
  ];

  const ecsPage = (
    <Card className="section-card" bordered={false}>
      <div className="section-title-row">
        <Typography.Title level={4} className="section-block-title">ECS 实例</Typography.Title>
        <Button size="small" icon={<ReloadOutlined />} loading={ecsLoading} onClick={() => void loadEcsInstances()}>刷新</Button>
      </div>
      <Typography.Paragraph type="secondary">该账号下所有地域的 ECS 实例，共 {ecsInstances.length} 台</Typography.Paragraph>
      <Table<EcsInstance>
        className="modern-table"
        rowKey="instanceId"
        columns={ecsColumns}
        dataSource={ecsInstances}
        size="small"
        loading={ecsLoading}
        pagination={{ pageSize: 15, showSizeChanger: false }}
        locale={{ emptyText: "暂无 ECS 实例" }}
        tableLayout="fixed"
      />
    </Card>
  );

  const aliyunPage = (
    <div className="workspace-stack">
      <div className="aliyun-feature-bar">
        <Segmented
          size="small"
          value={aliyunFeature}
          onChange={(val) => setAliyunFeature(val as AliyunFeature)}
          options={ALIYUN_FEATURE_OPTIONS}
        />
        {aliyunFeature !== "whitelist" && (
          <Select
            size="small"
            style={{ minWidth: 160 }}
            placeholder="选择账号"
            value={aliyunActiveAccountId || undefined}
            onChange={(val) => setAliyunActiveAccountId(val)}
            options={accountOptions}
          />
        )}
      </div>
      {aliyunFeature === "whitelist" && (
      <>
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
                    <span>类型</span>
                    <b>{aliyunTargetTypeLabel(record.targetType)}</b>
                  </div>
                  <div className="detail-item">
                    <span>动作</span>
                    <b>{record.action}</b>
                  </div>
                  <div className="detail-item">
                    <span>白名单分组</span>
                    <b>{record.whitelistGroupName || "-"}</b>
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
            支持两类目标：ECS 安全组规则，或 PolarDB 集群 IP 白名单分组。
          </Typography.Paragraph>
          <Typography.Paragraph type="secondary" className="section-help">
            ECS 目标按 ruleId 或描述匹配；PolarDB 目标按白名单分组名直接覆盖为本机公网 IP。
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
                      {record.targetType === "ecsSecurityGroup" ? (
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
                      ) : (
                        <Input
                          value={record.dbClusterIpArrayName || ""}
                          placeholder="例如 spenceryg"
                          addonBefore="白名单分组名"
                          onChange={(event) =>
                            updateTarget(record.id, {
                              dbClusterIpArrayName: normalizeNullable(event.target.value),
                            })
                          }
                        />
                      )}
                    </div>
                  ),
                }}
              />
            </>
          ) : null}
        </Card>
      </div>
      </>
      )}
      {aliyunFeature === "dns" && dnsPage}
      {aliyunFeature === "domain" && domainPage}
      {aliyunFeature === "ssl" && sslPage}
      {aliyunFeature === "ecs" && ecsPage}
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
                className="topbar-btn topbar-btn-ssh-test"
                icon={<CloudSyncOutlined />}
                loading={testingAllSsh}
                onClick={() => void testAllSshShortcuts()}
              >
                一键测试全部
              </Button>
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
        <div className="ssh-metric-chip ssh-metric-chip-tested">
          已测试 {testedSshCount}（成功 {successSshCount} / 失败 {failedSshCount}）
        </div>
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
            expandedRowRender: (record) => {
              const status = sshConnectionStatusMap[record.alias] ?? makeUnknownSshStatus(record.alias);
              const meta = sshShortcutMetaMap[record.alias] ?? { expireAt: null, remark: "" };
              const expired = !!(meta.expireAt && meta.expireAt < currentDateText);
              return (
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
                    <span>到期时间</span>
                    <Space direction="vertical" size={6} style={{ width: "100%" }}>
                      <Input
                        size="small"
                        type="date"
                        value={meta.expireAt || ""}
                        onChange={(event) =>
                          updateSshShortcutMeta(record.alias, {
                            expireAt: event.target.value || null,
                          })
                        }
                      />
                      {meta.expireAt ? (
                        <Tag color={expired ? "error" : "success"}>{expired ? "已到期" : "有效中"}</Tag>
                      ) : (
                        <Tag>未设置</Tag>
                      )}
                    </Space>
                  </div>
                  <div className="detail-item">
                    <span>备注</span>
                    <Input
                      size="small"
                      value={meta.remark}
                      maxLength={120}
                      allowClear
                      placeholder="例如：临时账号、负责人、用途说明"
                      onChange={(event) =>
                        updateSshShortcutMeta(record.alias, {
                          remark: event.target.value,
                        })
                      }
                    />
                  </div>
                  <div className="detail-item">
                    <span>解析状态</span>
                    <b>{record.error || "正常"}</b>
                  </div>
                  <div className="detail-item">
                    <span>连接状态</span>
                    <b>{sshStatusText(status.status)}</b>
                  </div>
                  <div className="detail-item">
                    <span>最近测试</span>
                    <b>{status.checkedAt ? new Date(status.checkedAt).toLocaleString() : "-"}</b>
                  </div>
                  <div className="detail-item">
                    <span>测试输出</span>
                    <b>{status.output || "-"}</b>
                  </div>
                </div>
              );
            },
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
                  <Tooltip title="设置">
                    <button
                      type="button"
                      className="left-rail-switch-btn"
                      onClick={() => setSettingsOpen(true)}
                      aria-label="打开设置"
                    >
                      <SettingOutlined className={`left-rail-item ${settingsOpen ? "active" : ""}`} />
                    </button>
                  </Tooltip>
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
              <div className="app-workspace">
                {moduleKey === "aliyun" ? aliyunPage : sshPage}
              </div>
            </div>
          </Layout.Content>
        </Layout>
        <Drawer
          title="设置"
          open={settingsOpen}
          width={360}
          className={`settings-drawer${isDarkMode ? " settings-drawer-dark" : ""}`}
          onClose={() => setSettingsOpen(false)}
        >
          <div className="settings-drawer-content">
            <Typography.Paragraph className="settings-drawer-desc">
              配置管理：支持一键导出与一键导入。
            </Typography.Paragraph>

            <Card className="settings-drawer-card" bordered={false}>
              <Typography.Title level={5} className="settings-drawer-card-title">
                导出配置
              </Typography.Title>
              <Typography.Paragraph type="secondary" className="settings-drawer-card-desc">
                先选择一个文件夹，再自动生成配置备份文件。
              </Typography.Paragraph>
              <Button
                type="primary"
                block
                icon={<DownloadOutlined />}
                loading={configTransferAction === "export"}
                disabled={configTransferAction === "import"}
                onClick={() => void exportConfigBackup()}
              >
                一键导出配置
              </Button>
            </Card>

            <Card className="settings-drawer-card" bordered={false}>
              <Typography.Title level={5} className="settings-drawer-card-title">
                导入配置
              </Typography.Title>
              <Typography.Paragraph type="secondary" className="settings-drawer-card-desc">
                先选择一个文件夹，系统会自动读取该目录下最新的配置备份文件。
              </Typography.Paragraph>
              <Button
                block
                icon={<UploadOutlined />}
                loading={configTransferAction === "import"}
                disabled={configTransferAction === "export"}
                onClick={() => void importConfigBackup()}
              >
                一键导入配置
              </Button>
            </Card>

            <Typography.Text type="secondary" className="settings-drawer-hint">
              建议仅导入你自己导出的配置文件。
            </Typography.Text>
          </div>
        </Drawer>
      </ConfigProvider>
    </Theme>
  );
}
