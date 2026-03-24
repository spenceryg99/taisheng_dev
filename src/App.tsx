import { useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { openUrl } from "@tauri-apps/plugin-opener";
import {
  Button,
  Card,
  Collapse,
  ConfigProvider,
  Drawer,
  Input,
  Layout,
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
  CopyOutlined,
  CloudSyncOutlined,
  DeleteOutlined,
  DownOutlined,
  DownloadOutlined,
  EyeInvisibleOutlined,
  EyeOutlined,
  GlobalOutlined,
  FileSearchOutlined,
  LinkOutlined,
  MoonOutlined,
  PlusOutlined,
  ReloadOutlined,
  RightOutlined,
  SaveOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
  ShopOutlined,
  SunOutlined,
  UploadOutlined,
} from "@ant-design/icons";

type Nullable<T> = T | null;
type StatusType = "info" | "success" | "warning" | "error";
type ModuleKey = "aliyun" | "ssh" | "pdd" | "website" | "logs";
type SshViewMode = "enabled" | "all";
type ThemeMode = "light" | "dark";
type PddViewMode = "manage" | "sync";
type SshConnectionState = "unknown" | "success" | "failed";
type LogLevelFilter = "all" | "info" | "error" | "warn" | "unknown";
type LogQueryMode = "query" | "tail";

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

interface SshConnectionTestResult {
  alias: string;
  status: SshConnectionState;
  exitCode?: number | null;
  output: string;
  checkedAt: string;
}

interface PddStoreItem {
  accountName: string;
  code: string;
}

interface PddAccountInput {
  id: string;
  name: string;
  account: string;
  password: string;
  appId: string;
  storeMallList: PddStoreItem[];
  cookiePath: Nullable<string>;
  cookieStatus: "unknown" | "valid" | "invalid";
  cookieCheckedAt: Nullable<string>;
  cookieReason: Nullable<string>;
}

interface PddLoginRequest {
  name: string;
  account: string;
  password: string;
  loginUrl: string;
  appId: string;
  cookiePath: Nullable<string>;
  ocrKey?: Nullable<string>;
}

interface PddLoginResponse {
  cookiePath: string;
  cookieCount: number;
  savedAt: string;
  message: string;
  loginUrl: string;
  account: string;
  ownerMallList?: PddStoreItem[];
  ownerMallNameList?: string[];
  capturePath?: string | null;
}

interface PddQuickSyncRequest {
  filePath: string;
  serverAlias: string;
  taskId: number;
  receiveId: number;
}

interface PddSyncStepResult {
  key: string;
  step: number;
  title: string;
  command: string;
  status: string;
  exitCode?: number | null;
  output: string;
}

interface PddQuickSyncResponse {
  success: boolean;
  message: string;
  filePath: string;
  serverAlias: string;
  taskId: number;
  oldReceiveId?: number | null;
  newReceiveId: number;
  replacedLine?: number | null;
  replacedCount: number;
  commitHash?: string | null;
  branch?: string | null;
  pushed?: boolean;
  steps?: PddSyncStepResult[];
  remoteSteps?: PddSyncStepResult[];
  updatedAt: string;
}

interface PddPersistedState {
  loginUrl: string;
  ocrKey: string;
  accounts: PddAccountInput[];
  syncFilePath?: string;
  syncTaskId?: number | null;
  syncServerAlias?: string | null;
}

interface WebsiteEntry {
  id: string;
  name: string;
  url: string;
  username: string;
  password: string;
}

interface StartLocalDevServicesResponse {
  backendPort: number;
  frontendPort: number;
  clearedBackendPids: number[];
  clearedFrontendPids: number[];
  message: string;
}

interface PlogListFiltersRequest {
  serverAlias: string;
  baseDir?: string;
  days?: number;
}

interface PlogListFiltersResponse {
  typeDirs: string[];
  logFiles: string[];
  dateDirs: string[];
}

interface PlogKeyFilters {
  orderId?: string;
  orderNo?: string;
  extOrderId?: string;
  mobile?: string;
  channel?: string;
}

interface PlogCustomFieldRule {
  name: string;
  keys: string[];
  contains?: string;
}

interface PlogQueryRequest {
  serverAlias: string;
  baseDir?: string;
  startAt: string;
  endAt: string;
  taskTypes?: string[];
  typeDirs?: string[];
  logFiles?: string[];
  level?: LogLevelFilter;
  keywords?: string[];
  keyFilters?: PlogKeyFilters;
  customFields?: PlogCustomFieldRule[];
  limit?: number;
  contextLines?: number;
}

interface PlogQueryItem {
  ts?: string | null;
  level: string;
  taskType: string;
  typeDir: string;
  logFile: string;
  message: string;
  orderId?: string | null;
  orderNo?: string | null;
  extOrderId?: string | null;
  mobile?: string | null;
  channel?: string | null;
  filePath: string;
  lineNo: number;
  rawLine: string;
  customFields?: Record<string, string>;
  context?: string[] | null;
}

interface PlogQueryResponse {
  elapsedMs: number;
  scannedFiles: number;
  scannedLines: number;
  matchedLines: number;
  truncated: boolean;
  items: PlogQueryItem[];
}

interface PlogTailRequest {
  serverAlias: string;
  baseDir?: string;
  taskTypes?: string[];
  typeDirs?: string[];
  logFiles?: string[];
  level?: LogLevelFilter;
  keywords?: string[];
  keyFilters?: PlogKeyFilters;
  customFields?: PlogCustomFieldRule[];
  limit?: number;
  maxFiles?: number;
  sinceAt?: string;
}

interface PlogTailResponse {
  elapsedMs: number;
  scannedFiles: number;
  scannedLines: number;
  matchedLines: number;
  truncated: boolean;
  items: PlogQueryItem[];
}

interface LogQueryTemplatePayload {
  baseDir: string;
  startAt: string;
  endAt: string;
  selectedTaskTypes: string[];
  selectedTypeDirs: string[];
  selectedLogFiles: string[];
  level: LogLevelFilter;
  keywords: string;
  orderId: string;
  orderNo: string;
  extOrderId: string;
  mobile: string;
  channel: string;
  limit: string;
  customRules: PlogCustomFieldRule[];
}

interface LogQueryTemplate {
  id: string;
  name: string;
  updatedAt: string;
  payload: LogQueryTemplatePayload;
}

interface ConfigBackupPayload {
  aliyun: PersistedState;
  pdd: PddPersistedState;
  websiteEntries: WebsiteEntry[];
  logTemplates: LogQueryTemplate[];
  hiddenSshAliases: string[];
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
const THEME_MODE_STORAGE_KEY = "desktop-theme-mode-v2";
const PDD_STORAGE_KEY = "pdd-open-platform-manager-v1";
const WEBSITE_STORAGE_KEY = "website-login-manager-v1";
const PLOG_TEMPLATE_STORAGE_KEY = "plog-query-templates-v1";
const CONFIG_BACKUP_SCHEMA = "sp-toolbox-config";
const PDD_DEFAULT_LOGIN_URL = "https://open.pinduoduo.com/application/home";
const PDD_LEGACY_LOGIN_URL = "https://mms.pinduoduo.com/login/";
const DEFAULT_PLOG_BASE_DIR = "~/junziyun-v7/storage/logs/custom";
const LOG_TASK_TYPE_OPTIONS = [
  "下单提单",
  "查单状态同步",
  "回调通知",
  "调度任务",
  "渠道鉴权配置",
  "取消订单",
  "异常错误",
  "商品套餐地址",
  "其他",
] as const;
const PDD_SYNC_TASK_OPTIONS: { label: string; value: number }[] = [
  { label: "泰盛卡行（task 0）", value: 0 },
  { label: "手机号卡订单管理（task 1）", value: 1 },
  { label: "爱宇订单导出（task 2）", value: 2 },
];

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

function formatDateTimeText(date: Date): string {
  const y = date.getFullYear();
  const m = pad2(date.getMonth() + 1);
  const d = pad2(date.getDate());
  const h = pad2(date.getHours());
  const min = pad2(date.getMinutes());
  const sec = pad2(date.getSeconds());
  return `${y}-${m}-${d} ${h}:${min}:${sec}`;
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

function isRecordObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseKeywordInput(value: string): string[] {
  return value
    .split(/[\n,，\s]+/)
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

function parseCustomRuleKeys(value: string): string[] {
  return value
    .split(/[\n,，;\s]+/)
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

function normalizeCustomRules(source: unknown): PlogCustomFieldRule[] {
  if (!Array.isArray(source)) {
    return [];
  }
  return source
    .map((item) => {
      if (!item || typeof item !== "object") {
        return null;
      }
      const maybe = item as {
        name?: unknown;
        keys?: unknown;
        contains?: unknown;
      };
      const name = String(maybe.name ?? "").trim();
      const keyList = Array.isArray(maybe.keys)
        ? maybe.keys.map((key) => String(key).trim()).filter((key) => key.length > 0)
        : [];
      const contains = String(maybe.contains ?? "").trim();
      if (!name || keyList.length === 0) {
        return null;
      }
      return {
        name,
        keys: Array.from(new Set(keyList)),
        contains: contains || undefined,
      } as PlogCustomFieldRule;
    })
    .filter((item): item is PlogCustomFieldRule => item !== null);
}

function readLogQueryTemplates(): LogQueryTemplate[] {
  try {
    const raw = localStorage.getItem(PLOG_TEMPLATE_STORAGE_KEY);
    if (!raw) {
      return [];
    }
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed
      .map((item) => {
        if (!item || typeof item !== "object") {
          return null;
        }
        const maybe = item as {
          id?: unknown;
          name?: unknown;
          updatedAt?: unknown;
          payload?: unknown;
        };
        const payload = (maybe.payload || {}) as Partial<LogQueryTemplatePayload>;
        const name = String(maybe.name ?? "").trim();
        if (!name) {
          return null;
        }
        return {
          id: String(maybe.id ?? uid("log-template")),
          name,
          updatedAt: String(maybe.updatedAt ?? ""),
          payload: {
            baseDir: String(payload.baseDir ?? DEFAULT_PLOG_BASE_DIR),
            startAt: String(payload.startAt ?? ""),
            endAt: String(payload.endAt ?? ""),
            selectedTaskTypes: Array.isArray(payload.selectedTaskTypes)
              ? payload.selectedTaskTypes.map((value) => String(value))
              : [],
            selectedTypeDirs: Array.isArray(payload.selectedTypeDirs)
              ? payload.selectedTypeDirs.map((value) => String(value))
              : [],
            selectedLogFiles: Array.isArray(payload.selectedLogFiles)
              ? payload.selectedLogFiles.map((value) => String(value))
              : [],
            level:
              payload.level === "info" ||
              payload.level === "error" ||
              payload.level === "warn" ||
              payload.level === "unknown" ||
              payload.level === "all"
                ? payload.level
                : "all",
            keywords: String(payload.keywords ?? ""),
            orderId: String(payload.orderId ?? ""),
            orderNo: String(payload.orderNo ?? ""),
            extOrderId: String(payload.extOrderId ?? ""),
            mobile: String(payload.mobile ?? ""),
            channel: String(payload.channel ?? ""),
            limit: String(payload.limit ?? "200"),
            customRules: normalizeCustomRules(payload.customRules),
          },
        } as LogQueryTemplate;
      })
      .filter((item): item is LogQueryTemplate => item !== null)
      .slice(0, 30);
  } catch {
    return [];
  }
}

function persistLogQueryTemplates(templates: LogQueryTemplate[]): void {
  localStorage.setItem(PLOG_TEMPLATE_STORAGE_KEY, JSON.stringify(templates));
}

function normalizeStoreItem(value: unknown): PddStoreItem | null {
  if (!value || typeof value !== "object") {
    return null;
  }
  const maybe = value as { accountName?: unknown; code?: unknown };
  const accountName = String(maybe.accountName ?? "").trim();
  const code = String(maybe.code ?? "").trim();
  if (!accountName) {
    return null;
  }
  return { accountName, code };
}

function normalizePersistedStoreMallList(primary: unknown, legacyNames: unknown): PddStoreItem[] {
  if (Array.isArray(primary)) {
    return primary.map((item) => normalizeStoreItem(item)).filter((item): item is PddStoreItem => item !== null);
  }
  if (Array.isArray(legacyNames)) {
    return legacyNames
      .map((name) => String(name).trim())
      .filter((name) => name.length > 0)
      .map((accountName) => ({ accountName, code: "" }));
  }
  return [];
}

function buildPddSyncStepKey(step: Pick<PddSyncStepResult, "key" | "step">): string {
  return `${step.key || "step"}-${step.step}`;
}

function pddSyncStatusLabel(status: string): string {
  switch (status) {
    case "success":
      return "成功";
    case "failed":
      return "失败";
    case "skipped":
      return "跳过";
    default:
      return status || "未知";
  }
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

async function copyTextToClipboard(text: string): Promise<void> {
  if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }

  if (typeof document === "undefined") {
    throw new Error("当前环境不支持复制");
  }
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "readonly");
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  textarea.style.pointerEvents = "none";
  document.body.appendChild(textarea);
  textarea.select();
  const copied = document.execCommand("copy");
  document.body.removeChild(textarea);
  if (!copied) {
    throw new Error("浏览器拒绝复制");
  }
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

function blankPddAccount(): PddAccountInput {
  return {
    id: uid("pdd"),
    name: "",
    account: "",
    password: "",
    appId: "",
    storeMallList: [],
    cookiePath: null,
    cookieStatus: "unknown",
    cookieCheckedAt: null,
    cookieReason: null,
  };
}

function blankWebsiteEntry(): WebsiteEntry {
  return {
    id: uid("website"),
    name: "",
    url: "",
    username: "",
    password: "",
  };
}

function normalizeWebsiteUrl(rawUrl: string): string {
  const trimmed = rawUrl.trim();
  if (!trimmed) {
    return "";
  }
  if (/^https?:\/\//i.test(trimmed)) {
    return trimmed;
  }
  return `https://${trimmed}`;
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
  const [sshConnectionStatusMap, setSshConnectionStatusMap] = useState<
    Record<string, SshConnectionTestResult>
  >({});
  const [testingSshAlias, setTestingSshAlias] = useState<string | null>(null);
  const [testingAllSsh, setTestingAllSsh] = useState(false);
  const [deletingSshAlias, setDeletingSshAlias] = useState<string | null>(null);
  const [aliyunSection, setAliyunSection] = useState<"run" | "accounts" | "targets">("run");
  const [showAccountEditor, setShowAccountEditor] = useState(false);
  const [showTargetEditor, setShowTargetEditor] = useState(false);
  const [themeMode, setThemeMode] = useState<ThemeMode>(() => readThemeMode());
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [configTransferAction, setConfigTransferAction] = useState<"import" | "export" | null>(null);

  const [pddLoginUrl, setPddLoginUrl] = useState(PDD_DEFAULT_LOGIN_URL);
  const [pddOcrKey, setPddOcrKey] = useState("");
  const [pddAccounts, setPddAccounts] = useState<PddAccountInput[]>([]);
  const [pddLoggingInAccountId, setPddLoggingInAccountId] = useState<string | null>(null);
  const [pddExpandedAccountIds, setPddExpandedAccountIds] = useState<string[]>([]);
  const [pddSyncFilePath, setPddSyncFilePath] = useState("");
  const [pddSyncTaskId, setPddSyncTaskId] = useState<number | undefined>(undefined);
  const [pddSyncReceiveId, setPddSyncReceiveId] = useState("");
  const [pddSyncServerAlias, setPddSyncServerAlias] = useState<string | undefined>(undefined);
  const [pddSyncing, setPddSyncing] = useState(false);
  const [pddSyncSummary, setPddSyncSummary] = useState("等待执行。");
  const [pddSyncSteps, setPddSyncSteps] = useState<PddSyncStepResult[]>([]);
  const [pddSyncActiveStepKey, setPddSyncActiveStepKey] = useState<string | null>(null);
  const [pddViewMode, setPddViewMode] = useState<PddViewMode>("manage");
  const [websiteEntries, setWebsiteEntries] = useState<WebsiteEntry[]>([]);
  const [openingWebsiteId, setOpeningWebsiteId] = useState<string | null>(null);
  const [startingLocalServices, setStartingLocalServices] = useState(false);
  const [logServerAlias, setLogServerAlias] = useState<string | undefined>(undefined);
  const [logBaseDir, setLogBaseDir] = useState(DEFAULT_PLOG_BASE_DIR);
  const [logStartAt, setLogStartAt] = useState(() =>
    formatDateTimeText(new Date(Date.now() - 2 * 60 * 60 * 1000))
  );
  const [logEndAt, setLogEndAt] = useState(() => formatDateTimeText(new Date()));
  const [logTypeDirOptions, setLogTypeDirOptions] = useState<string[]>([]);
  const [logLogFileOptions, setLogLogFileOptions] = useState<string[]>([]);
  const [logSelectedTypeDirs, setLogSelectedTypeDirs] = useState<string[]>([]);
  const [logSelectedLogFiles, setLogSelectedLogFiles] = useState<string[]>([]);
  const [logSelectedTaskTypes, setLogSelectedTaskTypes] = useState<string[]>([]);
  const [logLevelFilter, setLogLevelFilter] = useState<LogLevelFilter>("all");
  const [logKeywords, setLogKeywords] = useState("");
  const [logQueryMode, setLogQueryMode] = useState<LogQueryMode>("query");
  const [logTailIntervalSec, setLogTailIntervalSec] = useState<number>(5);
  const [logTailing, setLogTailing] = useState(false);
  const [logCustomRules, setLogCustomRules] = useState<PlogCustomFieldRule[]>([]);
  const [logCustomNameDraft, setLogCustomNameDraft] = useState("");
  const [logCustomKeysDraft, setLogCustomKeysDraft] = useState("");
  const [logCustomContainsDraft, setLogCustomContainsDraft] = useState("");
  const [logTemplates, setLogTemplates] = useState<LogQueryTemplate[]>(() =>
    readLogQueryTemplates()
  );
  const [logSelectedTemplateId, setLogSelectedTemplateId] = useState<string | undefined>(
    undefined
  );
  const [logTemplateName, setLogTemplateName] = useState("");
  const [logOrderId, setLogOrderId] = useState("");
  const [logOrderNo, setLogOrderNo] = useState("");
  const [logExtOrderId, setLogExtOrderId] = useState("");
  const [logMobile, setLogMobile] = useState("");
  const [logChannel, setLogChannel] = useState("");
  const [logLimit, setLogLimit] = useState("200");
  const [logRows, setLogRows] = useState<PlogQueryItem[]>([]);
  const [logQuerying, setLogQuerying] = useState(false);
  const [logFiltersLoading, setLogFiltersLoading] = useState(false);
  const [logSummary, setLogSummary] = useState("等待执行查询。");
  const [logStats, setLogStats] = useState<{
    scannedFiles: number;
    scannedLines: number;
    matchedLines: number;
    elapsedMs: number;
    truncated: boolean;
  }>({
    scannedFiles: 0,
    scannedLines: 0,
    matchedLines: 0,
    elapsedMs: 0,
    truncated: false,
  });

  const bootstrappedRef = useRef(false);
  const sshBootstrappedRef = useRef(false);
  const pddSshBootstrappedRef = useRef(false);
  const logBootstrappedRef = useRef(false);
  const pddConfigLoadedRef = useRef(false);
  const logTailTimerRef = useRef<number | null>(null);
  const logTailFetchingRef = useRef(false);
  const logTailSeenKeysRef = useRef<Set<string>>(new Set());
  const logTailSinceAtRef = useRef<string | undefined>(undefined);
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
  const pddSyncServerOptions = useMemo(
    () =>
      sshShortcuts
        .filter((row) => !hiddenAliasSet.has(row.alias))
        .map((row) => {
          const hostText = row.hostName?.trim();
          const userText = row.user?.trim();
          const portText = row.port?.trim();
          const detail = hostText
            ? `${userText ? `${userText}@` : ""}${hostText}${portText ? `:${portText}` : ""}`
            : "";
          return {
            label: detail ? `${row.alias} (${detail})` : row.alias,
            value: row.alias,
          };
        }),
    [hiddenAliasSet, sshShortcuts]
  );
  const logServerOptions = pddSyncServerOptions;
  const logTaskOptions = useMemo(
    () => LOG_TASK_TYPE_OPTIONS.map((item) => ({ label: item, value: item })),
    []
  );
  const logTemplateOptions = useMemo(
    () =>
      logTemplates.map((item) => ({
        label: `${item.name} · ${item.updatedAt ? new Date(item.updatedAt).toLocaleString() : "未记录时间"}`,
        value: item.id,
      })),
    [logTemplates]
  );
  const pddFilledAppIdCount = useMemo(
    () => pddAccounts.filter((item) => item.appId.trim().length > 0).length,
    [pddAccounts]
  );
  const pddMissingAppIdCount = useMemo(
    () => pddAccounts.filter((item) => item.appId.trim().length === 0).length,
    [pddAccounts]
  );
  const pddTotalStoreCount = useMemo(
    () =>
      pddAccounts.reduce(
        (total, item) => total + (Array.isArray(item.storeMallList) ? item.storeMallList.length : 0),
        0
      ),
    [pddAccounts]
  );
  const websiteConfiguredCount = useMemo(
    () => websiteEntries.filter((item) => item.url.trim().length > 0).length,
    [websiteEntries]
  );
  const pddActiveSyncStep = useMemo(() => {
    if (pddSyncSteps.length === 0) {
      return null;
    }
    if (!pddSyncActiveStepKey) {
      return pddSyncSteps[0];
    }
    return (
      pddSyncSteps.find((step) => buildPddSyncStepKey(step) === pddSyncActiveStepKey) ??
      pddSyncSteps[0]
    );
  }, [pddSyncActiveStepKey, pddSyncSteps]);
  const pddSyncDetailText = useMemo(() => {
    if (!pddActiveSyncStep) {
      return pddSyncSummary;
    }
    return [
      pddSyncSummary,
      "",
      `当前步骤: Step ${pddActiveSyncStep.step} · ${pddActiveSyncStep.title}`,
      `状态: ${pddSyncStatusLabel(pddActiveSyncStep.status)}`,
      `命令: ${pddActiveSyncStep.command || "-"}`,
      `退出码: ${pddActiveSyncStep.exitCode ?? "-"}`,
      "",
      pddActiveSyncStep.output || "<empty>",
    ].join("\n");
  }, [pddActiveSyncStep, pddSyncSummary]);

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

  const persistPddConfig = (
    nextAccounts: PddAccountInput[] = pddAccounts,
    nextLoginUrl = pddLoginUrl,
    nextOcrKey = pddOcrKey,
    shouldToast = true
  ): void => {
    const payload: PddPersistedState = {
      loginUrl: nextLoginUrl.trim() || PDD_DEFAULT_LOGIN_URL,
      ocrKey: nextOcrKey,
      accounts: nextAccounts,
      syncFilePath: pddSyncFilePath.trim(),
      syncTaskId: pddSyncTaskId ?? null,
      syncServerAlias: pddSyncServerAlias ?? null,
    };
    localStorage.setItem(PDD_STORAGE_KEY, JSON.stringify(payload));
    if (shouldToast) {
      messageApi.success("拼多多配置已保存");
    }
  };

  const loadPddConfig = (shouldToast = true): void => {
    const raw = localStorage.getItem(PDD_STORAGE_KEY);
    if (!raw) {
      const base = [blankPddAccount()];
      setPddAccounts(base);
      setPddLoginUrl(PDD_DEFAULT_LOGIN_URL);
      setPddOcrKey("");
      setPddSyncFilePath("");
      setPddSyncTaskId(undefined);
      setPddSyncServerAlias(undefined);
      pddConfigLoadedRef.current = true;
      if (shouldToast) {
        messageApi.info("已创建默认拼多多账号行");
      }
      return;
    }

    try {
      const parsed = JSON.parse(raw) as PddPersistedState;
      const loadedLoginUrl = parsed.loginUrl?.trim() || "";
      const normalizedLoginUrl =
        !loadedLoginUrl || loadedLoginUrl === PDD_LEGACY_LOGIN_URL
          ? PDD_DEFAULT_LOGIN_URL
          : loadedLoginUrl;
      const accountsLoaded = (parsed.accounts ?? []).map((item) => ({
        ...blankPddAccount(),
        ...item,
        id: item.id || uid("pdd"),
        appId: (item.appId || "").trim(),
        storeMallList: normalizePersistedStoreMallList(
          (item as unknown as { storeMallList?: unknown; storeMallNames?: unknown }).storeMallList,
          (item as unknown as { storeMallList?: unknown; storeMallNames?: unknown }).storeMallNames
        ),
        cookiePath: normalizeNullable(item.cookiePath),
        cookieCheckedAt: normalizeNullable(item.cookieCheckedAt),
        cookieReason: normalizeNullable(item.cookieReason),
      }));
      const ensuredAccounts = accountsLoaded.length > 0 ? accountsLoaded : [blankPddAccount()];

      setPddAccounts(ensuredAccounts);
      setPddLoginUrl(normalizedLoginUrl);
      setPddOcrKey(parsed.ocrKey || "");
      setPddSyncFilePath((parsed.syncFilePath || "").trim());
      setPddSyncTaskId(
        typeof parsed.syncTaskId === "number" && Number.isFinite(parsed.syncTaskId)
          ? parsed.syncTaskId
          : undefined
      );
      setPddSyncServerAlias(
        parsed.syncServerAlias && parsed.syncServerAlias.trim()
          ? parsed.syncServerAlias.trim()
          : undefined
      );
      pddConfigLoadedRef.current = true;
      if (shouldToast) {
        messageApi.success("已加载拼多多配置");
      }
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      const base = [blankPddAccount()];
      setPddAccounts(base);
      setPddLoginUrl(PDD_DEFAULT_LOGIN_URL);
      setPddOcrKey("");
      setPddSyncFilePath("");
      setPddSyncTaskId(undefined);
      setPddSyncServerAlias(undefined);
      pddConfigLoadedRef.current = true;
      messageApi.error(`加载拼多多配置失败: ${detail}`);
    }
  };

  const persistWebsiteEntries = (
    nextEntries: WebsiteEntry[] = websiteEntries,
    shouldToast = true
  ): void => {
    localStorage.setItem(WEBSITE_STORAGE_KEY, JSON.stringify(nextEntries));
    if (shouldToast) {
      messageApi.success("网址配置已保存");
    }
  };

  const loadWebsiteEntries = (shouldToast = true): void => {
    const raw = localStorage.getItem(WEBSITE_STORAGE_KEY);
    if (!raw) {
      const base = [blankWebsiteEntry()];
      setWebsiteEntries(base);
      if (shouldToast) {
        messageApi.info("已创建默认网址条目");
      }
      return;
    }

    try {
      const parsed = JSON.parse(raw) as WebsiteEntry[] | { entries?: WebsiteEntry[] };
      const sourceRows = Array.isArray(parsed)
        ? parsed
        : Array.isArray(parsed.entries)
          ? parsed.entries
          : [];
      const loadedRows = sourceRows.map((item) => ({
        ...blankWebsiteEntry(),
        ...item,
        id: item.id || uid("website"),
        name: String(item.name || ""),
        url: String(item.url || ""),
        username: String(item.username || ""),
        password: String(item.password || ""),
      }));
      const ensuredRows = loadedRows.length > 0 ? loadedRows : [blankWebsiteEntry()];
      setWebsiteEntries(ensuredRows);
      if (shouldToast) {
        messageApi.success("已加载网址配置");
      }
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      setWebsiteEntries([blankWebsiteEntry()]);
      messageApi.error(`加载网址配置失败: ${detail}`);
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
          pdd: {
            loginUrl: pddLoginUrl.trim() || PDD_DEFAULT_LOGIN_URL,
            ocrKey: pddOcrKey,
            accounts: pddAccounts,
            syncFilePath: pddSyncFilePath.trim(),
            syncTaskId: pddSyncTaskId ?? null,
            syncServerAlias: pddSyncServerAlias ?? null,
          },
          websiteEntries,
          logTemplates,
          hiddenSshAliases,
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

      const pddValue = sourceRoot.pdd;
      if (isRecordObject(pddValue) && Array.isArray(pddValue.accounts)) {
        localStorage.setItem(PDD_STORAGE_KEY, JSON.stringify(pddValue));
        importedLabels.push("拼多多");
      }

      const websiteValue = sourceRoot.websiteEntries ?? sourceRoot.website;
      if (
        Array.isArray(websiteValue) ||
        (isRecordObject(websiteValue) && Array.isArray(websiteValue.entries))
      ) {
        localStorage.setItem(WEBSITE_STORAGE_KEY, JSON.stringify(websiteValue));
        importedLabels.push("网址");
      }

      const logTemplatesValue = sourceRoot.logTemplates;
      if (Array.isArray(logTemplatesValue)) {
        localStorage.setItem(PLOG_TEMPLATE_STORAGE_KEY, JSON.stringify(logTemplatesValue));
        importedLabels.push("日志模板");
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
      loadPddConfig(false);
      loadWebsiteEntries(false);
      setHiddenSshAliases(readHiddenSshAliases());
      setLogTemplates(readLogQueryTemplates());
      setLogSelectedTemplateId(undefined);
      setLogTemplateName("");
      messageApi.success(`配置导入成功：${importedLabels.join("、")}（${backupFilePath}）`);
      setSettingsOpen(false);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      messageApi.error(`导入配置失败: ${detail}`);
    } finally {
      setConfigTransferAction(null);
    }
  };

  const updateWebsiteEntry = (id: string, patch: Partial<WebsiteEntry>): void => {
    setWebsiteEntries((prev) => {
      const next = prev.map((item) => (item.id === id ? { ...item, ...patch } : item));
      persistWebsiteEntries(next, false);
      return next;
    });
  };

  const addWebsiteEntry = (): void => {
    setWebsiteEntries((prev) => {
      const next = [...prev, blankWebsiteEntry()];
      persistWebsiteEntries(next, false);
      return next;
    });
  };

  const deleteWebsiteEntry = (id: string): void => {
    setWebsiteEntries((prev) => {
      const next = prev.filter((item) => item.id !== id);
      const ensured = next.length > 0 ? next : [blankWebsiteEntry()];
      persistWebsiteEntries(ensured, false);
      return ensured;
    });
  };

  const openWebsiteUrl = async (entry: WebsiteEntry): Promise<void> => {
    const rawUrl = entry.url.trim();
    if (!rawUrl) {
      messageApi.warning("请先填写网址");
      return;
    }

    const normalizedUrl = normalizeWebsiteUrl(rawUrl);
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(normalizedUrl);
    } catch {
      messageApi.warning("网址格式不正确，请输入有效地址");
      return;
    }

    if (!["http:", "https:"].includes(parsedUrl.protocol)) {
      messageApi.warning("仅支持 http 或 https 协议");
      return;
    }

    setOpeningWebsiteId(entry.id);
    try {
      await openUrl(parsedUrl.toString());
      messageApi.success(`已打开 ${entry.name.trim() || parsedUrl.hostname}`);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      messageApi.error(`打开网址失败: ${detail}`);
    } finally {
      setOpeningWebsiteId(null);
    }
  };

  const startLocalDevServices = async (): Promise<void> => {
    setStartingLocalServices(true);
    try {
      const response = await invoke<StartLocalDevServicesResponse>("start_local_dev_services");
      const backendKilled = response.clearedBackendPids.length;
      const frontendKilled = response.clearedFrontendPids.length;
      messageApi.success(
        `${response.message}（后端端口 ${response.backendPort} 清理 ${backendKilled} 个进程，前端端口 ${response.frontendPort} 清理 ${frontendKilled} 个进程）`
      );
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      messageApi.error(`启动本地服务失败: ${detail}`);
    } finally {
      setStartingLocalServices(false);
    }
  };

  const updatePddAccount = (id: string, patch: Partial<PddAccountInput>): void => {
    setPddAccounts((prev) => {
      const next = prev.map((item) => (item.id === id ? { ...item, ...patch } : item));
      persistPddConfig(next, pddLoginUrl, pddOcrKey, false);
      return next;
    });
  };

  const addPddAccount = (): void => {
    const newRow = blankPddAccount();
    setPddAccounts((prev) => {
      const next = [...prev, newRow];
      persistPddConfig(next, pddLoginUrl, pddOcrKey, false);
      return next;
    });
  };

  const deletePddAccount = (id: string): void => {
    setPddAccounts((prev) => {
      const next = prev.filter((item) => item.id !== id);
      const ensured = next.length > 0 ? next : [blankPddAccount()];
      persistPddConfig(ensured, pddLoginUrl, pddOcrKey, false);
      return ensured;
    });
  };

  const loginPddAccount = async (account: PddAccountInput): Promise<void> => {
    const name = account.name.trim();
    const loginAccount = account.account.trim();
    const password = account.password;
    const appId = account.appId.trim();
    const loginUrl = pddLoginUrl.trim();

    if (!name || !loginAccount || !password) {
      messageApi.warning("请完整填写名称、账号和密码");
      return;
    }
    if (!appId) {
      messageApi.warning("请先填写应用ID");
      return;
    }
    if (!loginUrl) {
      messageApi.warning("请先填写拼多多登录地址");
      return;
    }

    setPddLoggingInAccountId(account.id);
    try {
      const response = await invoke<PddLoginResponse>("pdd_login_with_browser", {
        request: {
          name,
          account: loginAccount,
          password,
          appId,
          loginUrl,
          cookiePath: account.cookiePath,
          ocrKey: normalizeNullable(pddOcrKey),
        } as PddLoginRequest,
      });
      const ownerMallList =
        Array.isArray(response.ownerMallList) && response.ownerMallList.length > 0
          ? response.ownerMallList
              .map((item) => normalizeStoreItem(item))
              .filter((item): item is PddStoreItem => item !== null)
          : Array.isArray(response.ownerMallNameList)
            ? response.ownerMallNameList
                .map((name) => String(name).trim())
                .filter((name) => name.length > 0)
                .map((accountName) => ({ accountName, code: "" }))
            : [];
      updatePddAccount(account.id, {
        cookiePath: null,
        cookieStatus: "valid",
        cookieReason: response.message,
        storeMallList: ownerMallList,
      });
      const summary =
        response.message ||
        `登录成功，已抓取店铺列表 ${ownerMallList.length} 条`;
      messageApi.success(summary);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      updatePddAccount(account.id, {
        cookieStatus: "invalid",
        cookieReason: detail,
      });
      messageApi.error(`登录失败: ${detail}`);
    } finally {
      setPddLoggingInAccountId(null);
    }
  };

  const copyPddStoreItem = async (store: PddStoreItem): Promise<void> => {
    const accountName = String(store.accountName ?? "").trim();
    const code = String(store.code ?? "").trim();
    if (!accountName && !code) {
      messageApi.warning("当前店铺没有可复制的内容");
      return;
    }
    const payload = `${accountName}\t${code}`;
    try {
      await copyTextToClipboard(payload);
      messageApi.success("已复制店铺名和编号");
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      messageApi.error(`复制失败: ${detail}`);
    }
  };

  const choosePddSyncFile = async (): Promise<void> => {
    try {
      const selected = await open({
        multiple: false,
        directory: false,
        filters: [
          { name: "PHP 文件", extensions: ["php"] },
          { name: "全部文件", extensions: ["*"] },
        ],
      });
      if (!selected || Array.isArray(selected)) {
        return;
      }
      setPddSyncFilePath(selected);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      messageApi.error(`选择文件失败: ${detail}`);
    }
  };

  const triggerPddQuickSync = async (): Promise<void> => {
    const filePath = pddSyncFilePath.trim();
    const receiveIdText = pddSyncReceiveId.trim();
    if (!filePath) {
      messageApi.warning("请先填写文件路径");
      return;
    }
    if (pddSyncTaskId === undefined) {
      messageApi.warning("请先选择类型");
      return;
    }
    if (!/^\d+$/.test(receiveIdText)) {
      messageApi.warning("替换ID必须是纯数字");
      return;
    }
    if (!pddSyncServerAlias) {
      messageApi.warning("请先选择服务器");
      return;
    }

    const receiveId = Number(receiveIdText);
    setPddSyncing(true);
    setPddSyncSummary("正在执行一键同步，请稍候...");
    setPddSyncSteps([]);
    setPddSyncActiveStepKey(null);
    try {
      const response = await invoke<PddQuickSyncResponse>("pdd_quick_sync", {
        request: {
          filePath,
          serverAlias: pddSyncServerAlias,
          taskId: pddSyncTaskId,
          receiveId,
        } as PddQuickSyncRequest,
      });

      const steps = Array.isArray(response.steps)
        ? response.steps
        : Array.isArray(response.remoteSteps)
          ? response.remoteSteps
          : [];
      setPddSyncSteps(steps);
      if (steps.length > 0) {
        const firstFailed = steps.find((step) => step.status === "failed");
        setPddSyncActiveStepKey(buildPddSyncStepKey(firstFailed ?? steps[0]));
      }

      const summary = [
        response.message,
        `文件: ${response.filePath}`,
        `服务器: ${response.serverAlias}`,
        `类型(task): ${response.taskId}`,
        `替换: ${response.oldReceiveId ?? "-"} -> ${response.newReceiveId}`,
        `行号: ${response.replacedLine ?? "-"}`,
        `替换数量: ${response.replacedCount}`,
        `提交: ${response.commitHash || "-"}`,
        `分支: ${response.branch || "-"}`,
        `推送: ${response.pushed ? "已推送" : "未推送"}`,
        `时间: ${response.updatedAt}`,
      ].join("\n");
      setPddSyncSummary(summary);
      if (response.success) {
        messageApi.success("一键同步完成");
      } else {
        messageApi.warning("一键同步存在失败步骤，请查看结果反馈");
      }
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      const failedStep: PddSyncStepResult = {
        key: "invoke",
        step: 1,
        title: "调用后端",
        command: "pdd_quick_sync",
        status: "failed",
        exitCode: null,
        output: detail,
      };
      setPddSyncSummary(`一键同步失败: ${detail}`);
      setPddSyncSteps([failedStep]);
      setPddSyncActiveStepKey(buildPddSyncStepKey(failedStep));
      messageApi.error(`一键同步失败: ${detail}`);
    } finally {
      setPddSyncing(false);
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

  const loadLogFilters = async (showToast = false): Promise<void> => {
    const alias = logServerAlias || logServerOptions[0]?.value;
    if (!alias) {
      if (showToast) {
        messageApi.warning("请先在 SSH 模块配置并显示至少一个可用服务器");
      }
      return;
    }
    setLogServerAlias(alias);
    setLogFiltersLoading(true);
    try {
      const response = await invoke<PlogListFiltersResponse>("plog_list_filters", {
        request: {
          serverAlias: alias,
          baseDir: logBaseDir.trim() || DEFAULT_PLOG_BASE_DIR,
          days: 14,
        } as PlogListFiltersRequest,
      });
      setLogTypeDirOptions(response.typeDirs || []);
      setLogLogFileOptions(response.logFiles || []);
      setLogSelectedTypeDirs((prev) =>
        prev.filter((item) => (response.typeDirs || []).includes(item))
      );
      setLogSelectedLogFiles((prev) =>
        prev.filter((item) => (response.logFiles || []).includes(item))
      );
      if (showToast) {
        messageApi.success(
          `筛选项已更新：目录 ${response.typeDirs.length}，日志名 ${response.logFiles.length}`
        );
      }
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      messageApi.error(`加载日志筛选项失败: ${detail}`);
    } finally {
      setLogFiltersLoading(false);
    }
  };

  const stopLogTailing = (showToast = false): void => {
    if (logTailTimerRef.current !== null) {
      window.clearInterval(logTailTimerRef.current);
      logTailTimerRef.current = null;
    }
    logTailFetchingRef.current = false;
    setLogTailing(false);
    if (showToast) {
      messageApi.info("已停止实时 Tail");
    }
  };

  const resolveLogServerAlias = (showToast = true): string | null => {
    const alias = logServerAlias || logServerOptions[0]?.value;
    if (!alias) {
      if (showToast) {
        messageApi.warning("请先选择服务器");
      }
      return null;
    }
    return alias;
  };

  const normalizeLogLimit = (): number | null => {
    const limitValue = Number(logLimit);
    if (!Number.isFinite(limitValue) || limitValue < 1) {
      messageApi.warning("返回条数必须是大于 0 的数字");
      return null;
    }
    return Math.min(Math.max(Math.floor(limitValue), 1), 1000);
  };

  const collectLogFilterPayload = (): {
    taskTypes?: string[];
    typeDirs?: string[];
    logFiles?: string[];
    level: LogLevelFilter;
    keywords?: string[];
    keyFilters: PlogKeyFilters;
    customFields?: PlogCustomFieldRule[];
  } => {
    const keywords = parseKeywordInput(logKeywords);
    const keyFilters: PlogKeyFilters = {
      orderId: normalizeNullable(logOrderId) || undefined,
      orderNo: normalizeNullable(logOrderNo) || undefined,
      extOrderId: normalizeNullable(logExtOrderId) || undefined,
      mobile: normalizeNullable(logMobile) || undefined,
      channel: normalizeNullable(logChannel) || undefined,
    };
    return {
      taskTypes: logSelectedTaskTypes.length > 0 ? logSelectedTaskTypes : undefined,
      typeDirs: logSelectedTypeDirs.length > 0 ? logSelectedTypeDirs : undefined,
      logFiles: logSelectedLogFiles.length > 0 ? logSelectedLogFiles : undefined,
      level: logLevelFilter,
      keywords: keywords.length > 0 ? keywords : undefined,
      keyFilters,
      customFields: logCustomRules.length > 0 ? logCustomRules : undefined,
    };
  };

  const applyLogTemplate = (template: LogQueryTemplate): void => {
    const payload = template.payload;
    setLogBaseDir(payload.baseDir || DEFAULT_PLOG_BASE_DIR);
    setLogStartAt(payload.startAt || formatDateTimeText(new Date(Date.now() - 2 * 60 * 60 * 1000)));
    setLogEndAt(payload.endAt || formatDateTimeText(new Date()));
    setLogSelectedTaskTypes(payload.selectedTaskTypes || []);
    setLogSelectedTypeDirs(payload.selectedTypeDirs || []);
    setLogSelectedLogFiles(payload.selectedLogFiles || []);
    setLogLevelFilter(payload.level || "all");
    setLogKeywords(payload.keywords || "");
    setLogOrderId(payload.orderId || "");
    setLogOrderNo(payload.orderNo || "");
    setLogExtOrderId(payload.extOrderId || "");
    setLogMobile(payload.mobile || "");
    setLogChannel(payload.channel || "");
    setLogLimit(payload.limit || "200");
    setLogCustomRules(normalizeCustomRules(payload.customRules));
    setLogTemplateName(template.name);
    setLogSummary(`已应用模板：${template.name}`);
    messageApi.success(`已应用模板：${template.name}`);
  };

  const saveCurrentLogTemplate = (): void => {
    const name = logTemplateName.trim();
    if (!name) {
      messageApi.warning("请先填写模板名称");
      return;
    }
    const payload: LogQueryTemplatePayload = {
      baseDir: logBaseDir.trim() || DEFAULT_PLOG_BASE_DIR,
      startAt: logStartAt.trim(),
      endAt: logEndAt.trim(),
      selectedTaskTypes: [...logSelectedTaskTypes],
      selectedTypeDirs: [...logSelectedTypeDirs],
      selectedLogFiles: [...logSelectedLogFiles],
      level: logLevelFilter,
      keywords: logKeywords,
      orderId: logOrderId,
      orderNo: logOrderNo,
      extOrderId: logExtOrderId,
      mobile: logMobile,
      channel: logChannel,
      limit: logLimit,
      customRules: [...logCustomRules],
    };
    const now = new Date().toISOString();
    const existingById = logSelectedTemplateId
      ? logTemplates.find((item) => item.id === logSelectedTemplateId)
      : undefined;
    const existingByName = logTemplates.find((item) => item.name === name);
    const target = existingById || existingByName;
    const nextTemplate: LogQueryTemplate = {
      id: target?.id || uid("log-template"),
      name,
      updatedAt: now,
      payload,
    };
    const merged = target
      ? logTemplates.map((item) => (item.id === target.id ? nextTemplate : item))
      : [nextTemplate, ...logTemplates].slice(0, 30);
    setLogTemplates(merged);
    setLogSelectedTemplateId(nextTemplate.id);
    persistLogQueryTemplates(merged);
    messageApi.success(target ? `模板已更新：${name}` : `模板已保存：${name}`);
  };

  const removeSelectedLogTemplate = (): void => {
    if (!logSelectedTemplateId) {
      messageApi.warning("请先选择要删除的模板");
      return;
    }
    const target = logTemplates.find((item) => item.id === logSelectedTemplateId);
    const next = logTemplates.filter((item) => item.id !== logSelectedTemplateId);
    setLogTemplates(next);
    setLogSelectedTemplateId(undefined);
    persistLogQueryTemplates(next);
    messageApi.success(`模板已删除：${target?.name || logSelectedTemplateId}`);
  };

  const selectLogTemplate = (templateId: string): void => {
    setLogSelectedTemplateId(templateId);
    const template = logTemplates.find((item) => item.id === templateId);
    if (!template) {
      return;
    }
    applyLogTemplate(template);
  };

  const addLogCustomRule = (): void => {
    const name = logCustomNameDraft.trim();
    const keys = parseCustomRuleKeys(logCustomKeysDraft);
    const contains = logCustomContainsDraft.trim();
    if (!name) {
      messageApi.warning("请先填写字段显示名");
      return;
    }
    if (keys.length === 0) {
      messageApi.warning("请先填写至少一个候选 key");
      return;
    }
    if (logCustomRules.some((item) => item.name === name)) {
      messageApi.warning("字段显示名已存在，请更换");
      return;
    }
    const nextRule: PlogCustomFieldRule = {
      name,
      keys,
      contains: contains || undefined,
    };
    setLogCustomRules((prev) => [...prev, nextRule].slice(0, 12));
    setLogCustomNameDraft("");
    setLogCustomKeysDraft("");
    setLogCustomContainsDraft("");
  };

  const removeLogCustomRule = (name: string): void => {
    setLogCustomRules((prev) => prev.filter((item) => item.name !== name));
  };

  const fetchLogTailOnce = async (showLoading = false): Promise<void> => {
    if (logTailFetchingRef.current) {
      return;
    }
    const alias = resolveLogServerAlias(false);
    if (!alias) {
      stopLogTailing(false);
      return;
    }
    const limit = normalizeLogLimit();
    if (!limit) {
      stopLogTailing(false);
      return;
    }
    logTailFetchingRef.current = true;
    if (showLoading) {
      setLogQuerying(true);
    }
    try {
      const filterPayload = collectLogFilterPayload();
      const response = await invoke<PlogTailResponse>("plog_tail_remote", {
        request: {
          serverAlias: alias,
          baseDir: logBaseDir.trim() || DEFAULT_PLOG_BASE_DIR,
          taskTypes: filterPayload.taskTypes,
          typeDirs: filterPayload.typeDirs,
          logFiles: filterPayload.logFiles,
          level: filterPayload.level,
          keywords: filterPayload.keywords,
          keyFilters: filterPayload.keyFilters,
          customFields: filterPayload.customFields,
          limit,
          maxFiles: 8,
          sinceAt: logTailSinceAtRef.current,
        } as PlogTailRequest,
      });
      const seen = logTailSeenKeysRef.current;
      const appended: PlogQueryItem[] = [];
      for (const item of response.items || []) {
        const key = `${item.filePath}:${item.lineNo}:${item.rawLine}`;
        if (seen.has(key)) {
          continue;
        }
        seen.add(key);
        appended.push(item);
      }
      if (appended.length > 0) {
        const sortedTs = appended
          .map((item) => item.ts || "")
          .filter((value) => value.length > 0)
          .sort();
        const newestTs = sortedTs.length > 0 ? sortedTs[sortedTs.length - 1] : undefined;
        if (newestTs) {
          logTailSinceAtRef.current = newestTs;
        }
      }
      setLogRows((prev) => {
        const merged = [...appended, ...prev];
        merged.sort((a, b) => {
          const bTs = b.ts || "";
          const aTs = a.ts || "";
          if (aTs !== bTs) {
            return bTs.localeCompare(aTs);
          }
          return b.lineNo - a.lineNo;
        });
        return merged.slice(0, Math.max(limit, 300));
      });
      setLogStats({
        scannedFiles: response.scannedFiles || 0,
        scannedLines: response.scannedLines || 0,
        matchedLines: response.matchedLines || 0,
        elapsedMs: response.elapsedMs || 0,
        truncated: !!response.truncated,
      });
      setLogSummary(
        [
          `实时 tail 运行中`,
          `服务器: ${alias}`,
          `新增: ${appended.length}`,
          `本轮命中: ${response.matchedLines}`,
          `耗时: ${response.elapsedMs}ms`,
          response.truncated ? "结果已截断，请收窄条件" : "结果完整",
        ].join(" | ")
      );
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      setLogSummary(`实时 tail 失败: ${detail}`);
      stopLogTailing(false);
      messageApi.error(`实时 tail 失败: ${detail}`);
    } finally {
      logTailFetchingRef.current = false;
      if (showLoading) {
        setLogQuerying(false);
      }
    }
  };

  const startLogTailing = async (): Promise<void> => {
    const alias = resolveLogServerAlias();
    if (!alias) {
      return;
    }
    const limit = normalizeLogLimit();
    if (!limit) {
      return;
    }
    if (logTailTimerRef.current !== null) {
      window.clearInterval(logTailTimerRef.current);
      logTailTimerRef.current = null;
    }
    logTailSeenKeysRef.current = new Set();
    logTailSinceAtRef.current = undefined;
    setLogRows([]);
    setLogTailing(true);
    setLogSummary(`实时 tail 已启动（${alias}），首次拉取中...`);
    await fetchLogTailOnce(true);
    const intervalMs = Math.min(Math.max(logTailIntervalSec, 2), 60) * 1000;
    logTailTimerRef.current = window.setInterval(() => {
      void fetchLogTailOnce(false);
    }, intervalMs);
    messageApi.success(`实时 tail 已启动，轮询间隔 ${Math.min(Math.max(logTailIntervalSec, 2), 60)} 秒`);
    setLogRows((prev) => prev.slice(0, Math.max(limit, 300)));
  };

  const triggerLogQuery = async (): Promise<void> => {
    const alias = resolveLogServerAlias();
    if (!alias) {
      return;
    }
    if (logTailing) {
      stopLogTailing(false);
    }
    const startAt = logStartAt.trim();
    const endAt = logEndAt.trim();
    if (!startAt || !endAt) {
      messageApi.warning("请先填写开始时间和结束时间");
      return;
    }
    const limit = normalizeLogLimit();
    if (!limit) {
      return;
    }
    const filterPayload = collectLogFilterPayload();

    setLogQuerying(true);
    setLogSummary("正在远程查询日志，请稍候...");
    try {
      const response = await invoke<PlogQueryResponse>("plog_query_remote", {
        request: {
          serverAlias: alias,
          baseDir: logBaseDir.trim() || DEFAULT_PLOG_BASE_DIR,
          startAt,
          endAt,
          taskTypes: filterPayload.taskTypes,
          typeDirs: filterPayload.typeDirs,
          logFiles: filterPayload.logFiles,
          level: filterPayload.level,
          keywords: filterPayload.keywords,
          keyFilters: filterPayload.keyFilters,
          customFields: filterPayload.customFields,
          limit,
          contextLines: 0,
        } as PlogQueryRequest,
      });
      setLogRows(response.items || []);
      setLogStats({
        scannedFiles: response.scannedFiles || 0,
        scannedLines: response.scannedLines || 0,
        matchedLines: response.matchedLines || 0,
        elapsedMs: response.elapsedMs || 0,
        truncated: !!response.truncated,
      });
      const summary = [
        `服务器: ${alias}`,
        `耗时: ${response.elapsedMs}ms`,
        `扫描文件: ${response.scannedFiles}`,
        `扫描行: ${response.scannedLines}`,
        `命中: ${response.matchedLines}`,
        `返回: ${(response.items || []).length}`,
        response.truncated ? "结果已截断，请收窄条件" : "结果完整",
      ].join(" | ");
      setLogSummary(summary);
      messageApi.success(`日志查询完成，返回 ${(response.items || []).length} 条`);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      setLogSummary(`日志查询失败: ${detail}`);
      messageApi.error(`日志查询失败: ${detail}`);
    } finally {
      setLogQuerying(false);
    }
  };

  const resetLogFilters = (): void => {
    stopLogTailing(false);
    setLogSelectedTaskTypes([]);
    setLogSelectedTypeDirs([]);
    setLogSelectedLogFiles([]);
    setLogLevelFilter("all");
    setLogKeywords("");
    setLogOrderId("");
    setLogOrderNo("");
    setLogExtOrderId("");
    setLogMobile("");
    setLogChannel("");
    setLogCustomRules([]);
    setLogLimit("200");
    setLogSummary("筛选条件已重置。");
    messageApi.success("日志筛选条件已重置");
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
    loadPddConfig(false);
    loadWebsiteEntries(false);
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

  useEffect(() => {
    if (moduleKey !== "pdd" || pddSshBootstrappedRef.current) {
      return;
    }
    pddSshBootstrappedRef.current = true;
    if (sshShortcuts.length === 0) {
      void loadSshShortcuts(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [moduleKey, sshShortcuts.length]);

  useEffect(() => {
    if (moduleKey !== "logs" || logBootstrappedRef.current) {
      return;
    }
    logBootstrappedRef.current = true;
    if (sshShortcuts.length === 0) {
      void loadSshShortcuts(false);
    }
    void loadLogFilters(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [moduleKey, sshShortcuts.length]);

  useEffect(() => {
    setPddSyncServerAlias((prev) => {
      if (!prev) {
        return undefined;
      }
      return pddSyncServerOptions.some((item) => item.value === prev) ? prev : undefined;
    });
  }, [pddSyncServerOptions]);

  useEffect(() => {
    setLogServerAlias((prev) => {
      if (!prev) {
        return logServerOptions[0]?.value;
      }
      return logServerOptions.some((item) => item.value === prev)
        ? prev
        : logServerOptions[0]?.value;
    });
  }, [logServerOptions]);

  useEffect(() => {
    if (moduleKey !== "logs" || !logServerAlias) {
      return;
    }
    void loadLogFilters(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [moduleKey, logServerAlias]);

  useEffect(() => {
    if (moduleKey !== "logs") {
      stopLogTailing(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [moduleKey]);

  useEffect(() => {
    if (logQueryMode !== "tail") {
      stopLogTailing(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [logQueryMode]);

  useEffect(() => {
    return () => {
      if (logTailTimerRef.current !== null) {
        window.clearInterval(logTailTimerRef.current);
      }
    };
  }, []);

  useEffect(() => {
    if (!pddConfigLoadedRef.current) {
      return;
    }
    persistPddConfig(pddAccounts, pddLoginUrl, pddOcrKey, false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pddSyncFilePath, pddSyncTaskId, pddSyncServerAlias]);

  useEffect(() => {
    setPddExpandedAccountIds((prev) =>
      prev.filter((id) => pddAccounts.some((account) => account.id === id))
    );
  }, [pddAccounts]);

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
      width: "18%",
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
      width: "22%",
      render: (_, record) => record.hostName || "-",
    },
    {
      title: "端口",
      dataIndex: "port",
      width: "8%",
      render: (_, record) => record.port || "-",
    },
    {
      title: "用户",
      dataIndex: "user",
      width: "10%",
      render: (_, record) => record.user || "-",
    },
    {
      title: "连接状态",
      key: "connectionStatus",
      width: "14%",
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
      width: "8%",
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

  const pddStoreColumns: ColumnsType<PddStoreItem> = [
    {
      title: "账户名",
      dataIndex: "accountName",
      width: "44%",
      render: (value) => value || "-",
    },
    {
      title: "编号",
      dataIndex: "code",
      width: "36%",
      render: (value) => value || "-",
    },
    {
      title: "操作",
      key: "actions",
      width: "20%",
      render: (_, record) => (
        <Button
          size="small"
          icon={<CopyOutlined />}
          className="pdd-store-copy-btn"
          onClick={() => void copyPddStoreItem(record)}
        >
          复制
        </Button>
      ),
    },
  ];

  const pddColumns: ColumnsType<PddAccountInput> = [
    {
      title: "名称",
      dataIndex: "name",
      width: "18%",
      render: (_, record) => (
        <Input
          value={record.name}
          placeholder="例如 主店账号"
          onChange={(event) => updatePddAccount(record.id, { name: event.target.value })}
        />
      ),
    },
    {
      title: "账号",
      dataIndex: "account",
      width: "22%",
      render: (_, record) => (
        <Input
          value={record.account}
          placeholder="手机号 / 用户名"
          onChange={(event) => updatePddAccount(record.id, { account: event.target.value })}
        />
      ),
    },
    {
      title: "密码",
      dataIndex: "password",
      width: "18%",
      render: (_, record) => (
        <Input.Password
          value={record.password}
          placeholder="密码"
          onChange={(event) => updatePddAccount(record.id, { password: event.target.value })}
        />
      ),
    },
    {
      title: "应用ID",
      dataIndex: "appId",
      width: "14%",
      render: (_, record) => (
        <Input
          value={record.appId}
          placeholder="例如 151203"
          onChange={(event) =>
            updatePddAccount(record.id, {
              appId: event.target.value.replace(/[^\d]/g, ""),
            })
          }
        />
      ),
    },
    {
      title: "店铺数",
      dataIndex: "storeMallList",
      width: "10%",
      render: (_, record) => {
        const count = Array.isArray(record.storeMallList) ? record.storeMallList.length : 0;
        return <Typography.Text type={count > 0 ? undefined : "secondary"}>{count}</Typography.Text>;
      },
    },
    {
      title: "操作",
      key: "actions",
      width: "14%",
      render: (_, record) => (
        <Space size={6} wrap>
          <Button
            size="small"
            type="primary"
            loading={pddLoggingInAccountId === record.id}
            onClick={() => void loginPddAccount(record)}
          >
            登录
          </Button>
          <Tooltip title="删除账号">
            <Button
              size="small"
              shape="circle"
              danger
              className="icon-action-btn"
              icon={<DeleteOutlined />}
              onClick={() => deletePddAccount(record.id)}
            />
          </Tooltip>
        </Space>
      ),
    },
  ];

  const websiteColumns: ColumnsType<WebsiteEntry> = [
    {
      title: "名称",
      dataIndex: "name",
      width: "18%",
      render: (_, record) => (
        <Input
          value={record.name}
          placeholder="例如 阿里云控制台"
          onChange={(event) => updateWebsiteEntry(record.id, { name: event.target.value })}
        />
      ),
    },
    {
      title: "网址",
      dataIndex: "url",
      width: "34%",
      render: (_, record) => (
        <Input
          value={record.url}
          placeholder="https://console.aliyun.com"
          onChange={(event) => updateWebsiteEntry(record.id, { url: event.target.value })}
        />
      ),
    },
    {
      title: "账号",
      dataIndex: "username",
      width: "18%",
      render: (_, record) => (
        <Input
          value={record.username}
          placeholder="登录账号"
          onChange={(event) => updateWebsiteEntry(record.id, { username: event.target.value })}
        />
      ),
    },
    {
      title: "密码",
      dataIndex: "password",
      width: "14%",
      render: (_, record) => (
        <Input.Password
          value={record.password}
          placeholder="密码"
          onChange={(event) => updateWebsiteEntry(record.id, { password: event.target.value })}
        />
      ),
    },
    {
      title: "操作",
      key: "actions",
      width: "16%",
      render: (_, record) => (
        <Space size={6} wrap>
          <Button
            size="small"
            type="primary"
            icon={<LinkOutlined />}
            loading={openingWebsiteId === record.id}
            disabled={!record.url.trim()}
            onClick={() => void openWebsiteUrl(record)}
          >
            一键打开
          </Button>
          <Tooltip title="删除条目">
            <Button
              size="small"
              shape="circle"
              danger
              className="icon-action-btn"
              icon={<DeleteOutlined />}
              onClick={() => deleteWebsiteEntry(record.id)}
            />
          </Tooltip>
        </Space>
      ),
    },
  ];

  const logColumns: ColumnsType<PlogQueryItem> = [
    {
      title: "时间",
      dataIndex: "ts",
      width: "14%",
      render: (_, record) => record.ts || "-",
    },
    {
      title: "级别",
      dataIndex: "level",
      width: "8%",
      render: (_, record) => {
        const level = (record.level || "unknown").toLowerCase();
        if (level === "error") {
          return <Tag color="error">error</Tag>;
        }
        if (level === "info") {
          return <Tag color="success">info</Tag>;
        }
        if (level === "warn") {
          return <Tag color="warning">warn</Tag>;
        }
        return <Tag>{record.level || "unknown"}</Tag>;
      },
    },
    {
      title: "任务类型",
      dataIndex: "taskType",
      width: "12%",
      render: (_, record) => record.taskType || "-",
    },
    {
      title: "目录 / 日志名",
      dataIndex: "typeDir",
      width: "18%",
      render: (_, record) => (
        <Space direction="vertical" size={0}>
          <Typography.Text>{record.typeDir || "-"}</Typography.Text>
          <Typography.Text type="secondary">{record.logFile || "-"}</Typography.Text>
        </Space>
      ),
    },
    {
      title: "关键信息",
      key: "keyFields",
      width: "16%",
      render: (_, record) => (
        <Space direction="vertical" size={0}>
          <Typography.Text type="secondary">
            订单: {record.orderNo || record.orderId || "-"}
          </Typography.Text>
          <Typography.Text type="secondary">
            渠道: {record.channel || "-"}
          </Typography.Text>
          <Typography.Text type="secondary">
            手机: {record.mobile || "-"}
          </Typography.Text>
        </Space>
      ),
    },
    {
      title: "自定义字段",
      dataIndex: "customFields",
      width: "16%",
      render: (_, record) => {
        const entries = Object.entries(record.customFields || {});
        if (entries.length === 0) {
          return "-";
        }
        return (
          <Space direction="vertical" size={0}>
            {entries.slice(0, 2).map(([key, value]) => (
              <Typography.Text key={key} type="secondary">
                {key}: {value}
              </Typography.Text>
            ))}
            {entries.length > 2 ? (
              <Typography.Text type="secondary">+{entries.length - 2} 项</Typography.Text>
            ) : null}
          </Space>
        );
      },
    },
    {
      title: "摘要",
      dataIndex: "message",
      width: "28%",
      ellipsis: true,
      render: (_, record) => record.message || "-",
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

  const pddPage = (
    <div className="workspace-stack">
      <Card className="topbar-card" bordered={false}>
        <div className="topbar-inner">
          <div className="topbar-left">
            <div className="topbar-title-col">
              <Typography.Text strong className="topbar-title">
                拼多多开放平台
              </Typography.Text>
              <Typography.Text className="topbar-desc">账号登录与应用ID管理</Typography.Text>
            </div>
          </div>
          <div className="topbar-right">
            <Space wrap className="topbar-actions pdd-topbar-actions">
              <Segmented
                className="pdd-view-switch"
                value={pddViewMode}
                options={[
                  { label: "账号管理", value: "manage" },
                  { label: "一键同步", value: "sync" },
                ]}
                onChange={(value) => setPddViewMode(value as PddViewMode)}
              />
              {pddViewMode === "manage" ? (
                <Button size="small" icon={<PlusOutlined />} onClick={addPddAccount}>
                  新增账号
                </Button>
              ) : null}
            </Space>
          </div>
        </div>
      </Card>

      {pddViewMode === "sync" ? (
        <Card className="section-card" bordered={false}>
          <Typography.Title level={4} className="section-block-title">
            一键同步
          </Typography.Title>
          <div className="pdd-sync-row">
            <Space.Compact block className="pdd-sync-file-picker">
              <Input
                value={pddSyncFilePath}
                onChange={(event) => setPddSyncFilePath(event.target.value)}
                placeholder="请选择或输入文件路径"
                addonBefore="文件"
              />
              <Button onClick={() => void choosePddSyncFile()}>选择文件</Button>
            </Space.Compact>
            <Select
              value={pddSyncTaskId}
              options={PDD_SYNC_TASK_OPTIONS}
              onChange={(value) => setPddSyncTaskId(value)}
              allowClear
              placeholder="选择类型（按 task id 匹配）"
              className="pdd-sync-type-select"
            />
            <Input
              value={pddSyncReceiveId}
              onChange={(event) => setPddSyncReceiveId(event.target.value.replace(/[^\d]/g, ""))}
              placeholder="输入要替换的新ID"
              addonBefore="替换ID"
            />
            <Select
              value={pddSyncServerAlias}
              options={pddSyncServerOptions}
              onChange={(value) => setPddSyncServerAlias(value)}
              allowClear
              showSearch
              optionFilterProp="label"
              placeholder="选择服务器（仅显示未隐藏快捷连接）"
              className="pdd-sync-server-select"
              notFoundContent="暂无可用服务器，请先到快捷连接中设置为显示"
            />
            <Button
              type="primary"
              className="pdd-sync-action-btn"
              loading={pddSyncing}
              onClick={() => void triggerPddQuickSync()}
            >
              一键同步
            </Button>
          </div>
          <div className="pdd-sync-feedback-block">
            <Typography.Text strong className="pdd-sync-feedback-title">
              结果反馈
            </Typography.Text>
            <div className="pdd-sync-step-tag-row">
              {pddSyncSteps.length > 0 ? (
                pddSyncSteps.map((step) => {
                  const stepKey = buildPddSyncStepKey(step);
                  return (
                    <Tag
                      key={stepKey}
                      className={[
                        "pdd-sync-step-tag",
                        `is-${step.status || "unknown"}`,
                        pddSyncActiveStepKey === stepKey ? "active" : "",
                      ]
                        .filter(Boolean)
                        .join(" ")}
                      onClick={() => setPddSyncActiveStepKey(stepKey)}
                    >
                      {`Step ${step.step} ${step.title} · ${pddSyncStatusLabel(step.status)}`}
                    </Tag>
                  );
                })
              ) : (
                <Tag className="pdd-sync-step-tag is-idle">等待执行</Tag>
              )}
            </div>
            <Input.TextArea
              value={pddSyncDetailText}
              readOnly
              autoSize={{ minRows: 10, maxRows: 18 }}
              className="pdd-sync-feedback-textarea"
              placeholder="每一步的执行结果会显示在这里"
            />
          </div>
        </Card>
      ) : (
        <>
          <div className="stat-row">
            <div className="stat-card stat-card-ip">账号 {pddAccounts.length}</div>
            <div className="stat-card stat-card-account">已填应用ID {pddFilledAppIdCount}</div>
            <div className="stat-card stat-card-rule">店铺 {pddTotalStoreCount}（未填ID {pddMissingAppIdCount}）</div>
          </div>

          <Card className="section-card" bordered={false}>
            <Collapse
              className="pdd-login-collapse"
              ghost
              defaultActiveKey={[]}
              expandIconPosition="end"
              items={[
                {
                  key: "pdd-login-settings",
                  label: "登录设置",
                  children: (
                    <div className="pdd-login-collapse-body">
                      <Typography.Paragraph type="secondary" className="section-help">
                        按完整链路执行：自动登录、自动滑块（失败可人工），成功后直接进入授权管理详情页并抓取 page 请求数据。
                      </Typography.Paragraph>
                      <Input
                        className="run-inline-input"
                        value={pddLoginUrl}
                        onChange={(event) => setPddLoginUrl(event.target.value)}
                        placeholder="拼多多登录地址，例如 https://open.pinduoduo.com/application/home"
                        addonBefore="登录地址"
                      />
                      <Input.Password
                        className="run-inline-input"
                        value={pddOcrKey}
                        onChange={(event) => setPddOcrKey(event.target.value)}
                        placeholder="滑块解密 K（留空则仅人工滑块）"
                        addonBefore="解密 K"
                      />
                    </div>
                  ),
                },
              ]}
            />
          </Card>

          <Card className="section-card" bordered={false}>
            <Typography.Title level={4} className="section-block-title">
              账号列表
            </Typography.Title>
            <Table<PddAccountInput>
              className="modern-table pdd-account-table"
              rowKey="id"
              columns={pddColumns}
              dataSource={pddAccounts}
              expandable={{
                columnWidth: 110,
                expandedRowKeys: pddExpandedAccountIds,
                onExpandedRowsChange: (keys) =>
                  setPddExpandedAccountIds(keys.map((key) => String(key))),
                rowExpandable: (record) =>
                  Array.isArray(record.storeMallList) && record.storeMallList.length > 0,
                expandIcon: ({ expanded, onExpand, record, expandable }) =>
                  expandable ? (
                    <Button
                      size="small"
                      className="pdd-expand-trigger"
                      icon={expanded ? <DownOutlined /> : <RightOutlined />}
                      onClick={(event) => onExpand(record, event)}
                    >
                      {expanded ? "收起" : "展开"}
                    </Button>
                  ) : (
                    <span className="pdd-expand-placeholder">-</span>
                  ),
                expandedRowRender: (record) => (
                  <Table<PddStoreItem>
                    className="pdd-store-table"
                    size="small"
                    rowKey={(row, index) => `${record.id}-${row.accountName}-${row.code}-${index}`}
                    columns={pddStoreColumns}
                    dataSource={record.storeMallList}
                    pagination={false}
                    tableLayout="fixed"
                    locale={{ emptyText: "暂无店铺数据" }}
                  />
                ),
              }}
              size="small"
              pagination={{ pageSize: 6, showSizeChanger: false }}
              tableLayout="fixed"
              locale={{ emptyText: "暂无账号，请点击“新增账号”" }}
            />
          </Card>

          <Card className="section-card" bordered={false}>
            <Typography.Title level={4} className="section-block-title">
              店铺列表说明
            </Typography.Title>
            <Typography.Paragraph type="secondary" className="section-help">
              点击账号行的“登录”后，程序会自动进入对应应用详情页并监听
              https://open-api.pinduoduo.com/pop/application/white/owner/page，
              返回中的 ownerMallList（兼容 ownerMallNameList）会解析为“账户名 + 编号”，并保存到该账号的店铺子列表。
            </Typography.Paragraph>
          </Card>
        </>
      )}
    </div>
  );

  const logsPage = (
    <div className="workspace-stack">
      <Card className="topbar-card" bordered={false}>
        <div className="topbar-inner">
          <div className="topbar-left">
            <div className="topbar-title-col">
              <Typography.Text strong className="topbar-title">
                SP工具箱
              </Typography.Text>
              <Typography.Text className="topbar-desc">日志中心（远程 plog 查询）</Typography.Text>
            </div>
          </div>
          <div className="topbar-right">
            <Space wrap className="topbar-actions">
              <Segmented<LogQueryMode>
                value={logQueryMode}
                onChange={(value) => setLogQueryMode(value as LogQueryMode)}
                options={[
                  { label: "普通查询", value: "query" },
                  { label: "实时 Tail", value: "tail" },
                ]}
              />
              <Select
                value={logServerAlias}
                options={logServerOptions}
                onChange={(value) => setLogServerAlias(value)}
                showSearch
                allowClear
                optionFilterProp="label"
                placeholder="选择服务器"
                className="pdd-sync-server-select"
                notFoundContent="暂无可用服务器，请先在 SSH 模块确认连接配置"
              />
              <Button
                size="small"
                className="topbar-btn topbar-btn-ssh-refresh"
                icon={<ReloadOutlined />}
                loading={logFiltersLoading}
                onClick={() => void loadLogFilters(true)}
              >
                刷新筛选项
              </Button>
              <Button
                size="small"
                className="topbar-btn topbar-btn-ssh-test"
                type="primary"
                icon={<CloudSyncOutlined />}
                loading={logQuerying}
                onClick={() => {
                  if (logQueryMode === "tail") {
                    if (logTailing) {
                      stopLogTailing(true);
                    } else {
                      void startLogTailing();
                    }
                    return;
                  }
                  void triggerLogQuery();
                }}
              >
                {logQueryMode === "tail" ? (logTailing ? "停止 Tail" : "启动 Tail") : "执行查询"}
              </Button>
              <Button size="small" onClick={resetLogFilters}>
                重置筛选
              </Button>
            </Space>
          </div>
        </div>
      </Card>

      <Card className="section-card" bordered={false}>
        <Typography.Title level={4} className="section-block-title">
          查询条件
        </Typography.Title>
        <Typography.Paragraph type="secondary" className="section-help">
          时间格式：YYYY-MM-DD HH:mm:ss。关键词可输入多个（空格、逗号分隔）。实时 Tail 会持续轮询最近日志并增量追加。
        </Typography.Paragraph>
        <div className="log-template-row">
          <Select
            value={logSelectedTemplateId}
            options={logTemplateOptions}
            onChange={(value) => {
              if (value) {
                selectLogTemplate(value);
              } else {
                setLogSelectedTemplateId(undefined);
              }
            }}
            allowClear
            placeholder="选择查询模板"
            onClear={() => setLogSelectedTemplateId(undefined)}
          />
          <Input
            value={logTemplateName}
            onChange={(event) => setLogTemplateName(event.target.value)}
            placeholder="模板名称，例如：回调异常追踪"
          />
          <Button size="small" onClick={saveCurrentLogTemplate}>
            保存模板
          </Button>
          <Button size="small" danger disabled={!logSelectedTemplateId} onClick={removeSelectedLogTemplate}>
            删除模板
          </Button>
          {logQueryMode === "tail" ? (
            <Select<number>
              value={logTailIntervalSec}
              onChange={(value) => setLogTailIntervalSec(value)}
              options={[
                { label: "2 秒轮询", value: 2 },
                { label: "5 秒轮询", value: 5 },
                { label: "10 秒轮询", value: 10 },
                { label: "15 秒轮询", value: 15 },
              ]}
              placeholder="轮询间隔"
            />
          ) : null}
        </div>
        <div className="log-filter-grid">
          <Input
            value={logBaseDir}
            onChange={(event) => setLogBaseDir(event.target.value)}
            addonBefore="日志根目录"
            placeholder="~/junziyun-v7/storage/logs/custom"
          />
          <Input
            value={logStartAt}
            onChange={(event) => setLogStartAt(event.target.value)}
            addonBefore="开始时间"
            placeholder="2026-03-23 00:00:00"
          />
          <Input
            value={logEndAt}
            onChange={(event) => setLogEndAt(event.target.value)}
            addonBefore="结束时间"
            placeholder="2026-03-23 23:59:59"
            disabled={logQueryMode === "tail"}
          />
          <Select<LogLevelFilter>
            value={logLevelFilter}
            onChange={(value) => setLogLevelFilter(value)}
            options={[
              { label: "全部级别", value: "all" },
              { label: "info", value: "info" },
              { label: "error", value: "error" },
              { label: "warn", value: "warn" },
              { label: "unknown", value: "unknown" },
            ]}
            placeholder="日志级别"
          />
          <Input
            value={logLimit}
            onChange={(event) =>
              setLogLimit(event.target.value.replace(/[^\d]/g, "").slice(0, 4))
            }
            addonBefore="返回条数"
            placeholder="200"
          />
          <Input
            value={logKeywords}
            onChange={(event) => setLogKeywords(event.target.value)}
            addonBefore="关键词"
            placeholder="例如 error timeout callback"
          />
          <Select
            mode="multiple"
            allowClear
            value={logSelectedTaskTypes}
            onChange={(value) => setLogSelectedTaskTypes(value)}
            options={logTaskOptions}
            placeholder="任务类型"
          />
          <Select
            mode="multiple"
            allowClear
            value={logSelectedTypeDirs}
            onChange={(value) => setLogSelectedTypeDirs(value)}
            options={logTypeDirOptions.map((item) => ({ label: item, value: item }))}
            placeholder="typeDir（目录）"
          />
          <Select
            mode="multiple"
            allowClear
            value={logSelectedLogFiles}
            onChange={(value) => setLogSelectedLogFiles(value)}
            options={logLogFileOptions.map((item) => ({ label: item, value: item }))}
            placeholder="logFileName（日志名）"
          />
          <Input
            value={logOrderId}
            onChange={(event) => setLogOrderId(event.target.value)}
            addonBefore="orderId"
            placeholder="支持模糊匹配"
          />
          <Input
            value={logOrderNo}
            onChange={(event) => setLogOrderNo(event.target.value)}
            addonBefore="orderNo"
            placeholder="支持模糊匹配"
          />
          <Input
            value={logExtOrderId}
            onChange={(event) => setLogExtOrderId(event.target.value)}
            addonBefore="extOrderId"
            placeholder="支持模糊匹配"
          />
          <Input
            value={logMobile}
            onChange={(event) => setLogMobile(event.target.value)}
            addonBefore="mobile"
            placeholder="支持模糊匹配"
          />
          <Input
            value={logChannel}
            onChange={(event) => setLogChannel(event.target.value)}
            addonBefore="channel"
            placeholder="支持模糊匹配"
          />
        </div>
        <div className="log-custom-rule-panel">
          <Typography.Text strong>自定义字段规则</Typography.Text>
          <div className="log-custom-rule-row">
            <Input
              value={logCustomNameDraft}
              onChange={(event) => setLogCustomNameDraft(event.target.value)}
              placeholder="字段显示名（例：taskId）"
            />
            <Input
              value={logCustomKeysDraft}
              onChange={(event) => setLogCustomKeysDraft(event.target.value)}
              placeholder="候选 key，逗号分隔（例：task_id,taskId,$task_id）"
            />
            <Input
              value={logCustomContainsDraft}
              onChange={(event) => setLogCustomContainsDraft(event.target.value)}
              placeholder="匹配值（可选，填了就按包含过滤）"
            />
            <Button size="small" onClick={addLogCustomRule}>
              添加规则
            </Button>
          </div>
          <div className="log-custom-rule-tags">
            {logCustomRules.length > 0 ? (
              logCustomRules.map((rule) => (
                <Tag key={rule.name} closable onClose={() => removeLogCustomRule(rule.name)}>
                  {`${rule.name} = [${rule.keys.join(", ")}]${rule.contains ? ` contains "${rule.contains}"` : ""}`}
                </Tag>
              ))
            ) : (
              <Typography.Text type="secondary">暂无规则，查询时仅展示系统字段</Typography.Text>
            )}
          </div>
        </div>
      </Card>

      <div className="stat-row">
        <div className="stat-card stat-card-ip">扫描文件 {logStats.scannedFiles}</div>
        <div className="stat-card stat-card-account">扫描行数 {logStats.scannedLines}</div>
        <div className="stat-card stat-card-rule">命中 {logStats.matchedLines}</div>
        <div className="stat-card stat-card-rule">耗时 {logStats.elapsedMs}ms</div>
      </div>

      <Card className="section-card" bordered={false}>
        <Typography.Title level={4} className="section-block-title">
          {logQueryMode === "tail" ? "实时 Tail 反馈" : "查询反馈"}
        </Typography.Title>
        <Input.TextArea
          value={logSummary}
          readOnly
          autoSize={{ minRows: 2, maxRows: 4 }}
          className="pdd-sync-feedback-textarea"
        />
        {logStats.truncated ? (
          <Typography.Paragraph type="secondary" className="section-help">
            当前结果已截断，建议缩小时间范围或增加筛选条件。
          </Typography.Paragraph>
        ) : null}
        <Table<PlogQueryItem>
          className="modern-table"
          rowKey={(record) => `${record.filePath}:${record.lineNo}:${record.ts || ""}`}
          columns={logColumns}
          dataSource={logRows}
          size="small"
          loading={logQuerying}
          pagination={{ pageSize: 10, showSizeChanger: false }}
          tableLayout="fixed"
          locale={{ emptyText: "暂无查询结果" }}
          expandable={{
            expandedRowRender: (record) => (
              <div className="result-detail-grid">
                <div className="detail-item">
                  <span>时间</span>
                  <b>{record.ts || "-"}</b>
                </div>
                <div className="detail-item">
                  <span>文件路径</span>
                  <b>{record.filePath}</b>
                </div>
                <div className="detail-item">
                  <span>行号</span>
                  <b>{record.lineNo}</b>
                </div>
                <div className="detail-item">
                  <span>原始日志</span>
                  <b className="log-raw-line">{record.rawLine}</b>
                </div>
                <div className="detail-item">
                  <span>自定义字段</span>
                  <b className="log-raw-line">
                    {Object.entries(record.customFields || {})
                      .map(([key, value]) => `${key}: ${value}`)
                      .join("\n") || "-"}
                  </b>
                </div>
                <div className="detail-item">
                  <span>操作</span>
                  <Space>
                    <Button
                      size="small"
                      icon={<CopyOutlined />}
                      onClick={() => void copyTextToClipboard(record.rawLine)}
                    >
                      复制原始日志
                    </Button>
                  </Space>
                </div>
              </div>
            ),
          }}
        />
      </Card>
    </div>
  );

  const websitePage = (
    <div className="workspace-stack">
      <Card className="topbar-card" bordered={false}>
        <div className="topbar-inner">
          <div className="topbar-left">
            <div className="topbar-title-col">
              <Typography.Text strong className="topbar-title">
                SP工具箱
              </Typography.Text>
              <Typography.Text className="topbar-desc">网址信息管理</Typography.Text>
            </div>
          </div>
          <div className="topbar-right">
            <Space wrap className="topbar-actions">
              <Button
                size="small"
                className="topbar-btn topbar-btn-local-service"
                icon={<CloudSyncOutlined />}
                loading={startingLocalServices}
                onClick={startLocalDevServices}
              >
                启动本地服务
              </Button>
              <Button
                size="small"
                className="topbar-btn topbar-btn-account"
                icon={<PlusOutlined />}
                onClick={addWebsiteEntry}
              >
                新增条目
              </Button>
            </Space>
          </div>
        </div>
      </Card>

      <div className="stat-row">
        <div className="stat-card stat-card-ip">网址条目 {websiteEntries.length}</div>
        <div className="stat-card stat-card-account">已填写网址 {websiteConfiguredCount}</div>
        <div className="stat-card stat-card-rule">可一键打开 {websiteConfiguredCount}</div>
      </div>

      <Card className="section-card" bordered={false}>
        <Typography.Title level={4} className="section-block-title">
          常用网址与账号密码
        </Typography.Title>
        <Typography.Paragraph type="secondary" className="section-help">
          在表格中填写名称、网址、账号和密码。点击“一键打开”会在默认浏览器打开该网址。
        </Typography.Paragraph>
        <Table<WebsiteEntry>
          className="modern-table"
          rowKey="id"
          columns={websiteColumns}
          dataSource={websiteEntries}
          size="small"
          pagination={{ pageSize: 8, showSizeChanger: false }}
          tableLayout="fixed"
          locale={{ emptyText: "暂无网址条目，请点击“新增条目”" }}
        />
      </Card>
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
                    <Tooltip title="拼多多开放平台">
                      <button
                        type="button"
                        className="left-rail-switch-btn"
                        onClick={() => setModuleKey("pdd")}
                        aria-label="切换到拼多多开放平台"
                      >
                        <ShopOutlined className={`left-rail-item ${moduleKey === "pdd" ? "active" : ""}`} />
                      </button>
                    </Tooltip>
                    <Tooltip title="日志中心">
                      <button
                        type="button"
                        className="left-rail-switch-btn"
                        onClick={() => setModuleKey("logs")}
                        aria-label="切换到日志中心"
                      >
                        <FileSearchOutlined
                          className={`left-rail-item ${moduleKey === "logs" ? "active" : ""}`}
                        />
                      </button>
                    </Tooltip>
                    <Tooltip title="网址信息管理">
                      <button
                        type="button"
                        className="left-rail-switch-btn"
                        onClick={() => setModuleKey("website")}
                        aria-label="切换到网址信息管理"
                      >
                        <GlobalOutlined
                          className={`left-rail-item ${moduleKey === "website" ? "active" : ""}`}
                        />
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
                {moduleKey === "aliyun"
                  ? aliyunPage
                  : moduleKey === "ssh"
                    ? sshPage
                    : moduleKey === "pdd"
                      ? pddPage
                      : moduleKey === "logs"
                        ? logsPage
                        : websitePage}
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
