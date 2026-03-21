use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::fs;
use std::io::Write;
use std::net::Ipv4Addr;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HOST};
use reqwest::Method;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

const ECS_VERSION: &str = "2014-05-26";
const STS_VERSION: &str = "2015-04-01";
const STS_HOST: &str = "sts.aliyuncs.com";
const PDD_DEFAULT_LOGIN_URL: &str = "https://open.pinduoduo.com/application/home";
const PDD_COOKIE_TEST_URL: &str = "https://mms.pinduoduo.com/";
const PDD_AUTH_MANAGE_DETAIL_BASE_URL: &str =
    "https://open.pinduoduo.com/application/app/detail/jbxx/sqgl";
const PDD_OWNER_PAGE_API_URL: &str = "https://open-api.pinduoduo.com/pop/application/white/owner/page";
const PDD_LOGIN_TIMEOUT_MS: u64 = 480_000;
const PDD_PAGE_CAPTURE_TIMEOUT_MS: u64 = 35_000;
const PDD_DEFAULT_VERIFY_IDF_ID: &str = "50";
const PDD_DEFAULT_OCR_URL: &str = "http://220.167.181.200:9009/openapi/verify_code_identify/";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountInput {
    id: String,
    name: Option<String>,
    access_key_id: String,
    access_key_secret: String,
    security_token: Option<String>,
    default_region_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TargetInput {
    id: String,
    name: Option<String>,
    account_id: String,
    security_group_id: String,
    region_id: Option<String>,
    rule_id: Option<String>,
    ip_protocol: Option<String>,
    port_range: Option<String>,
    policy: Option<String>,
    description: Option<String>,
    priority: Option<String>,
    auto_create: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SyncRequest {
    accounts: Vec<AccountInput>,
    targets: Vec<TargetInput>,
    ip_override: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicIpResponse {
    ip: String,
    cidr: String,
    carrier: Option<String>,
    location: Option<String>,
    isp: Option<String>,
    org: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountIdentityResponse {
    account_id: Option<String>,
    user_id: Option<String>,
    arn: Option<String>,
    principal_id: Option<String>,
    request_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SyncResponse {
    public_ip: String,
    cidr: String,
    results: Vec<TargetSyncResult>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TargetSyncResult {
    target_id: String,
    target_name: Option<String>,
    account_id: String,
    account_name: Option<String>,
    security_group_id: String,
    region_id: Option<String>,
    rule_id: Option<String>,
    action: String,
    success: bool,
    request_id: Option<String>,
    code: Option<String>,
    message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SshShortcutRow {
    alias: String,
    host_name: Option<String>,
    port: Option<String>,
    user: Option<String>,
    identity_file: Option<String>,
    proxy_jump: Option<String>,
    source_file: Option<String>,
    source_line: Option<usize>,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SshConnectionTestResult {
    alias: String,
    status: String,
    exit_code: Option<i32>,
    output: String,
    checked_at: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PddLoginRequest {
    name: String,
    account: String,
    password: String,
    login_url: String,
    app_id: String,
    cookie_path: Option<String>,
    ocr_key: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PddOwnerMallItem {
    account_name: String,
    code: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PddLoginResponse {
    cookie_path: String,
    cookie_count: usize,
    saved_at: String,
    message: String,
    login_url: String,
    account: String,
    owner_mall_list: Vec<PddOwnerMallItem>,
    capture_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PddCookieValidateRequest {
    cookie_path: String,
    test_url: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PddCookieStatusResponse {
    valid: bool,
    reason: String,
    cookie_path: String,
    cookie_count: usize,
    checked_at: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PddFetchRequest {
    api_url: String,
    cookie_path: String,
    output_path: String,
    dry_run: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PddFetchResponse {
    success: bool,
    status: u16,
    saved_path: Option<String>,
    message: String,
    fetched_at: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PddQuickSyncRequest {
    file_path: String,
    server_alias: String,
    task_id: i32,
    receive_id: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PddQuickSyncResponse {
    success: bool,
    message: String,
    file_path: String,
    server_alias: String,
    task_id: i32,
    old_receive_id: Option<i64>,
    new_receive_id: i64,
    replaced_line: Option<usize>,
    replaced_count: usize,
    commit_hash: Option<String>,
    branch: Option<String>,
    pushed: bool,
    steps: Vec<PddSyncStepResult>,
    remote_steps: Vec<PddSyncStepResult>,
    updated_at: String,
}

#[derive(Debug, Clone)]
struct SyncReceiveCallEntry {
    receive_id: i64,
    start: usize,
    end: usize,
    line_number: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PddSyncStepResult {
    key: String,
    step: usize,
    title: String,
    command: String,
    status: String,
    exit_code: Option<i32>,
    output: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserCookie {
    name: String,
    value: String,
    domain: String,
    path: String,
    #[serde(default)]
    expires: f64,
    #[serde(default)]
    http_only: bool,
    #[serde(default)]
    secure: bool,
    #[serde(default)]
    same_site: Option<String>,
}

#[derive(Debug, Clone)]
struct PddWebDriverConfig {
    webdriver_base_url: String,
    session_id: String,
}

#[derive(Debug, Clone)]
struct WdElementRect {
    width: f64,
}

#[derive(Debug, Clone)]
struct WdClient {
    client: reqwest::blocking::Client,
    base_url: String,
    session_id: String,
}

#[derive(Debug, Clone)]
struct SshAliasSource {
    source_file: String,
    source_line: usize,
}

#[derive(Debug, Clone)]
struct SecurityRule {
    rule_id: Option<String>,
    source_cidr_ip: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppWorldsIpData {
    ip: Option<String>,
    country: Option<String>,
    province: Option<String>,
    region: Option<String>,
    city: Option<String>,
    #[serde(rename = "fullAddress")]
    full_address: Option<String>,
    other: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AppWorldsIpResponse {
    code: Option<i64>,
    data: Option<AppWorldsIpData>,
    msg: Option<String>,
}

#[derive(Debug)]
struct ApiError {
    code: String,
    message: String,
    request_id: Option<String>,
}

impl ApiError {
    fn new(
        code: impl Into<String>,
        message: impl Into<String>,
        request_id: Option<String>,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            request_id,
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(request_id) = &self.request_id {
            write!(
                f,
                "{}: {} (RequestId: {})",
                self.code, self.message, request_id
            )
        } else {
            write!(f, "{}: {}", self.code, self.message)
        }
    }
}

impl std::error::Error for ApiError {}

#[derive(Clone)]
struct AlibabaOpenApiClient {
    http: reqwest::Client,
}

impl AlibabaOpenApiClient {
    fn new() -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .user_agent("tauri-aliyun-ip-whitelist/0.1.0")
            .build()
            .map_err(|err| format!("初始化 HTTP 客户端失败: {err}"))?;
        Ok(Self { http })
    }

    async fn call_rpc_json(
        &self,
        host: &str,
        action: &str,
        version: &str,
        credential: &AccountInput,
        params: &BTreeMap<String, String>,
    ) -> Result<Value, ApiError> {
        let endpoint = format!("https://{host}/");
        let body = form_url_encode(params);
        let payload_hash = sha256_hex(body.as_bytes());
        let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let nonce = Uuid::new_v4().to_string();

        let mut signed_headers: BTreeMap<String, String> = BTreeMap::new();
        signed_headers.insert(
            "content-type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        );
        signed_headers.insert("host".to_string(), host.to_string());
        signed_headers.insert("x-acs-action".to_string(), action.to_string());
        signed_headers.insert("x-acs-content-sha256".to_string(), payload_hash.clone());
        signed_headers.insert("x-acs-date".to_string(), timestamp.clone());
        signed_headers.insert("x-acs-signature-nonce".to_string(), nonce.clone());
        signed_headers.insert("x-acs-version".to_string(), version.to_string());

        if let Some(token) = trim_to_option(&credential.security_token) {
            signed_headers.insert("x-acs-security-token".to_string(), token.to_string());
        }

        let signed_header_names = signed_headers.keys().cloned().collect::<Vec<_>>().join(";");
        let canonical_headers = signed_headers
            .iter()
            .map(|(key, value)| format!("{}:{}", key, canonicalize_header_value(value)))
            .collect::<Vec<_>>()
            .join("\n");

        let canonical_request = format!(
            "POST\n/\n\n{}\n\n{}\n{}",
            canonical_headers, signed_header_names, payload_hash
        );
        let string_to_sign = format!(
            "ACS3-HMAC-SHA256\n{}",
            sha256_hex(canonical_request.as_bytes())
        );
        let signature = hmac_sha256_hex(&credential.access_key_secret, &string_to_sign)?;

        let authorization = format!(
            "ACS3-HMAC-SHA256 Credential={},SignedHeaders={},Signature={}",
            credential.access_key_id, signed_header_names, signature
        );

        let mut request = self
            .http
            .post(endpoint)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(HOST, host)
            .header("x-acs-action", action)
            .header("x-acs-content-sha256", payload_hash)
            .header("x-acs-date", timestamp)
            .header("x-acs-signature-nonce", nonce)
            .header("x-acs-version", version)
            .header(AUTHORIZATION, authorization)
            .body(body);

        if let Some(token) = trim_to_option(&credential.security_token) {
            request = request.header("x-acs-security-token", token);
        }

        let response = request.send().await.map_err(|err| {
            ApiError::new(
                "HttpRequestError",
                format!("调用 {} 失败: {}", action, err),
                None,
            )
        })?;

        let status = response.status();
        let response_text = response.text().await.map_err(|err| {
            ApiError::new(
                "HttpReadError",
                format!("读取 {} 响应失败: {}", action, err),
                None,
            )
        })?;

        let parsed_json: Value = serde_json::from_str(&response_text).map_err(|err| {
            ApiError::new(
                "InvalidJson",
                format!("{} 返回了无法解析的 JSON: {}", action, err),
                None,
            )
        })?;

        if !status.is_success() {
            let code = parsed_json
                .get("Code")
                .and_then(Value::as_str)
                .unwrap_or("HttpError")
                .to_string();
            let message = parsed_json
                .get("Message")
                .and_then(Value::as_str)
                .unwrap_or("请求失败")
                .to_string();
            let request_id = parsed_json
                .get("RequestId")
                .and_then(Value::as_str)
                .map(ToString::to_string);
            return Err(ApiError::new(code, message, request_id));
        }

        if parsed_json.get("Code").is_some() && parsed_json.get("Message").is_some() {
            let code = parsed_json
                .get("Code")
                .and_then(Value::as_str)
                .unwrap_or("ApiError")
                .to_string();
            let message = parsed_json
                .get("Message")
                .and_then(Value::as_str)
                .unwrap_or("请求失败")
                .to_string();
            let request_id = parsed_json
                .get("RequestId")
                .and_then(Value::as_str)
                .map(ToString::to_string);
            return Err(ApiError::new(code, message, request_id));
        }

        Ok(parsed_json)
    }
}

#[tauri::command]
async fn detect_public_ip() -> Result<PublicIpResponse, String> {
    let client = AlibabaOpenApiClient::new()?;
    if let Ok(response) = lookup_current_public_ip_profile(&client.http).await {
        return Ok(response);
    }

    let ip = detect_public_ipv4(&client.http)
        .await
        .map_err(|err| err.to_string())?;
    let metadata = lookup_ip_metadata(&client.http, &ip).await.ok();
    Ok(PublicIpResponse {
        cidr: format!("{ip}/32"),
        ip,
        carrier: metadata.as_ref().and_then(|item| item.carrier.clone()),
        location: metadata.as_ref().and_then(|item| item.location.clone()),
        isp: metadata.as_ref().and_then(|item| item.isp.clone()),
        org: metadata.as_ref().and_then(|item| item.org.clone()),
    })
}

#[tauri::command]
async fn verify_account(account: AccountInput) -> Result<AccountIdentityResponse, String> {
    let client = AlibabaOpenApiClient::new()?;
    let identity = get_caller_identity(&client, &account)
        .await
        .map_err(|err| err.to_string())?;

    Ok(AccountIdentityResponse {
        account_id: identity
            .get("AccountId")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        user_id: identity
            .get("UserId")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        arn: identity
            .get("Arn")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        principal_id: identity
            .get("PrincipalId")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        request_id: identity
            .get("RequestId")
            .and_then(Value::as_str)
            .map(ToString::to_string),
    })
}

#[tauri::command]
async fn sync_all(request: SyncRequest) -> Result<SyncResponse, String> {
    if request.accounts.is_empty() {
        return Err("至少需要 1 个账号".to_string());
    }
    if request.targets.is_empty() {
        return Err("至少需要 1 个目标规则".to_string());
    }

    let client = AlibabaOpenApiClient::new()?;
    let account_map: HashMap<String, AccountInput> = request
        .accounts
        .iter()
        .cloned()
        .map(|account| (account.id.clone(), account))
        .collect();

    let (ip, cidr) = if let Some(ip_override) = trim_to_option(&request.ip_override) {
        normalize_ipv4_or_cidr(ip_override).map_err(|err| format!("ipOverride 无效: {err}"))?
    } else {
        let ip = detect_public_ipv4(&client.http)
            .await
            .map_err(|err| err.to_string())?;
        (ip.clone(), format!("{ip}/32"))
    };

    let mut results = Vec::with_capacity(request.targets.len());
    for target in request.targets {
        let Some(account) = account_map.get(&target.account_id) else {
            results.push(TargetSyncResult {
                target_id: target.id,
                target_name: target.name,
                account_id: target.account_id,
                account_name: None,
                security_group_id: target.security_group_id,
                region_id: target.region_id,
                rule_id: target.rule_id,
                action: "failed".to_string(),
                success: false,
                request_id: None,
                code: Some("AccountNotFound".to_string()),
                message: "找不到对应账号，请检查 accountId".to_string(),
            });
            continue;
        };

        let mut account_name = account.name.clone();
        if account_name.is_none() {
            account_name = Some(account.id.clone());
        }

        match sync_single_target(&client, account, &target, &cidr).await {
            Ok(mut result) => {
                result.account_name = account_name;
                results.push(result);
            }
            Err(err) => {
                results.push(TargetSyncResult {
                    target_id: target.id,
                    target_name: target.name,
                    account_id: account.id.clone(),
                    account_name,
                    security_group_id: target.security_group_id,
                    region_id: target.region_id.clone(),
                    rule_id: target.rule_id.clone(),
                    action: "failed".to_string(),
                    success: false,
                    request_id: err.request_id,
                    code: Some(err.code),
                    message: err.message,
                });
            }
        }
    }

    Ok(SyncResponse {
        public_ip: ip,
        cidr,
        results,
    })
}

#[tauri::command]
fn list_ssh_shortcuts() -> Result<Vec<SshShortcutRow>, String> {
    list_ssh_shortcuts_internal()
}

#[tauri::command]
fn test_ssh_shortcut(alias: String) -> Result<SshConnectionTestResult, String> {
    let alias = validate_alias(&alias)?;
    Ok(run_ssh_connection_test(alias))
}

#[tauri::command]
fn test_all_ssh_shortcuts() -> Result<Vec<SshConnectionTestResult>, String> {
    let rows = list_ssh_shortcuts_internal()?;
    let results = rows
        .into_iter()
        .map(|row| run_ssh_connection_test(&row.alias))
        .collect::<Vec<_>>();
    Ok(results)
}

#[tauri::command]
fn delete_ssh_shortcut(alias: String) -> Result<String, String> {
    let alias = validate_alias(&alias)?;
    delete_ssh_alias_from_config(alias)
}

fn list_ssh_shortcuts_internal() -> Result<Vec<SshShortcutRow>, String> {
    let home_dir = home_dir_path()?;
    let config_path = home_dir.join(".ssh").join("config");
    if !config_path.exists() {
        return Ok(Vec::new());
    }

    let mut visited_files: HashSet<PathBuf> = HashSet::new();
    let mut aliases: BTreeMap<String, SshAliasSource> = BTreeMap::new();
    collect_ssh_aliases_from_file(&config_path, &home_dir, &mut visited_files, &mut aliases)?;

    let rows = aliases
        .into_iter()
        .map(|(alias, source)| resolve_ssh_shortcut_row(alias, source))
        .collect::<Vec<_>>();
    Ok(rows)
}

#[tauri::command]
fn open_ssh_terminal(alias: String) -> Result<(), String> {
    let alias = validate_alias(&alias)?;

    #[cfg(target_os = "macos")]
    {
        return open_ssh_terminal_macos(alias);
    }

    #[cfg(target_os = "windows")]
    {
        return open_ssh_terminal_windows(alias);
    }

    #[cfg(target_os = "linux")]
    {
        return open_ssh_terminal_linux(alias);
    }

    #[allow(unreachable_code)]
    Err("当前系统暂不支持一键打开 SSH 终端".to_string())
}

#[tauri::command]
async fn pdd_login_with_browser(request: PddLoginRequest) -> Result<PddLoginResponse, String> {
    let normalized = normalize_pdd_login_request(request)?;
    tauri::async_runtime::spawn_blocking(move || run_pdd_login_flow(normalized))
        .await
        .map_err(|err| format!("浏览器登录任务异常：{err}"))?
}

#[tauri::command]
async fn pdd_validate_cookie(
    request: PddCookieValidateRequest,
) -> Result<PddCookieStatusResponse, String> {
    let cookie_path = resolve_input_path(&request.cookie_path)?;
    let cookies = read_pdd_cookie_file(&cookie_path)?;
    let usable_cookies = usable_pdd_cookies(&cookies);
    let checked_at = Utc::now().to_rfc3339();

    if usable_cookies.is_empty() {
        return Ok(PddCookieStatusResponse {
            valid: false,
            reason: "Cookie 已过期或为空".to_string(),
            cookie_path: cookie_path.display().to_string(),
            cookie_count: 0,
            checked_at,
        });
    }

    let test_url = request
        .test_url
        .as_deref()
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .unwrap_or(PDD_COOKIE_TEST_URL);
    validate_pdd_host_url(test_url)?;

    let cookie_header = build_cookie_header(&usable_cookies);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("sp-toolbox-pdd-cookie-validator/0.1.0")
        .build()
        .map_err(|err| format!("初始化 HTTP 客户端失败：{err}"))?;
    let response = client
        .get(test_url)
        .header("cookie", cookie_header)
        .send()
        .await
        .map_err(|err| format!("检测 Cookie 失败：{err}"))?;
    let status = response.status();
    let location = response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_lowercase())
        .unwrap_or_default();
    let is_redirect = status.is_redirection();
    let body = if is_redirect {
        String::new()
    } else {
        response.text().await.unwrap_or_default().to_lowercase()
    };

    let looks_like_login = if is_redirect {
        location.contains("login") || location.contains("passport")
    } else {
        body.contains("欢迎登录")
            || body.contains("请输入账号")
            || body.contains("请输入密码")
            || body.contains("立即登录")
    };

    let valid = if is_redirect {
        !looks_like_login
    } else {
        status.is_success() && !looks_like_login
    };
    let reason = if valid {
        "Cookie 有效".to_string()
    } else if is_redirect && looks_like_login {
        "检测到跳转登录页，Cookie 已失效".to_string()
    } else if !status.is_success() {
        format!("目标站点返回 HTTP {}", status.as_u16())
    } else {
        "检测结果显示仍处于登录页，Cookie 可能失效".to_string()
    };

    Ok(PddCookieStatusResponse {
        valid,
        reason,
        cookie_path: cookie_path.display().to_string(),
        cookie_count: usable_cookies.len(),
        checked_at,
    })
}

#[tauri::command]
async fn pdd_fetch_store_configs(request: PddFetchRequest) -> Result<PddFetchResponse, String> {
    let api_url = request.api_url.trim();
    if api_url.is_empty() {
        return Err("apiUrl 不能为空".to_string());
    }
    let cookie_path = resolve_input_path(&request.cookie_path)?;
    let cookies = read_pdd_cookie_file(&cookie_path)?;
    let usable_cookies = usable_pdd_cookies(&cookies);
    if usable_cookies.is_empty() {
        return Err("Cookie 已失效，请先重新登录".to_string());
    }

    let cookie_header = build_cookie_header(&usable_cookies);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("sp-toolbox-pdd-fetch/0.1.0")
        .build()
        .map_err(|err| format!("初始化 HTTP 客户端失败：{err}"))?;

    let response = client
        .request(Method::GET, api_url)
        .header("cookie", cookie_header)
        .send()
        .await
        .map_err(|err| format!("请求抓取接口失败：{err}"))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|err| format!("读取抓取接口响应失败：{err}"))?;
    let parsed_json: Value = serde_json::from_str(&text).unwrap_or_else(|_| {
        serde_json::json!({
            "raw": text
        })
    });

    let fetched_at = Utc::now().to_rfc3339();
    if request.dry_run.unwrap_or(false) {
        return Ok(PddFetchResponse {
            success: status.is_success(),
            status: status.as_u16(),
            saved_path: None,
            message: "测试请求已完成，未写入文件".to_string(),
            fetched_at,
        });
    }

    let output_path = resolve_output_path(&request.output_path)?;
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "创建输出目录失败：{} ({err})",
                parent.as_os_str().to_string_lossy()
            )
        })?;
    }
    let payload = serde_json::to_string_pretty(&parsed_json)
        .map_err(|err| format!("序列化抓取结果失败：{err}"))?;
    fs::write(&output_path, payload)
        .map_err(|err| format!("写入抓取结果失败：{} ({err})", output_path.display()))?;

    Ok(PddFetchResponse {
        success: status.is_success(),
        status: status.as_u16(),
        saved_path: Some(output_path.display().to_string()),
        message: if status.is_success() {
            "抓取并保存成功".to_string()
        } else {
            "接口返回非 2xx，已保存响应供排查".to_string()
        },
        fetched_at,
    })
}

#[tauri::command]
async fn pdd_quick_sync(request: PddQuickSyncRequest) -> Result<PddQuickSyncResponse, String> {
    tauri::async_runtime::spawn_blocking(move || run_pdd_quick_sync(request))
        .await
        .map_err(|err| format!("执行一键同步任务失败：{err}"))?
}

fn run_pdd_quick_sync(request: PddQuickSyncRequest) -> Result<PddQuickSyncResponse, String> {
    if request.task_id < 0 {
        return Err("taskId 不能为负数".to_string());
    }
    if request.receive_id <= 0 {
        return Err("receiveId 必须大于 0".to_string());
    }
    let server_alias = request.server_alias.trim();
    if server_alias.is_empty() {
        return Err("serverAlias 不能为空".to_string());
    }

    let file_path = resolve_input_path(&request.file_path)?;
    let mut steps: Vec<PddSyncStepResult> = Vec::new();
    let mut old_receive_id: Option<i64> = None;
    let mut replaced_line: Option<usize> = None;
    let mut replaced_count: usize = 0;
    let mut commit_hash: Option<String> = None;
    let mut branch: Option<String> = None;
    let mut pushed = false;

    let replace_command = format!(
        "replace task {} min sync:receive -> {}",
        request.task_id, request.receive_id
    );
    let replace_result =
        match replace_min_sync_receive_in_task(&file_path, request.task_id, request.receive_id) {
            Ok(item) => {
                old_receive_id = Some(item.old_receive_id);
                replaced_line = Some(item.line_number);
                replaced_count = 1;
                steps.push(build_sync_step_result(
                    "replace",
                    1,
                    "替换文件",
                    &replace_command,
                    "success",
                    None,
                    format!(
                        "已将第 {} 行 sync:receive {} 替换为 {}",
                        item.line_number, item.old_receive_id, request.receive_id
                    ),
                ));
                item
            }
            Err(err) => {
                steps.push(build_sync_step_result(
                    "replace",
                    1,
                    "替换文件",
                    &replace_command,
                    "failed",
                    None,
                    err.clone(),
                ));
                return Ok(build_pdd_quick_sync_response(
                    &request,
                    &file_path,
                    old_receive_id,
                    replaced_line,
                    replaced_count,
                    commit_hash,
                    branch,
                    pushed,
                    steps,
                    format!("一键同步失败：替换步骤执行失败（{err}）"),
                ));
            }
        };

    let git_context = match prepare_git_commit_context(&file_path) {
        Ok(context) => context,
        Err(err) => {
            steps.push(build_sync_step_result(
                "git-commit",
                2,
                "Git 提交",
                "git add -- <file> && git commit -m <message>",
                "failed",
                None,
                err.clone(),
            ));
            steps.push(build_sync_step_result(
                "git-push",
                3,
                "Git 推送",
                "git push origin <branch>",
                "skipped",
                None,
                "因上一步失败，已跳过".to_string(),
            ));
            steps.push(build_sync_step_result(
                "ssh-connect",
                4,
                "连接服务器",
                &format!("ssh {} \"echo [connect-ok]\"", server_alias),
                "skipped",
                None,
                "因上一步失败，已跳过".to_string(),
            ));
            steps.extend(build_skipped_remote_sync_steps(
                request.receive_id,
                "因上一步失败，已跳过",
            ));
            return Ok(build_pdd_quick_sync_response(
                &request,
                &file_path,
                old_receive_id,
                replaced_line,
                replaced_count,
                commit_hash,
                branch,
                pushed,
                steps,
                format!("一键同步失败：Git 提交准备失败（{err}）"),
            ));
        }
    };

    branch = Some(git_context.branch.clone());

    match commit_single_file(
        &git_context,
        request.task_id,
        replace_result.old_receive_id,
        request.receive_id,
    ) {
        Ok(hash) => {
            commit_hash = Some(hash.clone());
            steps.push(build_sync_step_result(
                "git-commit",
                2,
                "Git 提交",
                &format!(
                    "git add -- {} && git commit -m <message>",
                    git_context.relative_text
                ),
                "success",
                Some(0),
                format!("提交成功，commit={hash}"),
            ));
        }
        Err(err) => {
            steps.push(build_sync_step_result(
                "git-commit",
                2,
                "Git 提交",
                &format!(
                    "git add -- {} && git commit -m <message>",
                    git_context.relative_text
                ),
                "failed",
                None,
                err.clone(),
            ));
            steps.push(build_sync_step_result(
                "git-push",
                3,
                "Git 推送",
                &format!("git push origin {}", git_context.branch),
                "skipped",
                None,
                "因上一步失败，已跳过".to_string(),
            ));
            steps.push(build_sync_step_result(
                "ssh-connect",
                4,
                "连接服务器",
                &format!("ssh {} \"echo [connect-ok]\"", server_alias),
                "skipped",
                None,
                "因上一步失败，已跳过".to_string(),
            ));
            steps.extend(build_skipped_remote_sync_steps(
                request.receive_id,
                "因上一步失败，已跳过",
            ));
            return Ok(build_pdd_quick_sync_response(
                &request,
                &file_path,
                old_receive_id,
                replaced_line,
                replaced_count,
                commit_hash,
                branch,
                pushed,
                steps,
                format!("一键同步失败：Git 提交失败（{err}）"),
            ));
        }
    }

    match push_git_branch(&git_context) {
        Ok(_) => {
            pushed = true;
            steps.push(build_sync_step_result(
                "git-push",
                3,
                "Git 推送",
                &format!("git push origin {}", git_context.branch),
                "success",
                Some(0),
                format!("已推送到 origin/{}", git_context.branch),
            ));
        }
        Err(err) => {
            steps.push(build_sync_step_result(
                "git-push",
                3,
                "Git 推送",
                &format!("git push origin {}", git_context.branch),
                "failed",
                None,
                err.clone(),
            ));
            steps.push(build_sync_step_result(
                "ssh-connect",
                4,
                "连接服务器",
                &format!("ssh {} \"echo [connect-ok]\"", server_alias),
                "skipped",
                None,
                "因上一步失败，已跳过".to_string(),
            ));
            steps.extend(build_skipped_remote_sync_steps(
                request.receive_id,
                "因上一步失败，已跳过",
            ));
            return Ok(build_pdd_quick_sync_response(
                &request,
                &file_path,
                old_receive_id,
                replaced_line,
                replaced_count,
                commit_hash,
                branch,
                pushed,
                steps,
                format!("一键同步失败：Git 推送失败（{err}）"),
            ));
        }
    }

    match run_ssh_command(server_alias, "echo '[connect-ok]'") {
        Ok((exit_code, output)) if exit_code == 0 => {
            steps.push(build_sync_step_result(
                "ssh-connect",
                4,
                "连接服务器",
                &format!("ssh {} \"echo [connect-ok]\"", server_alias),
                "success",
                Some(exit_code),
                output,
            ));
        }
        Ok((exit_code, output)) => {
            steps.push(build_sync_step_result(
                "ssh-connect",
                4,
                "连接服务器",
                &format!("ssh {} \"echo [connect-ok]\"", server_alias),
                "failed",
                Some(exit_code),
                output,
            ));
            steps.extend(build_skipped_remote_sync_steps(
                request.receive_id,
                "因连接服务器失败，已跳过",
            ));
            return Ok(build_pdd_quick_sync_response(
                &request,
                &file_path,
                old_receive_id,
                replaced_line,
                replaced_count,
                commit_hash,
                branch,
                pushed,
                steps,
                "一键同步失败：连接服务器失败".to_string(),
            ));
        }
        Err(err) => {
            steps.push(build_sync_step_result(
                "ssh-connect",
                4,
                "连接服务器",
                &format!("ssh {} \"echo [connect-ok]\"", server_alias),
                "failed",
                None,
                err.clone(),
            ));
            steps.extend(build_skipped_remote_sync_steps(
                request.receive_id,
                "因连接服务器失败，已跳过",
            ));
            return Ok(build_pdd_quick_sync_response(
                &request,
                &file_path,
                old_receive_id,
                replaced_line,
                replaced_count,
                commit_hash,
                branch,
                pushed,
                steps,
                format!("一键同步失败：连接服务器失败（{err}）"),
            ));
        }
    }

    steps.extend(run_remote_sync_steps(server_alias, request.receive_id));

    let success = !steps.iter().any(|item| item.status == "failed");
    let message = if success {
        format!(
            "一键同步完成：替换、提交、推送、连服与远程命令全部成功（task={}，id={}）",
            request.task_id, request.receive_id
        )
    } else {
        format!(
            "一键同步存在失败步骤，请查看反馈详情（task={}，id={}）",
            request.task_id, request.receive_id
        )
    };

    Ok(build_pdd_quick_sync_response(
        &request,
        &file_path,
        old_receive_id,
        replaced_line,
        replaced_count,
        commit_hash,
        branch,
        pushed,
        steps,
        message,
    ))
}

#[derive(Debug, Clone)]
struct ReplaceSyncResult {
    old_receive_id: i64,
    line_number: usize,
}

fn replace_min_sync_receive_in_task(
    file_path: &Path,
    task_id: i32,
    new_receive_id: i64,
) -> Result<ReplaceSyncResult, String> {
    if !file_path.exists() {
        return Err(format!("目标文件不存在：{}", file_path.display()));
    }
    let mut source = fs::read_to_string(file_path)
        .map_err(|err| format!("读取目标文件失败：{} ({err})", file_path.display()))?;
    let (block_start, block_end) = find_task_block_range(&source, task_id)?;
    let entries = collect_sync_receive_entries_in_block(&source, block_start, block_end);
    if entries.is_empty() {
        return Err(format!(
            "task->id == {} 的代码块里没有可替换的 sync:receive 调用",
            task_id
        ));
    }
    let target = entries
        .iter()
        .min_by_key(|entry| entry.receive_id)
        .cloned()
        .ok_or_else(|| "未找到可替换的 sync:receive".to_string())?;
    if target.receive_id == new_receive_id {
        return Err(format!(
            "task->id == {} 中最小 sync:receive 已是 {}，无需替换",
            task_id, new_receive_id
        ));
    }
    source.replace_range(target.start..target.end, &new_receive_id.to_string());
    fs::write(file_path, source)
        .map_err(|err| format!("写入目标文件失败：{} ({err})", file_path.display()))?;
    Ok(ReplaceSyncResult {
        old_receive_id: target.receive_id,
        line_number: target.line_number,
    })
}

#[derive(Debug, Clone)]
struct GitCommitContext {
    repo_root: PathBuf,
    branch: String,
    relative_text: String,
}

fn prepare_git_commit_context(file_path: &Path) -> Result<GitCommitContext, String> {
    let file_dir = file_path
        .parent()
        .ok_or_else(|| format!("无法识别文件目录：{}", file_path.display()))?;
    let repo_root_text = run_git_capture_output(
        file_dir,
        &["rev-parse", "--show-toplevel"],
        "定位 Git 仓库",
    )?;
    let repo_root = PathBuf::from(repo_root_text.trim());
    let branch = run_git_capture_output(
        &repo_root,
        &["rev-parse", "--abbrev-ref", "HEAD"],
        "读取当前分支",
    )?;
    let branch = branch.trim().to_string();
    if branch.is_empty() || branch == "HEAD" {
        return Err("当前处于 detached HEAD，无法自动推送".to_string());
    }

    let relative = file_path
        .strip_prefix(&repo_root)
        .map_err(|_| {
            format!(
                "目标文件不在仓库内：file={} repo={}",
                file_path.display(),
                repo_root.display()
            )
        })?
        .to_path_buf();
    let relative_text = relative.to_string_lossy().to_string();
    Ok(GitCommitContext {
        repo_root,
        branch,
        relative_text,
    })
}

fn commit_single_file(
    context: &GitCommitContext,
    task_id: i32,
    old_receive_id: i64,
    new_receive_id: i64,
) -> Result<String, String> {
    run_git_command(
        &context.repo_root,
        &["add", "--", &context.relative_text],
        "暂存目标文件",
    )?;

    let commit_message = format!(
        "chore(sync): task {} replace sync:receive {} -> {}",
        task_id, old_receive_id, new_receive_id
    );
    run_git_command(
        &context.repo_root,
        &["commit", "-m", &commit_message, "--", &context.relative_text],
        "提交目标文件改动",
    )?;

    let commit_hash = run_git_capture_output(
        &context.repo_root,
        &["rev-parse", "--short", "HEAD"],
        "读取提交哈希",
    )?;
    Ok(commit_hash.trim().to_string())
}

fn push_git_branch(context: &GitCommitContext) -> Result<(), String> {
    run_git_command(
        &context.repo_root,
        &["push", "origin", &context.branch],
        "推送到远端",
    )
}

fn run_git_command(repo_root: &Path, args: &[&str], context: &str) -> Result<(), String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()
        .map_err(|err| format!("{context}失败：{err}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if !stderr.is_empty() { stderr } else { stdout };
    Err(format!("{context}失败：{detail}"))
}

fn run_git_capture_output(repo_root: &Path, args: &[&str], context: &str) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()
        .map_err(|err| format!("{context}失败：{err}"))?;
    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return Ok(text);
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if !stderr.is_empty() { stderr } else { stdout };
    Err(format!("{context}失败：{detail}"))
}

#[derive(Debug, Clone)]
struct RemoteSyncStepDef {
    key: String,
    step: usize,
    title: String,
    display_command: String,
    remote_command: String,
}

fn remote_sync_step_defs(receive_id: i64) -> Vec<RemoteSyncStepDef> {
    vec![
        RemoteSyncStepDef {
            key: "remote-sudo".to_string(),
            step: 5,
            title: "sudo -i".to_string(),
            display_command: "sudo -i".to_string(),
            remote_command: "sudo -i bash -lc \"echo '[step1] sudo -i ok'\"".to_string(),
        },
        RemoteSyncStepDef {
            key: "remote-cd".to_string(),
            step: 6,
            title: "cd ~/junziyun-v7".to_string(),
            display_command: "cd ~/junziyun-v7".to_string(),
            remote_command: "sudo -i bash -lc \"cd ~/junziyun-v7 && pwd\"".to_string(),
        },
        RemoteSyncStepDef {
            key: "remote-git-pull".to_string(),
            step: 7,
            title: "git pull".to_string(),
            display_command: "git pull".to_string(),
            remote_command: "sudo -i bash -lc \"cd ~/junziyun-v7 && git pull\"".to_string(),
        },
        RemoteSyncStepDef {
            key: "remote-sync-pdd-order".to_string(),
            step: 8,
            title: format!("php artisan sync:pdd_order {receive_id}"),
            display_command: format!("php artisan sync:pdd_order {receive_id}"),
            remote_command: format!(
                "sudo -i bash -lc \"cd ~/junziyun-v7 && php artisan sync:pdd_order {receive_id}\""
            ),
        },
        RemoteSyncStepDef {
            key: "remote-restart-cron".to_string(),
            step: 9,
            title: "restart cron".to_string(),
            display_command:
                "cd /data/wwwroot/junziyun/ && /usr/local/php/bin/php /data/wwwroot/junziyun/artisan3 start:cron restart"
                    .to_string(),
            remote_command:
                "sudo -i bash -lc \"cd /data/wwwroot/junziyun/ && /usr/local/php/bin/php /data/wwwroot/junziyun/artisan3 start:cron restart\""
                    .to_string(),
        },
    ]
}

fn run_remote_sync_steps(server_alias: &str, receive_id: i64) -> Vec<PddSyncStepResult> {
    let step_defs = remote_sync_step_defs(receive_id);
    let mut results: Vec<PddSyncStepResult> = Vec::new();
    let mut can_continue = true;
    for def in step_defs {
        if !can_continue {
            results.push(build_sync_step_result(
                &def.key,
                def.step,
                &def.title,
                &def.display_command,
                "skipped",
                None,
                "因前一步失败，已跳过".to_string(),
            ));
            continue;
        }

        match run_ssh_command(server_alias, &def.remote_command) {
            Ok((exit_code, output)) => {
                if exit_code == 0 {
                    results.push(build_sync_step_result(
                        &def.key,
                        def.step,
                        &def.title,
                        &def.display_command,
                        "success",
                        Some(exit_code),
                        output,
                    ));
                } else {
                    can_continue = false;
                    results.push(build_sync_step_result(
                        &def.key,
                        def.step,
                        &def.title,
                        &def.display_command,
                        "failed",
                        Some(exit_code),
                        output,
                    ));
                }
            }
            Err(err) => {
                can_continue = false;
                results.push(build_sync_step_result(
                    &def.key,
                    def.step,
                    &def.title,
                    &def.display_command,
                    "failed",
                    None,
                    err,
                ));
            }
        }
    }
    results
}

fn build_skipped_remote_sync_steps(receive_id: i64, reason: &str) -> Vec<PddSyncStepResult> {
    remote_sync_step_defs(receive_id)
        .into_iter()
        .map(|def| {
            build_sync_step_result(
                &def.key,
                def.step,
                &def.title,
                &def.display_command,
                "skipped",
                None,
                reason.to_string(),
            )
        })
        .collect::<Vec<_>>()
}

fn build_sync_step_result(
    key: &str,
    step: usize,
    title: &str,
    command: &str,
    status: &str,
    exit_code: Option<i32>,
    output: String,
) -> PddSyncStepResult {
    PddSyncStepResult {
        key: key.to_string(),
        step,
        title: title.to_string(),
        command: command.to_string(),
        status: status.to_string(),
        exit_code,
        output,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_pdd_quick_sync_response(
    request: &PddQuickSyncRequest,
    file_path: &Path,
    old_receive_id: Option<i64>,
    replaced_line: Option<usize>,
    replaced_count: usize,
    commit_hash: Option<String>,
    branch: Option<String>,
    pushed: bool,
    steps: Vec<PddSyncStepResult>,
    message: String,
) -> PddQuickSyncResponse {
    let success = !steps.iter().any(|item| item.status == "failed");
    let remote_steps = steps
        .iter()
        .filter(|item| item.key.starts_with("remote-"))
        .cloned()
        .collect::<Vec<_>>();
    PddQuickSyncResponse {
        success,
        message,
        file_path: file_path.display().to_string(),
        server_alias: request.server_alias.trim().to_string(),
        task_id: request.task_id,
        old_receive_id,
        new_receive_id: request.receive_id,
        replaced_line,
        replaced_count,
        commit_hash,
        branch,
        pushed,
        steps,
        remote_steps,
        updated_at: Utc::now().to_rfc3339(),
    }
}

fn run_ssh_command(server_alias: &str, remote_cmd: &str) -> Result<(i32, String), String> {
    let output = Command::new("ssh")
        .args(["-o", "BatchMode=yes"])
        .args(["-o", "ConnectTimeout=20"])
        .arg("-tt")
        .arg("--")
        .arg(server_alias)
        .arg(remote_cmd)
        .output()
        .map_err(|err| format!("执行 ssh 命令失败：{err}"))?;

    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let merged = if stdout.is_empty() && stderr.is_empty() {
        "<no output>".to_string()
    } else if stdout.is_empty() {
        stderr
    } else if stderr.is_empty() {
        stdout
    } else {
        format!("{stdout}\n{stderr}")
    };
    Ok((code, merged))
}

async fn sync_single_target(
    client: &AlibabaOpenApiClient,
    account: &AccountInput,
    target: &TargetInput,
    cidr: &str,
) -> Result<TargetSyncResult, ApiError> {
    let region_id = resolve_target_region(client, account, target).await?;
    let ingress_rules =
        describe_ingress_rules(client, account, &region_id, &target.security_group_id).await?;

    if let Some(rule_id) = trim_to_option(&target.rule_id) {
        if let Some(rule) = ingress_rules
            .iter()
            .find(|rule| rule.rule_id.as_deref() == Some(rule_id))
            .cloned()
        {
            return update_existing_rule(
                client,
                account,
                target,
                &region_id,
                rule,
                cidr,
                "modified".to_string(),
            )
            .await;
        }

        return Ok(skipped_result(
            target,
            &region_id,
            Some(rule_id.to_string()),
            format!("未找到 ruleId={} 的规则，未执行修改", rule_id),
        ));
    }

    let Some(description) = trim_to_option(&target.description) else {
        return Ok(skipped_result(
            target,
            &region_id,
            None,
            "未填写描述且未提供 ruleId，未执行修改".to_string(),
        ));
    };

    let mut matched_rules: Vec<SecurityRule> = ingress_rules
        .iter()
        .filter(|rule| rule.description.as_deref() == Some(description))
        .cloned()
        .collect();

    match matched_rules.len() {
        0 => Ok(skipped_result(
            target,
            &region_id,
            None,
            format!("未找到描述完全匹配“{}”的规则，未执行修改", description),
        )),
        1 => {
            let rule = matched_rules.remove(0);
            update_existing_rule(
                client,
                account,
                target,
                &region_id,
                rule,
                cidr,
                "modified_by_description".to_string(),
            )
            .await
        }
        _ => Ok(skipped_result(
            target,
            &region_id,
            None,
            format!(
                "描述“{}”匹配到多条规则（{}条），未执行修改。请改用 ruleId。",
                description,
                matched_rules.len()
            ),
        )),
    }
}

fn skipped_result(
    target: &TargetInput,
    region_id: &str,
    rule_id: Option<String>,
    message: String,
) -> TargetSyncResult {
    TargetSyncResult {
        target_id: target.id.clone(),
        target_name: target.name.clone(),
        account_id: target.account_id.clone(),
        account_name: None,
        security_group_id: target.security_group_id.clone(),
        region_id: Some(region_id.to_string()),
        rule_id,
        action: "skipped".to_string(),
        success: true,
        request_id: None,
        code: None,
        message,
    }
}

async fn update_existing_rule(
    client: &AlibabaOpenApiClient,
    account: &AccountInput,
    target: &TargetInput,
    region_id: &str,
    rule: SecurityRule,
    cidr: &str,
    action: String,
) -> Result<TargetSyncResult, ApiError> {
    let Some(rule_id) = rule.rule_id.clone() else {
        return Err(ApiError::new(
            "RuleIdMissing",
            "目标规则没有 SecurityGroupRuleId，无法修改",
            None,
        ));
    };

    if rule.source_cidr_ip.is_none() {
        return Err(ApiError::new(
            "UnsupportedRuleType",
            "该规则不是 IPv4 CIDR 授权对象，不能直接改 SourceCidrIp",
            None,
        ));
    }

    if rule.source_cidr_ip.as_deref() == Some(cidr) {
        return Ok(TargetSyncResult {
            target_id: target.id.clone(),
            target_name: target.name.clone(),
            account_id: target.account_id.clone(),
            account_name: None,
            security_group_id: target.security_group_id.clone(),
            region_id: Some(region_id.to_string()),
            rule_id: Some(rule_id),
            action: "noop".to_string(),
            success: true,
            request_id: None,
            code: None,
            message: "规则 IP 已是最新，无需更新".to_string(),
        });
    }

    let mut params = BTreeMap::new();
    params.insert("RegionId".to_string(), region_id.to_string());
    params.insert(
        "SecurityGroupId".to_string(),
        target.security_group_id.clone(),
    );
    params.insert("SecurityGroupRuleId".to_string(), rule_id.clone());
    params.insert("SourceCidrIp".to_string(), cidr.to_string());

    let host = ecs_host(region_id);
    let response = client
        .call_rpc_json(
            &host,
            "ModifySecurityGroupRule",
            ECS_VERSION,
            account,
            &params,
        )
        .await?;

    Ok(TargetSyncResult {
        target_id: target.id.clone(),
        target_name: target.name.clone(),
        account_id: target.account_id.clone(),
        account_name: None,
        security_group_id: target.security_group_id.clone(),
        region_id: Some(region_id.to_string()),
        rule_id: Some(rule_id),
        action,
        success: true,
        request_id: response
            .get("RequestId")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        code: None,
        message: format!("规则已更新为 {}", cidr),
    })
}

async fn resolve_target_region(
    client: &AlibabaOpenApiClient,
    account: &AccountInput,
    target: &TargetInput,
) -> Result<String, ApiError> {
    if let Some(region_id) = trim_to_option(&target.region_id) {
        return Ok(region_id.to_string());
    }

    if let Some(region_id) = trim_to_option(&account.default_region_id) {
        if security_group_exists_in_region(client, account, region_id, &target.security_group_id)
            .await?
        {
            return Ok(region_id.to_string());
        }
    }

    discover_region_by_security_group(client, account, &target.security_group_id).await
}

async fn discover_region_by_security_group(
    client: &AlibabaOpenApiClient,
    account: &AccountInput,
    security_group_id: &str,
) -> Result<String, ApiError> {
    let regions = describe_regions(client, account).await?;
    let mut first_non_not_found_error: Option<ApiError> = None;

    for region in regions {
        match security_group_exists_in_region(client, account, &region, security_group_id).await {
            Ok(true) => return Ok(region),
            Ok(false) => continue,
            Err(err) => {
                if err.code.contains("InvalidSecurityGroupId.NotFound")
                    || err.code.contains("InvalidRegionId")
                {
                    continue;
                }
                if first_non_not_found_error.is_none() {
                    first_non_not_found_error = Some(err);
                }
            }
        }
    }

    if let Some(err) = first_non_not_found_error {
        return Err(err);
    }

    Err(ApiError::new(
        "SecurityGroupNotFound",
        format!("没有在任何地域找到安全组 {}", security_group_id),
        None,
    ))
}

async fn describe_regions(
    client: &AlibabaOpenApiClient,
    account: &AccountInput,
) -> Result<Vec<String>, ApiError> {
    let params = BTreeMap::new();

    let mut hosts = Vec::new();
    if let Some(default_region) = trim_to_option(&account.default_region_id) {
        hosts.push(ecs_host(default_region));
    }
    hosts.push("ecs.cn-hangzhou.aliyuncs.com".to_string());
    hosts.push("ecs.aliyuncs.com".to_string());

    let mut last_error: Option<ApiError> = None;
    for host in hosts {
        match client
            .call_rpc_json(&host, "DescribeRegions", ECS_VERSION, account, &params)
            .await
        {
            Ok(response) => {
                let region_values = response
                    .pointer("/Regions/Region")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();

                let regions = region_values
                    .iter()
                    .filter_map(|region| region.get("RegionId").and_then(Value::as_str))
                    .map(ToString::to_string)
                    .collect::<Vec<_>>();

                if regions.is_empty() {
                    return Err(ApiError::new(
                        "RegionEmpty",
                        "DescribeRegions 返回了空地域列表",
                        response
                            .get("RequestId")
                            .and_then(Value::as_str)
                            .map(ToString::to_string),
                    ));
                }

                return Ok(regions);
            }
            Err(err) => {
                last_error = Some(err);
            }
        }
    }

    Err(last_error
        .unwrap_or_else(|| ApiError::new("DescribeRegionsFailed", "无法获取地域列表", None)))
}

async fn security_group_exists_in_region(
    client: &AlibabaOpenApiClient,
    account: &AccountInput,
    region_id: &str,
    security_group_id: &str,
) -> Result<bool, ApiError> {
    let mut params = BTreeMap::new();
    params.insert("RegionId".to_string(), region_id.to_string());
    params.insert("MaxResults".to_string(), "1".to_string());
    params.insert(
        "SecurityGroupIds".to_string(),
        serde_json::to_string(&vec![security_group_id]).unwrap_or_else(|_| "[]".to_string()),
    );

    let host = ecs_host(region_id);
    let response = client
        .call_rpc_json(
            &host,
            "DescribeSecurityGroups",
            ECS_VERSION,
            account,
            &params,
        )
        .await?;

    let groups = response
        .pointer("/SecurityGroups/SecurityGroup")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    Ok(groups.iter().any(|group| {
        group
            .get("SecurityGroupId")
            .and_then(Value::as_str)
            .is_some_and(|id| id == security_group_id)
    }))
}

async fn describe_ingress_rules(
    client: &AlibabaOpenApiClient,
    account: &AccountInput,
    region_id: &str,
    security_group_id: &str,
) -> Result<Vec<SecurityRule>, ApiError> {
    let mut rules = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut params = BTreeMap::new();
        params.insert("RegionId".to_string(), region_id.to_string());
        params.insert("SecurityGroupId".to_string(), security_group_id.to_string());
        params.insert("Direction".to_string(), "ingress".to_string());
        params.insert("MaxResults".to_string(), "1000".to_string());

        if let Some(token) = &next_token {
            params.insert("NextToken".to_string(), token.clone());
        }

        let host = ecs_host(region_id);
        let response = client
            .call_rpc_json(
                &host,
                "DescribeSecurityGroupAttribute",
                ECS_VERSION,
                account,
                &params,
            )
            .await?;

        if let Some(permissions) = response.pointer("/Permissions/Permission") {
            match permissions {
                Value::Array(items) => {
                    for item in items {
                        rules.push(SecurityRule {
                            rule_id: item
                                .get("SecurityGroupRuleId")
                                .and_then(Value::as_str)
                                .map(ToString::to_string),
                            source_cidr_ip: item
                                .get("SourceCidrIp")
                                .and_then(Value::as_str)
                                .map(ToString::to_string),
                            description: item
                                .get("Description")
                                .and_then(Value::as_str)
                                .map(ToString::to_string),
                        });
                    }
                }
                Value::Object(_) => {
                    rules.push(SecurityRule {
                        rule_id: permissions
                            .get("SecurityGroupRuleId")
                            .and_then(Value::as_str)
                            .map(ToString::to_string),
                        source_cidr_ip: permissions
                            .get("SourceCidrIp")
                            .and_then(Value::as_str)
                            .map(ToString::to_string),
                        description: permissions
                            .get("Description")
                            .and_then(Value::as_str)
                            .map(ToString::to_string),
                    });
                }
                _ => {}
            }
        }

        next_token = response
            .get("NextToken")
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .filter(|token| !token.is_empty());

        if next_token.is_none() {
            break;
        }
    }

    Ok(rules)
}

async fn get_caller_identity(
    client: &AlibabaOpenApiClient,
    account: &AccountInput,
) -> Result<Value, ApiError> {
    let params = BTreeMap::new();
    client
        .call_rpc_json(STS_HOST, "GetCallerIdentity", STS_VERSION, account, &params)
        .await
}

async fn detect_public_ipv4(http: &reqwest::Client) -> Result<String, ApiError> {
    let sources = [
        "https://api.ipsimple.org/ipv4?format=json",
        "https://api64.ipify.org?format=json",
        "https://4.ipw.cn",
        "https://ipv4.icanhazip.com",
        "https://ifconfig.me/ip",
    ];

    let mut last_error_message = String::new();
    for source in sources {
        match http.get(source).send().await {
            Ok(response) => match response.text().await {
                Ok(body) => {
                    if let Some(ip) = parse_ip_from_response(&body) {
                        return Ok(ip);
                    }
                    last_error_message = format!("IP 服务返回内容无效: {}", source);
                }
                Err(err) => {
                    last_error_message = format!("读取 IP 服务响应失败: {}", err);
                }
            },
            Err(err) => {
                last_error_message = format!("调用 IP 服务失败: {}", err);
            }
        }
    }

    Err(ApiError::new(
        "PublicIpDetectFailed",
        if last_error_message.is_empty() {
            "无法检测公网 IPv4".to_string()
        } else {
            last_error_message
        },
        None,
    ))
}

async fn lookup_current_public_ip_profile(
    http: &reqwest::Client,
) -> Result<PublicIpResponse, ApiError> {
    // Use appworlds API as the primary source for current IP + geolocation + carrier.
    let payload = fetch_appworlds_data(http, None)
        .await
        .map_err(|err| ApiError::new("PublicIpGeoLookupFailed", err.message, err.request_id))?;

    let ip = payload
        .ip
        .as_deref()
        .filter(|value| value.parse::<Ipv4Addr>().is_ok())
        .ok_or_else(|| ApiError::new("PublicIpGeoInvalid", "公网 IP 服务未返回有效 IPv4", None))?;

    Ok(PublicIpResponse {
        ip: ip.to_string(),
        cidr: format!("{ip}/32"),
        carrier: infer_network_carrier(
            payload.other.as_deref(),
            payload.full_address.as_deref(),
            None,
            false,
        ),
        location: appworlds_location(&payload),
        isp: trim_str_to_option(payload.other.as_deref()).map(ToString::to_string),
        org: trim_str_to_option(payload.full_address.as_deref()).map(ToString::to_string),
    })
}

#[derive(Debug, Clone)]
struct PublicIpMetadata {
    carrier: Option<String>,
    location: Option<String>,
    isp: Option<String>,
    org: Option<String>,
}

async fn lookup_ip_metadata(
    http: &reqwest::Client,
    ip: &str,
) -> Result<PublicIpMetadata, ApiError> {
    let payload = fetch_appworlds_data(http, Some(ip)).await?;

    Ok(PublicIpMetadata {
        carrier: infer_network_carrier(
            payload.other.as_deref(),
            payload.full_address.as_deref(),
            None,
            false,
        ),
        location: appworlds_location(&payload),
        isp: trim_str_to_option(payload.other.as_deref()).map(ToString::to_string),
        org: trim_str_to_option(payload.full_address.as_deref()).map(ToString::to_string),
    })
}

async fn fetch_appworlds_data(
    http: &reqwest::Client,
    ip: Option<&str>,
) -> Result<AppWorldsIpData, ApiError> {
    let endpoint = if let Some(ip) = ip {
        format!("https://ip.appworlds.cn?ip={ip}")
    } else {
        "https://ip.appworlds.cn".to_string()
    };

    for attempt in 0..2 {
        let response = http.get(&endpoint).send().await.map_err(|err| {
            ApiError::new(
                "IpMetadataLookupFailed",
                format!("查询 IP 归属地失败: {err}"),
                None,
            )
        })?;

        let payload: AppWorldsIpResponse = response.json().await.map_err(|err| {
            ApiError::new(
                "IpMetadataParseFailed",
                format!("解析 IP 归属地响应失败: {err}"),
                None,
            )
        })?;

        if payload.code == Some(200) {
            return payload.data.ok_or_else(|| {
                ApiError::new(
                    "IpMetadataLookupFailed",
                    "IP 归属地服务未返回有效 data".to_string(),
                    None,
                )
            });
        }

        let msg = payload
            .msg
            .unwrap_or_else(|| "IP 归属地服务返回失败".to_string());
        let rate_limited =
            payload.code == Some(300) || msg.contains("1次/秒") || msg.contains("访问频率");

        if rate_limited && attempt == 0 {
            std::thread::sleep(Duration::from_millis(1100));
            continue;
        }

        return Err(ApiError::new("IpMetadataLookupFailed", msg, None));
    }

    Err(ApiError::new(
        "IpMetadataLookupFailed",
        "IP 归属地服务返回失败".to_string(),
        None,
    ))
}

fn appworlds_location(payload: &AppWorldsIpData) -> Option<String> {
    if let Some(full) = trim_str_to_option(payload.full_address.as_deref()) {
        return Some(full.to_string());
    }

    format_location(
        payload.country.as_deref(),
        payload.province.as_deref().or(payload.region.as_deref()),
        payload.city.as_deref(),
    )
}

fn format_location(
    country: Option<&str>,
    region_name: Option<&str>,
    city: Option<&str>,
) -> Option<String> {
    let mut parts = Vec::new();
    for part in [country, region_name, city] {
        if let Some(value) = trim_str_to_option(part) {
            if !parts.iter().any(|item: &String| item == value) {
                parts.push(value.to_string());
            }
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

fn infer_network_carrier(
    isp: Option<&str>,
    org: Option<&str>,
    as_name: Option<&str>,
    mobile: bool,
) -> Option<String> {
    let joined = [isp, org, as_name]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
    let haystack = joined.to_lowercase();

    if haystack.contains("电信") || haystack.contains("telecom") || haystack.contains("chinanet")
    {
        return Some("中国电信".to_string());
    }
    if haystack.contains("联通") || haystack.contains("unicom") || haystack.contains("cucc") {
        return Some("中国联通".to_string());
    }
    if haystack.contains("移动") || haystack.contains("mobile") || haystack.contains("cmcc") {
        return Some("中国移动".to_string());
    }
    if haystack.contains("广电")
        || haystack.contains("broadnet")
        || haystack.contains("radio and television")
    {
        return Some("中国广电".to_string());
    }
    if haystack.contains("铁通") || haystack.contains("tietong") {
        return Some("中国铁通".to_string());
    }
    if haystack.contains("教育网") || haystack.contains("cernet") {
        return Some("中国教育网".to_string());
    }
    if mobile {
        return Some("移动网络".to_string());
    }

    trim_str_to_option(isp)
        .or_else(|| trim_str_to_option(org))
        .or_else(|| trim_str_to_option(as_name))
        .map(ToString::to_string)
}

fn parse_ip_from_response(body: &str) -> Option<String> {
    if let Ok(json) = serde_json::from_str::<Value>(body) {
        if let Some(ip) = json.get("ip").and_then(Value::as_str) {
            if ip.parse::<Ipv4Addr>().is_ok() {
                return Some(ip.to_string());
            }
        }
    }

    let text = body.trim();
    if text.parse::<Ipv4Addr>().is_ok() {
        return Some(text.to_string());
    }

    None
}

fn normalize_ipv4_or_cidr(input: &str) -> Result<(String, String), String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("值不能为空".to_string());
    }

    if let Some((ip_part, mask_part)) = trimmed.split_once('/') {
        let ip = ip_part
            .parse::<Ipv4Addr>()
            .map_err(|_| "不是合法的 IPv4 地址".to_string())?;
        let mask: u8 = mask_part
            .parse::<u8>()
            .map_err(|_| "CIDR 掩码必须是 0-32".to_string())?;
        if mask > 32 {
            return Err("CIDR 掩码必须是 0-32".to_string());
        }
        return Ok((ip.to_string(), format!("{ip}/{mask}")));
    }

    let ip = trimmed
        .parse::<Ipv4Addr>()
        .map_err(|_| "不是合法的 IPv4 地址".to_string())?;
    Ok((ip.to_string(), format!("{ip}/32")))
}

fn home_dir_path() -> Result<PathBuf, String> {
    if let Some(home) = env::var_os("HOME") {
        return Ok(PathBuf::from(home));
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(profile) = env::var_os("USERPROFILE") {
            return Ok(PathBuf::from(profile));
        }
        if let (Some(drive), Some(path)) = (env::var_os("HOMEDRIVE"), env::var_os("HOMEPATH")) {
            let mut combined = PathBuf::from(drive);
            combined.push(path);
            return Ok(combined);
        }
    }

    Err("无法获取当前用户的 Home 目录".to_string())
}

fn collect_ssh_aliases_from_file(
    path: &Path,
    home_dir: &Path,
    visited_files: &mut HashSet<PathBuf>,
    aliases: &mut BTreeMap<String, SshAliasSource>,
) -> Result<(), String> {
    let normalized_path = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if !visited_files.insert(normalized_path) {
        return Ok(());
    }

    let content = fs::read_to_string(path)
        .map_err(|err| format!("读取 SSH 配置失败：{} ({err})", path.display()))?;
    let base_dir = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    for (index, raw_line) in content.lines().enumerate() {
        let tokens = parse_ssh_line_tokens(raw_line);
        if tokens.is_empty() {
            continue;
        }

        let key = tokens[0].to_ascii_lowercase();
        if key == "include" {
            for pattern in tokens.iter().skip(1) {
                let include_paths = expand_ssh_include_pattern(pattern, &base_dir, home_dir)?;
                for include_path in include_paths {
                    if include_path.is_file() {
                        collect_ssh_aliases_from_file(
                            &include_path,
                            home_dir,
                            visited_files,
                            aliases,
                        )?;
                    }
                }
            }
            continue;
        }

        if key == "host" {
            for alias in tokens.iter().skip(1) {
                if !is_explicit_ssh_alias(alias) {
                    continue;
                }
                aliases.entry(alias.to_string()).or_insert(SshAliasSource {
                    source_file: path.display().to_string(),
                    source_line: index + 1,
                });
            }
        }
    }

    Ok(())
}

fn parse_ssh_line_tokens(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote_char: Option<char> = None;

    for ch in line.chars() {
        if let Some(quote) = quote_char {
            if ch == quote {
                quote_char = None;
            } else {
                current.push(ch);
            }
            continue;
        }

        match ch {
            '#' => break,
            '"' | '\'' => {
                quote_char = Some(ch);
            }
            _ if ch.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn expand_ssh_include_pattern(
    pattern: &str,
    base_dir: &Path,
    home_dir: &Path,
) -> Result<Vec<PathBuf>, String> {
    let trimmed = pattern.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    let path_with_home = if trimmed == "~" {
        home_dir.to_path_buf()
    } else if let Some(suffix) = trimmed.strip_prefix("~/") {
        home_dir.join(suffix)
    } else {
        PathBuf::from(trimmed)
    };

    let resolved_pattern = if path_with_home.is_absolute() {
        path_with_home
    } else {
        base_dir.join(path_with_home)
    };

    let pattern_text = resolved_pattern.to_string_lossy().to_string();
    if pattern_text.contains('*') || pattern_text.contains('?') || pattern_text.contains('[') {
        let mut matched = Vec::new();
        for entry in glob::glob(&pattern_text).map_err(|err| {
            format!(
                "解析 Include 通配符失败：{} ({err})",
                resolved_pattern.display()
            )
        })? {
            match entry {
                Ok(file) => matched.push(file),
                Err(err) => {
                    return Err(format!("展开 Include 失败：{err}"));
                }
            }
        }
        matched.sort();
        return Ok(matched);
    }

    if resolved_pattern.exists() {
        return Ok(vec![resolved_pattern]);
    }
    Ok(Vec::new())
}

fn is_explicit_ssh_alias(alias: &str) -> bool {
    let trimmed = alias.trim();
    if trimmed.is_empty() || trimmed.starts_with('!') {
        return false;
    }
    !trimmed
        .chars()
        .any(|ch| ch == '*' || ch == '?' || ch == '[' || ch == ']')
}

fn resolve_ssh_shortcut_row(alias: String, source: SshAliasSource) -> SshShortcutRow {
    let mut row = SshShortcutRow {
        alias: alias.clone(),
        host_name: None,
        port: None,
        user: None,
        identity_file: None,
        proxy_jump: None,
        source_file: Some(source.source_file),
        source_line: Some(source.source_line),
        error: None,
    };

    let output = Command::new("ssh").arg("-G").arg(&alias).output();
    match output {
        Ok(output) => {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                row.error = Some(if stderr.is_empty() {
                    format!("ssh -G {} 执行失败", alias)
                } else {
                    stderr
                });
                return row;
            }

            let parsed = parse_ssh_g_output(&String::from_utf8_lossy(&output.stdout));
            row.host_name = sanitize_optional_value(parsed.get("hostname").cloned());
            row.port = sanitize_optional_value(parsed.get("port").cloned());
            row.user = sanitize_optional_value(parsed.get("user").cloned());
            row.identity_file = sanitize_optional_value(parsed.get("identityfile").cloned());
            row.proxy_jump = sanitize_optional_value(parsed.get("proxyjump").cloned());
        }
        Err(err) => {
            row.error = Some(format!("执行 ssh -G 失败：{err}"));
        }
    }

    row
}

fn parse_ssh_g_output(output: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in output.lines() {
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else {
            continue;
        };
        let value = parts.collect::<Vec<_>>().join(" ");
        map.insert(key.to_ascii_lowercase(), value);
    }
    map
}

fn sanitize_optional_value(value: Option<String>) -> Option<String> {
    value.and_then(|raw| {
        let normalized = raw.trim();
        if normalized.is_empty() || normalized.eq_ignore_ascii_case("none") {
            None
        } else {
            Some(normalized.to_string())
        }
    })
}

fn validate_alias(alias: &str) -> Result<&str, String> {
    let trimmed = alias.trim();
    if trimmed.is_empty() {
        return Err("SSH 别名不能为空".to_string());
    }

    if trimmed
        .chars()
        .any(|ch| ch == '\0' || ch == '\n' || ch == '\r')
    {
        return Err("SSH 别名包含非法字符（不允许换行或空字符）".to_string());
    }

    Ok(trimmed)
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn run_ssh_connection_test(alias: &str) -> SshConnectionTestResult {
    let output = Command::new("ssh")
        .args(["-o", "BatchMode=yes"])
        .args(["-o", "ConnectTimeout=8"])
        .args(["-o", "ConnectionAttempts=1"])
        .args(["-o", "NumberOfPasswordPrompts=0"])
        .args(["-o", "StrictHostKeyChecking=accept-new"])
        .arg("--")
        .arg(alias)
        .arg("echo __SP_SSH_TEST_OK__")
        .output();

    let checked_at = Utc::now().to_rfc3339();
    match output {
        Ok(output) => {
            let exit_code = output.status.code();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let merged = if stdout.is_empty() && stderr.is_empty() {
                "<no output>".to_string()
            } else if stdout.is_empty() {
                stderr
            } else if stderr.is_empty() {
                stdout
            } else {
                format!("{stdout}\n{stderr}")
            };

            let success = output.status.success() && merged.contains("__SP_SSH_TEST_OK__");
            SshConnectionTestResult {
                alias: alias.to_string(),
                status: if success {
                    "success".to_string()
                } else {
                    "failed".to_string()
                },
                exit_code,
                output: if success {
                    merged.replace("__SP_SSH_TEST_OK__", "连接测试成功")
                } else {
                    merged
                },
                checked_at,
            }
        }
        Err(err) => SshConnectionTestResult {
            alias: alias.to_string(),
            status: "failed".to_string(),
            exit_code: None,
            output: format!("执行 ssh 测试失败：{err}"),
            checked_at,
        },
    }
}

fn load_ssh_alias_sources() -> Result<BTreeMap<String, SshAliasSource>, String> {
    let home_dir = home_dir_path()?;
    let config_path = home_dir.join(".ssh").join("config");
    if !config_path.exists() {
        return Ok(BTreeMap::new());
    }

    let mut visited_files: HashSet<PathBuf> = HashSet::new();
    let mut aliases: BTreeMap<String, SshAliasSource> = BTreeMap::new();
    collect_ssh_aliases_from_file(&config_path, &home_dir, &mut visited_files, &mut aliases)?;
    Ok(aliases)
}

fn delete_ssh_alias_from_config(alias: &str) -> Result<String, String> {
    let alias_sources = load_ssh_alias_sources()?;
    let source = alias_sources
        .get(alias)
        .ok_or_else(|| format!("未找到 SSH 快捷连接：{alias}"))?;
    let source_path = PathBuf::from(&source.source_file);
    if !source_path.exists() {
        return Err(format!("配置文件不存在：{}", source_path.display()));
    }

    let content = fs::read_to_string(&source_path)
        .map_err(|err| format!("读取 SSH 配置失败：{} ({err})", source_path.display()))?;
    let line_ending = if content.contains("\r\n") { "\r\n" } else { "\n" };
    let had_trailing_newline = content.ends_with('\n');
    let mut lines = content.lines().map(ToString::to_string).collect::<Vec<_>>();

    let removed_line_count = remove_ssh_alias_from_lines(&mut lines, alias)?;
    let mut next_content = lines.join(line_ending);
    if had_trailing_newline && !next_content.is_empty() {
        next_content.push_str(line_ending);
    }
    fs::write(&source_path, next_content)
        .map_err(|err| format!("写入 SSH 配置失败：{} ({err})", source_path.display()))?;

    Ok(format!(
        "已删除 SSH 快捷连接 {}（{}，移除 {} 行）",
        alias,
        source_path.display(),
        removed_line_count
    ))
}

fn remove_ssh_alias_from_lines(lines: &mut Vec<String>, alias: &str) -> Result<usize, String> {
    for idx in 0..lines.len() {
        let tokens = parse_ssh_line_tokens(&lines[idx]);
        if tokens.len() < 2 {
            continue;
        }
        if !tokens[0].eq_ignore_ascii_case("host") {
            continue;
        }

        if !tokens.iter().skip(1).any(|token| token == alias) {
            continue;
        }

        let mut block_end = idx + 1;
        while block_end < lines.len() {
            let next_tokens = parse_ssh_line_tokens(&lines[block_end]);
            if !next_tokens.is_empty() {
                let key = next_tokens[0].to_ascii_lowercase();
                if key == "host" || key == "match" {
                    break;
                }
            }
            block_end += 1;
        }

        let remaining = tokens
            .iter()
            .skip(1)
            .filter(|token| token.as_str() != alias)
            .cloned()
            .collect::<Vec<_>>();
        if remaining.is_empty() {
            let removed = block_end.saturating_sub(idx);
            lines.drain(idx..block_end);
            return Ok(removed);
        }

        let indent = lines[idx]
            .chars()
            .take_while(|ch| ch.is_whitespace())
            .collect::<String>();
        lines[idx] = format!("{indent}Host {}", remaining.join(" "));
        return Ok(1);
    }

    Err(format!("未在 SSH 配置中找到别名 {alias}"))
}

#[cfg(target_os = "macos")]
fn open_ssh_terminal_macos(alias: &str) -> Result<(), String> {
    let command = format!("ssh -- {}", shell_single_quote(alias));
    let escaped_command = command.replace('\\', "\\\\").replace('"', "\\\"");
    let status = Command::new("osascript")
        .arg("-e")
        .arg("tell application \"Terminal\" to activate")
        .arg("-e")
        .arg(format!(
            "tell application \"Terminal\" to do script \"{}\"",
            escaped_command
        ))
        .status()
        .map_err(|err| format!("启动 Terminal 失败：{err}"))?;

    if !status.success() {
        return Err("启动 Terminal 失败".to_string());
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn open_ssh_terminal_windows(alias: &str) -> Result<(), String> {
    let escaped = alias.replace('"', "\\\"");
    let ssh_command = format!("ssh -- \"{}\"", escaped);
    let status = Command::new("cmd")
        .args(["/C", "start", "", "cmd", "/K", &ssh_command])
        .status()
        .map_err(|err| format!("启动命令行失败：{err}"))?;

    if !status.success() {
        return Err("启动命令行失败".to_string());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_ssh_terminal_linux(alias: &str) -> Result<(), String> {
    let launchers: [(&str, Vec<&str>); 3] = [
        ("x-terminal-emulator", vec!["-e", "ssh", "--", alias]),
        ("gnome-terminal", vec!["--", "ssh", "--", alias]),
        ("konsole", vec!["-e", "ssh", "--", alias]),
    ];

    for (bin, args) in launchers {
        if Command::new(bin).args(args).spawn().is_ok() {
            return Ok(());
        }
    }

    Err("未找到可用终端程序，请手动执行 ssh <alias>".to_string())
}

fn normalize_pdd_login_request(request: PddLoginRequest) -> Result<PddLoginRequest, String> {
    let name = request.name.trim().to_string();
    let account = request.account.trim().to_string();
    let password = request.password;
    let app_id = request.app_id.trim().to_string();
    let login_url = if request.login_url.trim().is_empty() {
        PDD_DEFAULT_LOGIN_URL.to_string()
    } else {
        request.login_url.trim().to_string()
    };
    validate_pdd_host_url(&login_url)?;

    if name.is_empty() {
        return Err("名称不能为空".to_string());
    }
    if account.is_empty() {
        return Err("账号不能为空".to_string());
    }
    if password.trim().is_empty() {
        return Err("密码不能为空".to_string());
    }
    if app_id.is_empty() {
        return Err("应用 ID 不能为空".to_string());
    }
    if !app_id.chars().all(|ch| ch.is_ascii_digit()) {
        return Err("应用 ID 必须是数字".to_string());
    }

    Ok(PddLoginRequest {
        name,
        account,
        password,
        login_url,
        app_id,
        cookie_path: request.cookie_path.and_then(|item| {
            let normalized = item.trim();
            if normalized.is_empty() {
                None
            } else {
                Some(normalized.to_string())
            }
        }),
        ocr_key: request.ocr_key.and_then(|item| {
            let normalized = item.trim();
            if normalized.is_empty() {
                None
            } else {
                Some(normalized.to_string())
            }
        }),
    })
}

fn run_pdd_login_flow(request: PddLoginRequest) -> Result<PddLoginResponse, String> {
    let cookie_path = resolve_pdd_cookie_path(
        request.cookie_path.as_deref(),
        &request.name,
        &request.account,
    )?;
    let cookie_dir = cookie_path
        .parent()
        .ok_or_else(|| "无法解析 Cookie 目录".to_string())?;
    let captures_dir = cookie_dir.join("captures");
    let profile_dir = cookie_dir
        .join("profiles")
        .join(sanitize_path_segment(&format!(
            "{}-{}",
            request.name, request.account
        )));
    fs::create_dir_all(cookie_dir)
        .map_err(|err| format!("创建 Cookie 目录失败：{} ({err})", cookie_dir.display()))?;
    fs::create_dir_all(&profile_dir)
        .map_err(|err| format!("创建浏览器目录失败：{} ({err})", profile_dir.display()))?;
    fs::create_dir_all(&captures_dir)
        .map_err(|err| format!("创建调试目录失败：{} ({err})", captures_dir.display()))?;
    let login_log_path = captures_dir.join("rust_login_flow.log");
    append_pdd_login_log(
        &login_log_path,
        &format!(
            "[start] name={} account={} login_url={} app_id={} ocr_key={}",
            request.name,
            request.account,
            request.login_url,
            request.app_id,
            request.ocr_key.as_deref().unwrap_or("<empty>")
        ),
    );

    let chrome_binary = resolve_pdd_chrome_executable()?;
    let chromedriver_path = resolve_pdd_chromedriver_path()
        .ok_or_else(|| "未找到 chromedriver，请先安装或设置 CHROMEDRIVER_PATH".to_string())?;
    let port = reserve_local_port()?;
    let mut chromedriver = start_chromedriver_process(&chromedriver_path, port)?;
    append_pdd_login_log(
        &login_log_path,
        &format!(
            "[chromedriver] started path={} port={} profile={}",
            chromedriver_path,
            port,
            profile_dir.display()
        ),
    );
    let webdriver_base_url = format!("http://127.0.0.1:{port}");
    let wd_config = wait_and_create_webdriver_session(
        &webdriver_base_url,
        &chrome_binary,
        &profile_dir,
    )?;
    let wd = WdClient::new(wd_config)?;
    append_pdd_login_log(&login_log_path, "[webdriver] session created");
    let login_result = execute_pdd_login_flow_with_wd(&wd, &request, &captures_dir, &login_log_path);

    if login_result.is_err() {
        append_pdd_login_log(&login_log_path, "[cleanup] login failed, closing webdriver session");
        let _ = wd.delete_session();
    } else {
        append_pdd_login_log(
            &login_log_path,
            "[cleanup] login success, keep current browser window and skip session delete",
        );
    }
    let _ = chromedriver.kill();
    let _ = chromedriver.wait();

    match login_result {
        Ok(login_outcome) => {
            append_pdd_login_log(
                &login_log_path,
                &format!("[done] success message={}", login_outcome.message),
            );
            Ok(PddLoginResponse {
                cookie_path: cookie_path.display().to_string(),
                cookie_count: 0,
                saved_at: Utc::now().to_rfc3339(),
                message: login_outcome.message.clone(),
                login_url: request.login_url,
                account: request.account,
                owner_mall_list: login_outcome.owner_mall_list,
                capture_path: Some(login_outcome.capture_path.display().to_string()),
            })
        }
        Err(err) => {
            append_pdd_login_log(&login_log_path, &format!("[done] error={err}"));
            Err(err)
        }
    }
}

fn resolve_pdd_chromedriver_path() -> Option<String> {
    if let Ok(env_path) = env::var("CHROMEDRIVER_PATH") {
        let trimmed = env_path.trim();
        if !trimmed.is_empty() {
            let path = PathBuf::from(trimmed);
            if path.exists() {
                return Some(path.display().to_string());
            }
        }
    }

    let candidates = [
        "/opt/homebrew/bin/chromedriver",
        "/usr/local/bin/chromedriver",
        "/usr/bin/chromedriver",
        "/Users/spenceryg/Documents/taisheng/自动化流程/配置拼多多解密/bin/chromedriver-mac-arm64-146/chromedriver-mac-arm64/chromedriver",
    ];
    for path_text in candidates {
        let path = PathBuf::from(path_text);
        if path.exists() {
            return Some(path.display().to_string());
        }
    }
    None
}

fn resolve_pdd_chrome_executable() -> Result<String, String> {
    let mut candidates: Vec<String> = Vec::new();

    #[cfg(target_os = "macos")]
    {
        candidates.extend([
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".to_string(),
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge".to_string(),
            "/Applications/Chromium.app/Contents/MacOS/Chromium".to_string(),
        ]);
    }
    #[cfg(target_os = "windows")]
    {
        candidates.extend([
            "C:/Program Files/Google/Chrome/Application/chrome.exe".to_string(),
            "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe".to_string(),
            "C:/Program Files/Microsoft/Edge/Application/msedge.exe".to_string(),
            "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe".to_string(),
        ]);
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        candidates.extend([
            "/usr/bin/google-chrome".to_string(),
            "/usr/bin/google-chrome-stable".to_string(),
            "/usr/bin/chromium".to_string(),
            "/usr/bin/chromium-browser".to_string(),
            "/snap/bin/chromium".to_string(),
        ]);
    }

    for path_text in &candidates {
        let path = PathBuf::from(path_text);
        if path.exists() {
            return Ok(path.display().to_string());
        }
    }
    Err(format!(
        "未找到可用 Chrome/Chromium，可安装后重试。已检查：{}",
        candidates.join(", ")
    ))
}

fn reserve_local_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|err| format!("分配本地端口失败：{err}"))?;
    let port = listener
        .local_addr()
        .map_err(|err| format!("读取本地端口失败：{err}"))?
        .port();
    drop(listener);
    Ok(port)
}

fn start_chromedriver_process(chromedriver_path: &str, port: u16) -> Result<Child, String> {
    Command::new(chromedriver_path)
        .arg(format!("--port={port}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| format!("启动 chromedriver 失败：{err}"))
}

fn wait_and_create_webdriver_session(
    webdriver_base_url: &str,
    chrome_binary: &str,
    profile_dir: &Path,
) -> Result<PddWebDriverConfig, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|err| format!("初始化 WebDriver 客户端失败：{err}"))?;
    let status_url = format!("{}/status", webdriver_base_url.trim_end_matches('/'));
    let start = std::time::Instant::now();

    while start.elapsed() < Duration::from_secs(12) {
        if let Ok(resp) = client.get(&status_url).send() {
            if resp.status().is_success() {
                break;
            }
        }
        thread::sleep(Duration::from_millis(250));
    }

    let create_url = format!("{}/session", webdriver_base_url.trim_end_matches('/'));
    let capabilities = serde_json::json!({
        "browserName": "chrome",
        "goog:loggingPrefs": {
            "performance": "ALL"
        },
        "goog:chromeOptions": {
            "binary": chrome_binary,
            "excludeSwitches": ["enable-automation"],
            "useAutomationExtension": false,
            "detach": true,
            "perfLoggingPrefs": {
                "enableNetwork": true,
                "enablePage": false
            },
            "args": [
                format!("--user-data-dir={}", profile_dir.display()),
                "--disable-blink-features=AutomationControlled",
                "--window-size=1360,960",
                "--no-sandbox",
                "--disable-gpu"
            ]
        }
    });
    let body = serde_json::json!({
        "capabilities": {
            "alwaysMatch": capabilities
        }
    });
    let resp = client
        .post(&create_url)
        .json(&body)
        .send()
        .map_err(|err| format!("创建 WebDriver 会话失败：{err}"))?;
    let status = resp.status();
    let payload: Value = resp
        .json()
        .map_err(|err| format!("解析 WebDriver 会话响应失败：{err}"))?;
    if !status.is_success() {
        return Err(format!(
            "创建 WebDriver 会话失败：{}",
            extract_webdriver_error(&payload)
        ));
    }

    let session_id = payload
        .pointer("/value/sessionId")
        .and_then(Value::as_str)
        .or_else(|| payload.get("sessionId").and_then(Value::as_str))
        .ok_or_else(|| format!("WebDriver 会话响应缺少 sessionId: {payload}"))?
        .to_string();
    Ok(PddWebDriverConfig {
        webdriver_base_url: webdriver_base_url.trim_end_matches('/').to_string(),
        session_id,
    })
}

impl WdClient {
    fn new(config: PddWebDriverConfig) -> Result<Self, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|err| format!("初始化 WebDriver HTTP 客户端失败：{err}"))?;
        Ok(Self {
            client,
            base_url: config.webdriver_base_url,
            session_id: config.session_id,
        })
    }

    fn send_raw(
        &self,
        method: &str,
        endpoint: &str,
        body: Option<&Value>,
    ) -> Result<(StatusCode, Value), String> {
        let mut builder = match method {
            "GET" => self.client.get(endpoint),
            "POST" => self.client.post(endpoint),
            "DELETE" => self.client.delete(endpoint),
            _ => return Err(format!("不支持的 WebDriver 方法：{method}")),
        };
        if let Some(payload) = body {
            builder = builder.json(payload);
        }
        let response = builder
            .send()
            .map_err(|err| format!("WebDriver 请求失败：{endpoint} ({err})"))?;
        let status = response.status();
        let payload: Value = response
            .json()
            .map_err(|err| format!("WebDriver 响应解析失败：{endpoint} ({err})"))?;
        Ok((status, payload))
    }

    fn endpoint(&self, sub_path: &str) -> String {
        format!(
            "{}/session/{}/{}",
            self.base_url,
            self.session_id,
            sub_path.trim_start_matches('/')
        )
    }

    fn command(&self, method: &str, sub_path: &str, body: Option<Value>) -> Result<Value, String> {
        let url = self.endpoint(sub_path);
        let (status, payload) = self.send_raw(method, &url, body.as_ref())?;
        if !status.is_success() {
            return Err(format!("WebDriver 命令失败：{}", extract_webdriver_error(&payload)));
        }
        Ok(payload.get("value").cloned().unwrap_or(Value::Null))
    }

    fn delete_session(&self) -> Result<(), String> {
        let url = format!("{}/session/{}", self.base_url, self.session_id);
        let (status, payload) = self.send_raw("DELETE", &url, None)?;
        if !status.is_success() {
            return Err(format!(
                "关闭 WebDriver 会话失败：{}",
                extract_webdriver_error(&payload)
            ));
        }
        Ok(())
    }

    fn navigate(&self, url: &str) -> Result<(), String> {
        self.command("POST", "url", Some(serde_json::json!({ "url": url })))
            .map(|_| ())
    }

    fn current_url(&self) -> Result<String, String> {
        self.command("GET", "url", None)?
            .as_str()
            .map(|item| item.to_string())
            .ok_or_else(|| "读取当前页面 URL 失败".to_string())
    }

    fn execute_script(&self, script: &str, args: Vec<Value>) -> Result<Value, String> {
        self.command(
            "POST",
            "execute/sync",
            Some(serde_json::json!({
                "script": script,
                "args": args
            })),
        )
    }

    fn execute_cdp(&self, cmd: &str, params: Value) -> Result<Value, String> {
        self.command(
            "POST",
            "goog/cdp/execute",
            Some(serde_json::json!({
                "cmd": cmd,
                "params": params
            })),
        )
    }

    fn find_element(&self, using: &str, value: &str) -> Result<Option<String>, String> {
        let url = self.endpoint("element");
        let body = serde_json::json!({
            "using": using,
            "value": value
        });
        let (status, payload) = self.send_raw("POST", &url, Some(&body))?;
        if status.is_success() {
            let value = payload.get("value").cloned().unwrap_or(Value::Null);
            return extract_element_id(&value)
                .map(Some)
                .ok_or_else(|| format!("WebDriver element 响应缺少元素 ID: {payload}"));
        }

        let error = payload
            .pointer("/value/error")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if error == "no such element" {
            return Ok(None);
        }
        Err(format!("查找元素失败：{}", extract_webdriver_error(&payload)))
    }

    fn element_displayed(&self, element_id: &str) -> Result<bool, String> {
        self.command("GET", &format!("element/{element_id}/displayed"), None)?
            .as_bool()
            .ok_or_else(|| "读取元素可见状态失败".to_string())
    }

    fn element_click(&self, element_id: &str) -> Result<(), String> {
        self.command(
            "POST",
            &format!("element/{element_id}/click"),
            Some(serde_json::json!({})),
        )
        .map(|_| ())
    }

    fn element_clear(&self, element_id: &str) -> Result<(), String> {
        self.command(
            "POST",
            &format!("element/{element_id}/clear"),
            Some(serde_json::json!({})),
        )
        .map(|_| ())
    }

    fn element_send_keys(&self, element_id: &str, text: &str) -> Result<(), String> {
        let value = text.chars().map(|ch| ch.to_string()).collect::<Vec<_>>();
        self.command(
            "POST",
            &format!("element/{element_id}/value"),
            Some(serde_json::json!({
                "text": text,
                "value": value
            })),
        )
        .map(|_| ())
    }

    fn element_rect(&self, element_id: &str) -> Result<WdElementRect, String> {
        let rect = self.command("GET", &format!("element/{element_id}/rect"), None)?;
        let width = rect
            .get("width")
            .and_then(Value::as_f64)
            .ok_or_else(|| "读取元素宽度失败".to_string())?;
        Ok(WdElementRect { width })
    }

    fn element_screenshot_png(&self, element_id: &str) -> Result<Vec<u8>, String> {
        let value = self.command("GET", &format!("element/{element_id}/screenshot"), None)?;
        let b64 = value
            .as_str()
            .ok_or_else(|| "读取元素截图失败".to_string())?;
        BASE64_STANDARD
            .decode(b64.as_bytes())
            .map_err(|err| format!("解码元素截图失败：{err}"))
    }

    fn perform_actions(&self, actions: Value) -> Result<(), String> {
        self.command("POST", "actions", Some(actions)).map(|_| ())?;
        let _ = self.command("DELETE", "actions", None);
        Ok(())
    }

    fn window_handles(&self) -> Result<Vec<String>, String> {
        let value = self.command("GET", "window/handles", None)?;
        let arr = value
            .as_array()
            .ok_or_else(|| "读取窗口句柄失败".to_string())?;
        Ok(arr
            .iter()
            .filter_map(Value::as_str)
            .map(|item| item.to_string())
            .collect::<Vec<_>>())
    }

    fn switch_to_window(&self, handle: &str) -> Result<(), String> {
        self.command(
            "POST",
            "window",
            Some(serde_json::json!({
                "handle": handle
            })),
        )
        .map(|_| ())
    }
}

fn extract_element_id(value: &Value) -> Option<String> {
    value
        .get("element-6066-11e4-a52e-4f735466cecf")
        .and_then(Value::as_str)
        .or_else(|| value.get("ELEMENT").and_then(Value::as_str))
        .map(|item| item.to_string())
}

fn extract_webdriver_error(payload: &Value) -> String {
    payload
        .pointer("/value/message")
        .and_then(Value::as_str)
        .or_else(|| payload.get("message").and_then(Value::as_str))
        .unwrap_or("未知 WebDriver 错误")
        .to_string()
}

#[derive(Debug, Clone)]
struct PddPageCaptureResult {
    capture_path: PathBuf,
    owner_mall_list: Vec<PddOwnerMallItem>,
}

#[derive(Debug, Clone)]
struct PddLoginOutcome {
    message: String,
    capture_path: PathBuf,
    owner_mall_list: Vec<PddOwnerMallItem>,
}

fn execute_pdd_login_flow_with_wd(
    wd: &WdClient,
    request: &PddLoginRequest,
    captures_dir: &Path,
    login_log_path: &Path,
) -> Result<PddLoginOutcome, String> {
    append_pdd_login_log(login_log_path, "[flow] begin");
    align_to_first_window(wd, login_log_path)?;
    ensure_navigate_to_url(wd, &request.login_url, Duration::from_secs(20))?;
    append_pdd_login_log(
        login_log_path,
        &format!("[flow] navigated login current={}", wd.current_url().unwrap_or_default()),
    );
    thread::sleep(Duration::from_millis(800));

    let mut already_logged_in = false;
    if wd.current_url()?.to_lowercase().contains("open.pinduoduo.com") {
        already_logged_in = !has_home_login_button(wd)?;
    }
    append_pdd_login_log(
        login_log_path,
        &format!("[flow] already_logged_in={already_logged_in}"),
    );

    if !already_logged_in {
        let state = ensure_login_form_ready(wd)?;
        if state {
            already_logged_in = true;
        } else {
            fill_credentials(wd, &request.account, &request.password)?;
            click_login_button(wd)?;
            thread::sleep(Duration::from_millis(1200));
            let slider_result = handle_slider_if_needed(
                wd,
                captures_dir,
                request.ocr_key.as_deref(),
                3,
                120,
            )?;
            append_pdd_login_log(
                login_log_path,
                &format!(
                    "[flow] slider required={} solved={} error={}",
                    slider_result.required,
                    slider_result.solved,
                    slider_result.error.clone().unwrap_or_default()
                ),
            );
            if slider_result.required && !slider_result.solved {
                return Err(format!(
                    "滑块验证码未通过: {}",
                    slider_result
                        .error
                        .unwrap_or_else(|| "自动与人工滑块均未通过".to_string())
                ));
            }
        }
    }

    if !wait_for_login_success(
        wd,
        Duration::from_millis(PDD_LOGIN_TIMEOUT_MS),
        &request.login_url,
    )? {
        return Err(
            "等待登录成功超时：右上角“登录”按钮仍存在，请先完成滑块并确认登录".to_string(),
        );
    }

    install_target_api_capture_hook(wd, PDD_OWNER_PAGE_API_URL)?;
    append_pdd_login_log(
        login_log_path,
        &format!("[flow] browser request hook installed target={PDD_OWNER_PAGE_API_URL}"),
    );

    let detail_url = build_pdd_auth_manage_detail_url(&request.app_id)?;
    ensure_navigate_to_url(wd, &detail_url, Duration::from_secs(20))?;
    append_pdd_login_log(
        login_log_path,
        &format!(
            "[flow] navigated detail current={} target={}",
            wd.current_url().unwrap_or_default(),
            detail_url
        ),
    );
    thread::sleep(Duration::from_millis(1400));

    let capture_result = capture_page_api_data_on_detail_page(
        wd,
        captures_dir,
        login_log_path,
        Duration::from_millis(PDD_PAGE_CAPTURE_TIMEOUT_MS),
    )?;
    append_pdd_login_log(
        login_log_path,
        &format!(
            "[flow] page_api_saved={} mall_count={}",
            capture_result.capture_path.display(),
            capture_result.owner_mall_list.len()
        ),
    );

    let prefix = if already_logged_in {
        "检测到已登录，已进入授权详情并抓取店铺列表"
    } else {
        "登录成功，已进入授权详情并抓取店铺列表"
    };
    let message = format!(
        "{prefix}，共 {} 个店铺，保存文件：{}",
        capture_result.owner_mall_list.len(),
        capture_result.capture_path.display()
    );
    Ok(PddLoginOutcome {
        message,
        capture_path: capture_result.capture_path,
        owner_mall_list: capture_result.owner_mall_list,
    })
}

fn align_to_first_window(wd: &WdClient, login_log_path: &Path) -> Result<(), String> {
    let handles = wd.window_handles()?;
    append_pdd_login_log(
        login_log_path,
        &format!("[window] handles={}", handles.join(",")),
    );
    if let Some(first) = handles.first() {
        wd.switch_to_window(first)?;
        append_pdd_login_log(login_log_path, &format!("[window] switched={first}"));
    }
    Ok(())
}

#[derive(Debug)]
struct SliderHandleResult {
    required: bool,
    solved: bool,
    error: Option<String>,
}

fn handle_slider_if_needed(
    wd: &WdClient,
    captures_dir: &Path,
    ocr_key: Option<&str>,
    auto_slider_retries: usize,
    manual_slider_timeout_sec: u64,
) -> Result<SliderHandleResult, String> {
    if !is_slider_present(wd)? {
        return Ok(SliderHandleResult {
            required: false,
            solved: true,
            error: None,
        });
    }

    let mut last_error: Option<String> = None;
    if let Some(key) = ocr_key.filter(|item| !item.trim().is_empty()) {
        for attempt in 1..=auto_slider_retries {
            match solve_slider_once(wd, attempt, captures_dir, key.trim()) {
                Ok(_) => {
                    if !is_slider_present(wd)? {
                        return Ok(SliderHandleResult {
                            required: true,
                            solved: true,
                            error: None,
                        });
                    }
                }
                Err(err) => {
                    last_error = Some(err);
                }
            }
            click_slider_refresh_if_exists(wd);
            thread::sleep(Duration::from_millis(1000));
        }
    }

    let wait_deadline = std::time::Instant::now() + Duration::from_secs(manual_slider_timeout_sec);
    while std::time::Instant::now() < wait_deadline {
        if !is_slider_present(wd)? {
            return Ok(SliderHandleResult {
                required: true,
                solved: true,
                error: last_error,
            });
        }
        thread::sleep(Duration::from_millis(500));
    }

    Ok(SliderHandleResult {
        required: true,
        solved: false,
        error: last_error,
    })
}

fn solve_slider_once(
    wd: &WdClient,
    attempt: usize,
    captures_dir: &Path,
    ocr_key: &str,
) -> Result<(), String> {
    let bg_id = find_visible(
        wd,
        &[("css selector", ".slider-img-bg")],
        Duration::from_secs(8),
    )?
    .ok_or_else(|| "未找到滑块背景图".to_string())?;
    let item_id = find_visible(wd, &[("css selector", ".slider-item")], Duration::from_secs(8))?
        .ok_or_else(|| "未找到滑块拼图".to_string())?;
    let handle_id = find_visible(
        wd,
        &[("css selector", "#slide-button")],
        Duration::from_secs(8),
    )?
    .ok_or_else(|| "未找到滑块按钮".to_string())?;

    let image_png = wd.element_screenshot_png(&bg_id)?;
    let shot_path = captures_dir.join(format!("slider_bg_attempt_{attempt}.png"));
    fs::write(&shot_path, &image_png)
        .map_err(|err| format!("写入滑块截图失败：{} ({err})", shot_path.display()))?;

    let ocr_result = call_slider_ocr(&image_png, ocr_key)?;
    let verify_distance = parse_first_number(&ocr_result)
        .ok_or_else(|| format!("OCR 无法提取距离：{ocr_result}"))?;
    let dom_bg_width = wd.element_rect(&bg_id)?.width;
    let dom_item_width = wd.element_rect(&item_id)?.width;
    if dom_bg_width <= 0.0 {
        return Err("无法获取滑块背景宽度".to_string());
    }

    let image = image::load_from_memory(&image_png)
        .map_err(|err| format!("解析滑块截图图片失败：{err}"))?;
    let image_width = image.width() as f64;
    let scale = image_width / dom_bg_width;
    let verify_scaled = verify_distance / scale;
    let move_distance = verify_scaled - (dom_item_width / 2.0);

    drag_slider(wd, &handle_id, move_distance)?;
    thread::sleep(Duration::from_millis(1600));

    let debug = serde_json::json!({
        "verify_code_raw": verify_distance,
        "verify_code_scaled": verify_scaled,
        "move_distance": move_distance,
        "dom_bg_width": dom_bg_width,
        "dom_item_width": dom_item_width,
        "image_width": image_width,
        "scale": scale,
        "ocr_raw": ocr_result
    });
    let debug_path = captures_dir.join(format!("slider_debug_attempt_{attempt}.json"));
    let mut writer = fs::File::create(&debug_path)
        .map_err(|err| format!("写入滑块调试文件失败：{} ({err})", debug_path.display()))?;
    writer
        .write_all(
            serde_json::to_string_pretty(&debug)
                .map_err(|err| format!("序列化滑块调试数据失败：{err}"))?
                .as_bytes(),
        )
        .map_err(|err| format!("写入滑块调试数据失败：{} ({err})", debug_path.display()))?;
    Ok(())
}

fn call_slider_ocr(image_png: &[u8], ocr_key: &str) -> Result<String, String> {
    let image_b64 = BASE64_STANDARD.encode(image_png);
    let body = serde_json::json!({
        "key": ocr_key,
        "verify_idf_id": PDD_DEFAULT_VERIFY_IDF_ID,
        "img_base64": format!("data:image/png;base64,{image_b64}"),
        "words": ""
    });
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|err| format!("初始化 OCR 客户端失败：{err}"))?;
    let response = client
        .post(PDD_DEFAULT_OCR_URL)
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .map_err(|err| format!("请求 OCR 服务失败：{err}"))?;
    let status = response.status();
    let payload: Value = response
        .json()
        .map_err(|err| format!("解析 OCR 响应失败：{err}"))?;
    if !status.is_success() {
        return Err(format!(
            "OCR 服务返回异常 HTTP {}: {}",
            status.as_u16(),
            payload
        ));
    }
    let code = payload.get("code").and_then(Value::as_i64).unwrap_or_default();
    if code != 200 {
        return Err(format!("OCR 识别失败: {payload}"));
    }
    let res_str = payload
        .pointer("/data/res_str")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("OCR 响应缺少 data.res_str: {payload}"))?;
    Ok(res_str.to_string())
}

fn parse_first_number(text: &str) -> Option<f64> {
    let mut token = String::new();
    let mut started = false;
    let mut dot_seen = false;
    for ch in text.chars() {
        if !started {
            if ch == '-' || ch.is_ascii_digit() {
                started = true;
                token.push(ch);
            }
            continue;
        }
        if ch.is_ascii_digit() {
            token.push(ch);
            continue;
        }
        if ch == '.' && !dot_seen {
            dot_seen = true;
            token.push(ch);
            continue;
        }
        break;
    }
    if token.is_empty() || token == "-" || token == "." || token == "-." {
        return None;
    }
    token.parse::<f64>().ok()
}

fn drag_slider(wd: &WdClient, handle_id: &str, move_distance: f64) -> Result<(), String> {
    let track = build_drag_track(move_distance);
    let mut pointer_actions = vec![
        serde_json::json!({
            "type": "pointerMove",
            "duration": 0,
            "origin": {
                "element-6066-11e4-a52e-4f735466cecf": handle_id
            },
            "x": 0,
            "y": 0
        }),
        serde_json::json!({
            "type": "pointerDown",
            "button": 0
        }),
        serde_json::json!({
            "type": "pause",
            "duration": 120
        }),
    ];
    for (idx, step) in track.iter().enumerate() {
        let y = match idx % 3 {
            0 => 0,
            1 => 1,
            _ => -1,
        };
        pointer_actions.push(serde_json::json!({
            "type": "pointerMove",
            "duration": 26,
            "origin": "pointer",
            "x": step,
            "y": y
        }));
    }
    pointer_actions.push(serde_json::json!({
        "type": "pointerMove",
        "duration": 40,
        "origin": "pointer",
        "x": 1,
        "y": 0
    }));
    pointer_actions.push(serde_json::json!({
        "type": "pointerUp",
        "button": 0
    }));

    wd.perform_actions(serde_json::json!({
        "actions": [{
            "type": "pointer",
            "id": "mouse",
            "parameters": {"pointerType":"mouse"},
            "actions": pointer_actions
        }]
    }))
}

fn build_drag_track(move_distance: f64) -> Vec<i32> {
    let total = move_distance.max(5.0);
    let mut track = Vec::new();
    let mut current = 0.0;
    while current < total {
        let ratio = if total > 0.0 { current / total } else { 1.0 };
        let max_step = if ratio < 0.55 {
            7.0
        } else if ratio < 0.85 {
            4.0
        } else {
            2.0
        };
        let remaining = total - current;
        let step = remaining.min(max_step);
        let step_int = step.round() as i32;
        if step_int <= 0 {
            break;
        }
        track.push(step_int);
        current += step_int as f64;
    }
    let correction = (total - current).round() as i32;
    if correction != 0 {
        track.push(correction);
    }
    if track.is_empty() {
        track.push(total.round().max(1.0) as i32);
    }
    track
}

fn is_slider_present(wd: &WdClient) -> Result<bool, String> {
    if let Some(element_id) = wd.find_element("css selector", "#slide-captcha-dialog")? {
        return wd.element_displayed(&element_id);
    }
    Ok(false)
}

fn click_slider_refresh_if_exists(wd: &WdClient) {
    let selectors = [
        "#slide-captcha-dialog .captcha-refresh",
        "#slide-captcha-dialog .captcha-refresh img",
    ];
    for selector in selectors {
        if let Ok(Some(element_id)) = wd.find_element("css selector", selector) {
            if wd.element_displayed(&element_id).unwrap_or(false) {
                let _ = wd.element_click(&element_id);
                return;
            }
        }
    }
}

fn wait_for_login_success(wd: &WdClient, timeout: Duration, home_url: &str) -> Result<bool, String> {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if detect_logged_in_on_home(wd, home_url)? {
            return Ok(true);
        }
        thread::sleep(Duration::from_millis(1200));
    }
    Ok(false)
}

fn detect_logged_in_on_home(wd: &WdClient, home_url: &str) -> Result<bool, String> {
    let current = wd.current_url()?.to_lowercase();
    if !current.contains("open.pinduoduo.com") {
        ensure_navigate_to_url(wd, home_url, Duration::from_secs(20))?;
        thread::sleep(Duration::from_millis(800));
    }
    Ok(!has_home_login_button(wd)?)
}

fn ensure_navigate_to_url(wd: &WdClient, target_url: &str, timeout: Duration) -> Result<(), String> {
    let start = std::time::Instant::now();
    let target_host = extract_url_host(target_url);
    let mut last_url = String::new();
    let mut last_err = String::new();

    while start.elapsed() < timeout {
        if let Err(err) = wd.navigate(target_url) {
            last_err = err;
        }
        thread::sleep(Duration::from_millis(700));

        match wd.current_url() {
            Ok(current) => {
                last_url = current.clone();
                if url_matches_target(&current, target_url, target_host.as_deref()) {
                    return Ok(());
                }

                // Force location on same tab when standard navigate is ignored.
                let _ = wd.execute_script(
                    "window.location.href = arguments[0]; return window.location.href;",
                    vec![Value::String(target_url.to_string())],
                );
                thread::sleep(Duration::from_millis(700));
                if let Ok(current2) = wd.current_url() {
                    last_url = current2.clone();
                    if url_matches_target(&current2, target_url, target_host.as_deref()) {
                        return Ok(());
                    }
                }
            }
            Err(err) => {
                last_err = err;
            }
        }
    }

    let err_suffix = if last_err.is_empty() {
        String::new()
    } else {
        format!("，最后错误：{last_err}")
    };
    Err(format!(
        "浏览器未能跳转到目标地址：{target_url}，当前地址：{}{}",
        if last_url.is_empty() { "<unknown>" } else { &last_url },
        err_suffix
    ))
}

fn append_pdd_login_log(path: &Path, line: &str) {
    let now = Utc::now().to_rfc3339();
    let text = format!("{now} {line}\n");
    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = file.write_all(text.as_bytes());
    }
}

fn extract_url_host(url_text: &str) -> Option<String> {
    url::Url::parse(url_text)
        .ok()
        .and_then(|parsed| parsed.host_str().map(|host| host.to_ascii_lowercase()))
}

fn url_matches_target(current_url: &str, target_url: &str, target_host: Option<&str>) -> bool {
    if current_url.eq_ignore_ascii_case(target_url) {
        return true;
    }
    if let Some(host) = target_host {
        if let Ok(parsed_current) = url::Url::parse(current_url) {
            if let Some(current_host) = parsed_current.host_str() {
                if current_host.eq_ignore_ascii_case(host) {
                    return true;
                }
            }
        }
    }
    false
}

fn has_home_login_button(wd: &WdClient) -> Result<bool, String> {
    let script = r#"
const topAreaSelectors = [
  'div[class*="user-info_login_btn"]',
  'div[class*="user-info"] [class*="login"]',
  'div[class*="login_btn"]'
];
const isVisible = (el) => {
  if (!el) return false;
  const rect = el.getBoundingClientRect();
  const style = window.getComputedStyle(el);
  return (
    rect.width > 0 &&
    rect.height > 0 &&
    style.display !== "none" &&
    style.visibility !== "hidden" &&
    style.opacity !== "0"
  );
};

for (const selector of topAreaSelectors) {
  const nodes = Array.from(document.querySelectorAll(selector));
  for (const node of nodes) {
    if (!isVisible(node)) continue;
    const txt = (node.textContent || "").trim();
    if (!txt || txt.includes("登录")) return true;
  }
}

const topContainers = Array.from(
  document.querySelectorAll("header,[class*='header'],[class*='top'],[class*='nav']")
);
for (const container of topContainers) {
  if (!isVisible(container)) continue;
  const node = Array.from(container.querySelectorAll("a,button,div,span")).find((item) => {
    return (item.textContent || "").trim() === "登录" && isVisible(item);
  });
  if (node) return true;
}

return false;
"#;
    Ok(wd.execute_script(script, Vec::new())?.as_bool().unwrap_or(true))
}

fn ensure_login_form_ready(wd: &WdClient) -> Result<bool, String> {
    if wait_login_form(wd, Duration::from_secs(2))? {
        return Ok(false);
    }

    let entry_locators = [
        ("css selector", r#"div[class*="user-info_login_btn"]"#),
        ("css selector", r#"div[class*="login_btn"]"#),
        ("xpath", r#"//a[normalize-space()='登录']"#),
        ("xpath", r#"//button[contains(normalize-space(.),'登录')]"#),
        ("css selector", ".login-btn"),
        ("css selector", ".header-login"),
    ];
    if let Some(entry_id) = find_visible(wd, &entry_locators, Duration::from_secs(4))? {
        let _ = wd.element_click(&entry_id);
    }

    if wait_login_form(wd, Duration::from_secs(8))? {
        return Ok(false);
    }
    if !has_home_login_button(wd)? {
        return Ok(true);
    }
    Err("未找到登录表单，请确认页面存在“登录入口”并可正常打开登录弹窗".to_string())
}

fn wait_login_form(wd: &WdClient, timeout: Duration) -> Result<bool, String> {
    let account_locators = [
        ("xpath", r#"//input[@placeholder='请输入账号']"#),
        ("xpath", r#"//input[contains(@placeholder,'账号')]"#),
        ("xpath", r#"//input[contains(@placeholder,'手机')]"#),
        ("xpath", r#"//input[contains(@placeholder,'用户名')]"#),
        ("css selector", "input[name*='user']"),
        ("css selector", "input[name*='account']"),
        ("css selector", "input[type='text']"),
    ];
    Ok(find_visible(wd, &account_locators, timeout)?.is_some())
}

fn fill_credentials(wd: &WdClient, account: &str, password: &str) -> Result<(), String> {
    let account_locators = [
        ("xpath", r#"//input[@placeholder='请输入账号']"#),
        ("xpath", r#"//input[contains(@placeholder,'账号')]"#),
        ("xpath", r#"//input[contains(@placeholder,'手机')]"#),
        ("xpath", r#"//input[contains(@placeholder,'用户名')]"#),
        ("css selector", "input[name*='user']"),
        ("css selector", "input[name*='account']"),
        ("css selector", "input[type='text']"),
    ];
    let password_locators = [
        ("xpath", r#"//input[@placeholder='请输入密码']"#),
        ("css selector", "input[type='password']"),
        ("xpath", r#"//input[contains(@placeholder,'密码')]"#),
        ("css selector", "input[name*='pass']"),
    ];
    let account_id = find_visible(wd, &account_locators, Duration::from_secs(10))?
        .ok_or_else(|| "未找到账号输入框".to_string())?;
    let password_id = find_visible(wd, &password_locators, Duration::from_secs(10))?
        .ok_or_else(|| "未找到密码输入框".to_string())?;
    wd.element_clear(&account_id)?;
    wd.element_send_keys(&account_id, account)?;
    wd.element_clear(&password_id)?;
    wd.element_send_keys(&password_id, password)?;
    Ok(())
}

fn click_login_button(wd: &WdClient) -> Result<(), String> {
    let login_locators = [
        ("css selector", "button[type='submit']"),
        ("xpath", r#"//button[contains(normalize-space(.),'立即登录')]"#),
        ("xpath", r#"//button[contains(normalize-space(.),'登录')]"#),
        ("css selector", ".login-btn"),
        ("css selector", ".submit-btn"),
    ];
    let button_id = find_visible(wd, &login_locators, Duration::from_secs(5))?
        .ok_or_else(|| "未找到登录按钮".to_string())?;
    wd.element_click(&button_id)?;
    Ok(())
}

fn build_pdd_auth_manage_detail_url(app_id: &str) -> Result<String, String> {
    let mut parsed = url::Url::parse(PDD_AUTH_MANAGE_DETAIL_BASE_URL)
        .map_err(|err| format!("授权管理详情 URL 配置错误：{err}"))?;
    parsed.query_pairs_mut().append_pair("id", app_id);
    Ok(parsed.to_string())
}

fn capture_page_api_data_on_detail_page(
    wd: &WdClient,
    captures_dir: &Path,
    login_log_path: &Path,
    timeout: Duration,
) -> Result<PddPageCaptureResult, String> {
    let record = wait_for_target_api_record_from_page_hook(wd, PDD_OWNER_PAGE_API_URL, timeout)?;
    let request_url = record
        .get("url")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let status = record
        .get("status")
        .and_then(Value::as_u64)
        .unwrap_or_default() as u16;
    let body_text = record
        .get("responseBody")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if body_text.trim().is_empty() {
        return Err("监听到目标接口请求，但响应体为空".to_string());
    }
    let parsed_body: Value = serde_json::from_str(&body_text).unwrap_or_else(|_| {
        serde_json::json!({
            "raw": body_text
        })
    });
    let owner_mall_list = extract_owner_mall_list(&parsed_body);

    append_pdd_login_log(
        login_log_path,
        &format!(
            "[capture] matched target url={} status={} ownerMallListCount={}",
            request_url,
            status,
            owner_mall_list.len()
        ),
    );

    let now = Utc::now();
    let output_path = captures_dir.join(format!(
        "page_api_capture_{}.json",
        now.format("%Y%m%d_%H%M%S")
    ));
    let payload = serde_json::json!({
        "capturedAt": now.to_rfc3339(),
        "currentUrl": wd.current_url().unwrap_or_default(),
        "targetApiUrl": PDD_OWNER_PAGE_API_URL,
        "request": {
            "url": request_url,
            "status": status,
            "record": record
        },
        "response": parsed_body,
        "ownerMallList": owner_mall_list
    });
    fs::write(
        &output_path,
        serde_json::to_string_pretty(&payload)
            .map_err(|err| format!("序列化 page 接口数据失败：{err}"))?,
    )
    .map_err(|err| format!("写入 page 接口数据失败：{} ({err})", output_path.display()))?;
    Ok(PddPageCaptureResult {
        capture_path: output_path,
        owner_mall_list,
    })
}

fn install_target_api_capture_hook(wd: &WdClient, target_url: &str) -> Result<(), String> {
    let target_lower = target_url.to_ascii_lowercase();
    let target_literal = serde_json::to_string(&target_lower)
        .map_err(|err| format!("序列化目标 URL 失败：{err}"))?;
    let source = format!(
        r#"
(() => {{
  const KEY = "__spPddTargetCaptureV1";
  const TARGET = {target_literal};
  const CLIP = (value, maxLen = 1000000) => {{
    if (value === null || value === undefined) return "";
    const text = String(value);
    return text.length > maxLen ? `${{text.slice(0, maxLen)}}...[truncated]` : text;
  }};
  const shouldCapture = (url) => String(url || "").toLowerCase().startsWith(TARGET);
  const now = () => new Date().toISOString();

  const state = {{
    installed: true,
    seq: 0,
    records: [],
    push(record) {{
      if (!shouldCapture(record.url)) return;
      this.records.push(record);
      if (this.records.length > 300) {{
        this.records.splice(0, this.records.length - 300);
      }}
    }}
  }};
  window[KEY] = state;

  if (!window.__spPddFetchPatchedV1 && window.fetch) {{
    const originFetch = window.fetch.bind(window);
    window.fetch = async function(input, init) {{
      const startedAt = Date.now();
      const reqUrl =
        typeof input === "string"
          ? input
          : (input && input.url) || "";
      const reqMethod =
        (init && init.method) ||
        (input && input.method) ||
        "GET";
      const reqBody = CLIP(init && init.body ? init.body : "");
      try {{
        const resp = await originFetch(input, init);
        let respBody = "";
        try {{
          respBody = CLIP(await resp.clone().text());
        }} catch (err) {{
          respBody = "";
        }}
        state.push({{
          id: ++state.seq,
          type: "fetch",
          url: CLIP(resp.url || reqUrl, 4000),
          method: CLIP(reqMethod, 20),
          status: Number(resp.status || 0),
          requestBody: reqBody,
          responseBody: respBody,
          capturedAt: now(),
          durationMs: Date.now() - startedAt
        }});
        return resp;
      }} catch (err) {{
        state.push({{
          id: ++state.seq,
          type: "fetch",
          url: CLIP(reqUrl, 4000),
          method: CLIP(reqMethod, 20),
          status: 0,
          requestBody: reqBody,
          responseBody: "",
          capturedAt: now(),
          error: CLIP(err && err.message ? err.message : String(err), 500)
        }});
        throw err;
      }}
    }};
    window.__spPddFetchPatchedV1 = true;
  }}

  if (!XMLHttpRequest.prototype.__spPddPatchedV1) {{
    const originOpen = XMLHttpRequest.prototype.open;
    const originSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function(method, url) {{
      this.__spPddMethod = method || "GET";
      this.__spPddUrl = url || "";
      return originOpen.apply(this, arguments);
    }};
    XMLHttpRequest.prototype.send = function(body) {{
      const xhr = this;
      const startedAt = Date.now();
      const requestBody = CLIP(body || "");
      const onReady = function() {{
        if (xhr.readyState !== 4) return;
        let responseBody = "";
        try {{
          responseBody = CLIP(xhr.responseText || "");
        }} catch (err) {{
          responseBody = "";
        }}
        state.push({{
          id: ++state.seq,
          type: "xhr",
          url: CLIP(xhr.responseURL || xhr.__spPddUrl || "", 4000),
          method: CLIP(xhr.__spPddMethod || "GET", 20),
          status: Number(xhr.status || 0),
          requestBody,
          responseBody,
          capturedAt: now(),
          durationMs: Date.now() - startedAt
        }});
        xhr.removeEventListener("readystatechange", onReady);
      }};
      xhr.addEventListener("readystatechange", onReady);
      return originSend.apply(this, arguments);
    }};
    XMLHttpRequest.prototype.__spPddPatchedV1 = true;
  }}
}})();
"#
    );
    let _ = wd.execute_cdp("Page.enable", serde_json::json!({}));
    wd.execute_cdp(
        "Page.addScriptToEvaluateOnNewDocument",
        serde_json::json!({ "source": source }),
    )?;
    Ok(())
}

fn wait_for_target_api_record_from_page_hook(
    wd: &WdClient,
    target_url: &str,
    timeout: Duration,
) -> Result<Value, String> {
    let script = r#"
const target = String(arguments[0] || "").toLowerCase();
const state = window.__spPddTargetCaptureV1;
if (!state || !Array.isArray(state.records)) {
  return [];
}
return state.records
  .filter((item) => String(item.url || "").toLowerCase().startsWith(target))
  .slice(-20);
"#;
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        let value = wd.execute_script(script, vec![Value::String(target_url.to_string())])?;
        if let Some(records) = value.as_array() {
            if records.is_empty() {
                thread::sleep(Duration::from_millis(400));
                continue;
            }
            if let Some(record) = records.iter().rev().find(|item| {
                item.get("responseBody")
                    .and_then(Value::as_str)
                    .map(|body| !body.trim().is_empty())
                    .unwrap_or(false)
            }) {
                return Ok(record.clone());
            }
            if let Some(last) = records.last() {
                return Ok(last.clone());
            }
        }
        thread::sleep(Duration::from_millis(800));
    }
    Err(format!(
        "进入详情页后未监听到目标接口响应：{target_url}"
    ))
}

fn extract_owner_mall_list(payload: &Value) -> Vec<PddOwnerMallItem> {
    let mut result: Vec<PddOwnerMallItem> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    collect_owner_mall_items(payload, &mut result, &mut seen);
    result
}

fn collect_owner_mall_items(
    node: &Value,
    result: &mut Vec<PddOwnerMallItem>,
    seen: &mut HashSet<String>,
) {
    match node {
        Value::Object(map) => {
            for (key, value) in map {
                if key == "ownerMallNameList" {
                    collect_owner_mall_entries(value, result, seen);
                }
                collect_owner_mall_items(value, result, seen);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_owner_mall_items(item, result, seen);
            }
        }
        _ => {}
    }
}

fn collect_owner_mall_entries(
    value: &Value,
    result: &mut Vec<PddOwnerMallItem>,
    seen: &mut HashSet<String>,
) {
    match value {
        Value::Array(items) => {
            for item in items {
                match item {
                    Value::String(name) => {
                        push_owner_mall_item(name, "", result, seen);
                    }
                    Value::Object(obj) => {
                        let account_name = find_first_text(
                            obj,
                            &["ownerMallName", "mallName", "accountName", "name"],
                        );
                        let code = find_first_text(
                            obj,
                            &[
                                "ownerName",
                                "ownerMallId",
                                "mallId",
                                "ownerMallNo",
                                "ownerMallCode",
                                "mallCode",
                                "mallSn",
                                "mallNumber",
                                "number",
                                "code",
                                "id",
                            ],
                        );
                        push_owner_mall_item(
                            account_name.as_deref().unwrap_or(""),
                            code.as_deref().unwrap_or(""),
                            result,
                            seen,
                        );
                    }
                    _ => {}
                }
            }
        }
        Value::String(text) => {
            for piece in text.split(|ch| matches!(ch, ',' | ';' | '，' | '；')) {
                push_owner_mall_item(piece, "", result, seen);
            }
        }
        _ => {}
    }
}

fn find_first_text(
    map: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Option<String> {
    for key in keys {
        if let Some(value) = map.get(*key) {
            if let Some(text) = json_value_to_text(value) {
                let normalized = text.trim();
                if !normalized.is_empty() {
                    return Some(normalized.to_string());
                }
            }
        }
    }
    None
}

fn json_value_to_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.to_string()),
        Value::Number(num) => Some(num.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

fn push_owner_mall_item(
    account_name: &str,
    code: &str,
    result: &mut Vec<PddOwnerMallItem>,
    seen: &mut HashSet<String>,
) {
    let name = account_name.trim();
    let normalized_code = code.trim();
    if name.is_empty() {
        return;
    }
    let dedupe_key = format!("{name}|{normalized_code}");
    if !seen.insert(dedupe_key) {
        return;
    }
    result.push(PddOwnerMallItem {
        account_name: name.to_string(),
        code: normalized_code.to_string(),
    });
}

fn find_task_block_range(content: &str, task_id: i32) -> Result<(usize, usize), String> {
    let mut offset = 0usize;
    for line_chunk in content.split_inclusive('\n') {
        let line = line_chunk.trim_end_matches('\n');
        if extract_task_id_from_line(line) != Some(task_id) {
            offset += line_chunk.len();
            continue;
        }
        let open_brace = content[offset..]
            .find('{')
            .map(|idx| offset + idx)
            .ok_or_else(|| format!("task->id == {task_id} 代码块缺少 '{{'"))?;
        let close_brace = find_matching_brace(content, open_brace)?;
        return Ok((open_brace + 1, close_brace));
    }
    Err(format!("未找到 task->id == {task_id} 对应代码块"))
}

fn extract_task_id_from_line(line: &str) -> Option<i32> {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with("/*") {
        return None;
    }
    let task_idx = line.find("$task->id")?;
    let eq_idx = line[task_idx..].find("==")? + task_idx + 2;
    let suffix = &line[eq_idx..];
    let digits: String = suffix
        .chars()
        .skip_while(|ch| !ch.is_ascii_digit())
        .take_while(|ch| ch.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse::<i32>().ok()
}

fn find_matching_brace(content: &str, open_brace_idx: usize) -> Result<usize, String> {
    let bytes = content.as_bytes();
    let mut depth = 0i32;
    for (idx, byte) in bytes.iter().enumerate().skip(open_brace_idx) {
        match *byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(idx);
                }
            }
            _ => {}
        }
    }
    Err("未找到匹配的大括号 '}'".to_string())
}

fn collect_sync_receive_entries_in_block(
    content: &str,
    block_start: usize,
    block_end: usize,
) -> Vec<SyncReceiveCallEntry> {
    let block = &content[block_start..block_end];
    let mut entries: Vec<SyncReceiveCallEntry> = Vec::new();
    let mut offset = block_start;
    let mut line_number = content[..block_start]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1;

    for line_chunk in block.split_inclusive('\n') {
        let line = line_chunk.trim_end_matches('\n');
        if let Some(entry) = extract_sync_receive_entry(line, offset, line_number) {
            entries.push(entry);
        }
        offset += line_chunk.len();
        line_number += 1;
    }
    entries
}

fn extract_sync_receive_entry(
    line: &str,
    line_start_offset: usize,
    line_number: usize,
) -> Option<SyncReceiveCallEntry> {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with("/*") {
        return None;
    }
    let call_pos = line.find("Artisan::call")?;
    if line[..call_pos].contains("//") {
        return None;
    }
    let sync_pos = line[call_pos..].find("sync:receive")? + call_pos;
    let mut idx = sync_pos + "sync:receive".len();
    let bytes = line.as_bytes();
    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
        idx += 1;
    }
    let number_start = idx;
    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
        idx += 1;
    }
    if number_start == idx {
        return None;
    }
    let receive_id = line[number_start..idx].parse::<i64>().ok()?;
    Some(SyncReceiveCallEntry {
        receive_id,
        start: line_start_offset + number_start,
        end: line_start_offset + idx,
        line_number,
    })
}

fn find_visible(
    wd: &WdClient,
    locators: &[(&str, &str)],
    timeout: Duration,
) -> Result<Option<String>, String> {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        for (using, value) in locators {
            if let Some(element_id) = wd.find_element(using, value)? {
                if wd.element_displayed(&element_id).unwrap_or(false) {
                    return Ok(Some(element_id));
                }
            }
        }
        thread::sleep(Duration::from_millis(200));
    }
    Ok(None)
}

fn resolve_pdd_cookie_path(
    explicit: Option<&str>,
    name: &str,
    account: &str,
) -> Result<PathBuf, String> {
    if let Some(path_text) = explicit {
        return resolve_output_path(path_text);
    }
    let home = home_dir_path()?;
    let safe = sanitize_path_segment(&format!("{name}-{account}"));
    Ok(home
        .join(".sp-toolbox")
        .join("pdd")
        .join("cookies")
        .join(format!("{safe}.json")))
}

fn resolve_input_path(path_text: &str) -> Result<PathBuf, String> {
    let trimmed = path_text.trim();
    if trimmed.is_empty() {
        return Err("路径不能为空".to_string());
    }
    let path = PathBuf::from(trimmed);
    if path.is_absolute() {
        return Ok(path);
    }
    let cwd = env::current_dir().map_err(|err| format!("读取当前工作目录失败：{err}"))?;
    Ok(cwd.join(path))
}

fn resolve_output_path(path_text: &str) -> Result<PathBuf, String> {
    resolve_input_path(path_text)
}

fn sanitize_path_segment(value: &str) -> String {
    let mut normalized = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string();
    if normalized.is_empty() {
        normalized = "pdd".to_string();
    }
    normalized
}

fn validate_pdd_host_url(url_text: &str) -> Result<(), String> {
    let parsed = url::Url::parse(url_text).map_err(|err| format!("URL 无效：{err}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("仅支持 http/https 地址".to_string());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "URL 缺少主机名".to_string())?
        .to_ascii_lowercase();
    if !host.contains("pinduoduo.com") {
        return Err("仅支持 pinduoduo.com 域名".to_string());
    }
    Ok(())
}

fn read_pdd_cookie_file(path: &Path) -> Result<Vec<BrowserCookie>, String> {
    if !path.exists() {
        return Err(format!("Cookie 文件不存在：{}", path.display()));
    }
    let text = fs::read_to_string(path)
        .map_err(|err| format!("读取 Cookie 文件失败：{} ({err})", path.display()))?;
    serde_json::from_str::<Vec<BrowserCookie>>(&text)
        .map_err(|err| format!("解析 Cookie 文件失败：{} ({err})", path.display()))
}

fn usable_pdd_cookies(cookies: &[BrowserCookie]) -> Vec<BrowserCookie> {
    let now = Utc::now().timestamp() as f64;
    cookies
        .iter()
        .filter(|cookie| {
            if !cookie.domain.contains("pinduoduo.com") {
                return false;
            }
            if cookie.name.trim().is_empty() || cookie.value.trim().is_empty() {
                return false;
            }
            if cookie.expires > 0.0 && cookie.expires < now {
                return false;
            }
            true
        })
        .cloned()
        .collect()
}

fn build_cookie_header(cookies: &[BrowserCookie]) -> String {
    cookies
        .iter()
        .map(|cookie| format!("{}={}", cookie.name.trim(), cookie.value))
        .collect::<Vec<_>>()
        .join("; ")
}

fn trim_to_option(value: &Option<String>) -> Option<&str> {
    value.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty())
}

fn trim_str_to_option(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|s| !s.is_empty())
}

fn ecs_host(region_id: &str) -> String {
    format!("ecs.{region_id}.aliyuncs.com")
}

fn form_url_encode(params: &BTreeMap<String, String>) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in params {
        serializer.append_pair(key, value);
    }
    serializer.finish()
}

fn canonicalize_header_value(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn hmac_sha256_hex(secret: &str, message: &str) -> Result<String, ApiError> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).map_err(|err| {
        ApiError::new(
            "SignatureInitError",
            format!("初始化签名失败: {}", err),
            None,
        )
    })?;

    mac.update(message.as_bytes());
    let result = mac.finalize().into_bytes();
    Ok(hex::encode(result))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            detect_public_ip,
            verify_account,
            sync_all,
            list_ssh_shortcuts,
            open_ssh_terminal,
            test_ssh_shortcut,
            test_all_ssh_shortcuts,
            delete_ssh_shortcut,
            pdd_login_with_browser,
            pdd_validate_cookie,
            pdd_fetch_store_configs,
            pdd_quick_sync
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
