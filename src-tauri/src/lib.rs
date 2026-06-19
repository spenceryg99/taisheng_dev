use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HOST};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

const ECS_VERSION: &str = "2014-05-26";
const POLARDB_VERSION: &str = "2017-08-01";
const STS_VERSION: &str = "2015-04-01";
const STS_HOST: &str = "sts.aliyuncs.com";
const POLARDB_HOST: &str = "polardb.aliyuncs.com";
const LOCAL_BACKEND_DIR: &str = "/Users/spenceryg/Documents/taisheng/junziyun-v7";
const LOCAL_FRONTEND_DIR: &str = "/Users/spenceryg/Documents/taisheng/taisheng_web";
const LOCAL_BACKEND_PORT: u16 = 9528;
const LOCAL_FRONTEND_PORT: u16 = 9669;

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

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum TargetType {
    EcsSecurityGroup,
    PolardbClusterWhitelist,
}

impl Default for TargetType {
    fn default() -> Self {
        Self::EcsSecurityGroup
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TargetInput {
    id: String,
    name: Option<String>,
    account_id: String,
    #[serde(default)]
    target_type: TargetType,
    #[serde(default)]
    security_group_id: String,
    #[serde(default)]
    db_cluster_id: Option<String>,
    #[serde(default)]
    db_cluster_ip_array_name: Option<String>,
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
    target_type: TargetType,
    resource_id: String,
    whitelist_group_name: Option<String>,
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalDevStartResponse {
    backend_port: u16,
    frontend_port: u16,
    cleared_backend_pids: Vec<u32>,
    cleared_frontend_pids: Vec<u32>,
    message: String,
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

#[derive(Debug, Clone)]
struct PolardbWhitelistGroup {
    name: String,
    security_ips: Option<String>,
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
            let resource_id = target_resource_id(&target);
            let whitelist_group_name = target_whitelist_group_name(&target);
            results.push(TargetSyncResult {
                target_id: target.id,
                target_name: target.name,
                account_id: target.account_id,
                account_name: None,
                target_type: target.target_type,
                resource_id,
                whitelist_group_name,
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
                let resource_id = target_resource_id(&target);
                let whitelist_group_name = target_whitelist_group_name(&target);
                results.push(TargetSyncResult {
                    target_id: target.id,
                    target_name: target.name,
                    account_id: account.id.clone(),
                    account_name,
                    target_type: target.target_type,
                    resource_id,
                    whitelist_group_name,
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

#[tauri::command]
fn read_text_file(path: String) -> Result<String, String> {
    let target = resolve_input_path(&path)?;
    fs::read_to_string(&target).map_err(|err| format!("读取文件失败：{} ({err})", target.display()))
}

#[tauri::command]
fn write_text_file(path: String, content: String) -> Result<String, String> {
    let target = resolve_output_path(&path)?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("创建目录失败：{} ({err})", parent.display()))?;
    }
    fs::write(&target, content)
        .map_err(|err| format!("写入文件失败：{} ({err})", target.display()))?;
    Ok(target.display().to_string())
}

#[tauri::command]
fn join_file_path(directory: String, file_name: String) -> Result<String, String> {
    let dir = resolve_input_path(&directory)?;
    if !dir.exists() || !dir.is_dir() {
        return Err(format!("目录不存在：{}", dir.display()));
    }
    let trimmed_name = file_name.trim();
    if trimmed_name.is_empty() {
        return Err("文件名不能为空".to_string());
    }
    if trimmed_name.contains('/') || trimmed_name.contains('\\') {
        return Err("文件名不能包含路径分隔符".to_string());
    }
    Ok(dir.join(trimmed_name).display().to_string())
}

#[tauri::command]
fn find_latest_config_backup_file(directory: String) -> Result<String, String> {
    let dir = resolve_input_path(&directory)?;
    if !dir.exists() || !dir.is_dir() {
        return Err(format!("目录不存在：{}", dir.display()));
    }

    let mut latest: Option<(PathBuf, std::time::SystemTime, String)> = None;
    let entries =
        fs::read_dir(&dir).map_err(|err| format!("读取目录失败：{} ({err})", dir.display()))?;
    for entry in entries {
        let item = entry.map_err(|err| format!("读取目录项失败：{} ({err})", dir.display()))?;
        let path = item.path();
        if !path.is_file() {
            continue;
        }
        let file_name = item.file_name().to_string_lossy().to_string();
        if !file_name.ends_with(".json") || !file_name.contains("sp-toolbox-config") {
            continue;
        }
        let modified = item
            .metadata()
            .ok()
            .and_then(|meta| meta.modified().ok())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        match &latest {
            None => {
                latest = Some((path, modified, file_name));
            }
            Some((_, latest_time, latest_name)) => {
                if modified > *latest_time || (modified == *latest_time && file_name > *latest_name)
                {
                    latest = Some((path, modified, file_name));
                }
            }
        }
    }

    if let Some((path, _, _)) = latest {
        return Ok(path.display().to_string());
    }

    Err("该目录下未找到配置备份文件（sp-toolbox-config*.json）".to_string())
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
fn start_local_dev_services() -> Result<LocalDevStartResponse, String> {
    ensure_dir_exists(LOCAL_BACKEND_DIR, "后端项目目录")?;
    ensure_dir_exists(LOCAL_FRONTEND_DIR, "前端项目目录")?;

    let cleared_backend_pids = kill_processes_on_port(LOCAL_BACKEND_PORT)?;
    let cleared_frontend_pids = kill_processes_on_port(LOCAL_FRONTEND_PORT)?;

    start_local_backend_service()?;
    wait_for_port_listen(LOCAL_BACKEND_PORT, Duration::from_secs(12))?;

    start_local_frontend_service()?;
    wait_for_port_listen(LOCAL_FRONTEND_PORT, Duration::from_secs(20))?;

    Ok(LocalDevStartResponse {
        backend_port: LOCAL_BACKEND_PORT,
        frontend_port: LOCAL_FRONTEND_PORT,
        cleared_backend_pids,
        cleared_frontend_pids,
        message: "本地前后端服务已启动".to_string(),
    })
}

fn target_resource_id(target: &TargetInput) -> String {
    match target.target_type {
        TargetType::PolardbClusterWhitelist => target
            .db_cluster_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("")
            .to_string(),
        TargetType::EcsSecurityGroup => target.security_group_id.trim().to_string(),
    }
}

fn target_whitelist_group_name(target: &TargetInput) -> Option<String> {
    match target.target_type {
        TargetType::PolardbClusterWhitelist => {
            trim_to_option(&target.db_cluster_ip_array_name).map(ToString::to_string)
        }
        TargetType::EcsSecurityGroup => None,
    }
}

async fn sync_single_target(
    client: &AlibabaOpenApiClient,
    account: &AccountInput,
    target: &TargetInput,
    cidr: &str,
) -> Result<TargetSyncResult, ApiError> {
    match target.target_type {
        TargetType::EcsSecurityGroup => sync_ecs_target(client, account, target, cidr).await,
        TargetType::PolardbClusterWhitelist => {
            sync_polardb_whitelist_target(client, account, target, cidr).await
        }
    }
}

async fn sync_ecs_target(
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
        target_type: target.target_type.clone(),
        resource_id: target_resource_id(target),
        whitelist_group_name: target_whitelist_group_name(target),
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
            target_type: target.target_type.clone(),
            resource_id: target_resource_id(target),
            whitelist_group_name: target_whitelist_group_name(target),
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
        target_type: target.target_type.clone(),
        resource_id: target_resource_id(target),
        whitelist_group_name: target_whitelist_group_name(target),
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

async fn sync_polardb_whitelist_target(
    client: &AlibabaOpenApiClient,
    account: &AccountInput,
    target: &TargetInput,
    cidr: &str,
) -> Result<TargetSyncResult, ApiError> {
    let db_cluster_id = trim_to_option(&target.db_cluster_id).ok_or_else(|| {
        ApiError::new("DBClusterIdMissing", "PolarDB 目标未填写 DBClusterId", None)
    })?;
    let group_name = trim_to_option(&target.db_cluster_ip_array_name).ok_or_else(|| {
        ApiError::new(
            "DBClusterIPArrayNameMissing",
            "PolarDB 目标未填写白名单分组名",
            None,
        )
    })?;
    let region_id = resolve_polardb_target_region(client, account, target, db_cluster_id).await?;
    let whitelist_groups =
        describe_polardb_access_whitelist(client, account, db_cluster_id).await?;

    let mut matched_groups: Vec<PolardbWhitelistGroup> = whitelist_groups
        .into_iter()
        .filter(|group| group.name == group_name)
        .collect();

    match matched_groups.len() {
        0 => Ok(TargetSyncResult {
            target_id: target.id.clone(),
            target_name: target.name.clone(),
            account_id: target.account_id.clone(),
            account_name: None,
            target_type: target.target_type.clone(),
            resource_id: target_resource_id(target),
            whitelist_group_name: Some(group_name.to_string()),
            region_id: Some(region_id),
            rule_id: None,
            action: "skipped".to_string(),
            success: true,
            request_id: None,
            code: None,
            message: format!(
                "未找到名为“{}”的 PolarDB 白名单分组，未执行修改",
                group_name
            ),
        }),
        1 => {
            let current_group = matched_groups.remove(0);
            let current_cidrs = current_group
                .security_ips
                .as_deref()
                .map(|value| {
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|item| !item.is_empty())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            if current_cidrs.len() == 1 && current_cidrs[0] == cidr {
                return Ok(TargetSyncResult {
                    target_id: target.id.clone(),
                    target_name: target.name.clone(),
                    account_id: target.account_id.clone(),
                    account_name: None,
                    target_type: target.target_type.clone(),
                    resource_id: target_resource_id(target),
                    whitelist_group_name: Some(group_name.to_string()),
                    region_id: Some(region_id),
                    rule_id: None,
                    action: "noop".to_string(),
                    success: true,
                    request_id: None,
                    code: None,
                    message: "白名单分组 IP 已是最新，无需更新".to_string(),
                });
            }

            let request_id =
                modify_polardb_access_whitelist(client, account, db_cluster_id, group_name, cidr)
                    .await?;

            Ok(TargetSyncResult {
                target_id: target.id.clone(),
                target_name: target.name.clone(),
                account_id: target.account_id.clone(),
                account_name: None,
                target_type: target.target_type.clone(),
                resource_id: target_resource_id(target),
                whitelist_group_name: Some(group_name.to_string()),
                region_id: Some(region_id),
                rule_id: None,
                action: "modified_whitelist".to_string(),
                success: true,
                request_id: Some(request_id),
                code: None,
                message: format!("白名单分组已覆盖为 {}", cidr),
            })
        }
        _ => Ok(TargetSyncResult {
            target_id: target.id.clone(),
            target_name: target.name.clone(),
            account_id: target.account_id.clone(),
            account_name: None,
            target_type: target.target_type.clone(),
            resource_id: target_resource_id(target),
            whitelist_group_name: Some(group_name.to_string()),
            region_id: Some(region_id),
            rule_id: None,
            action: "skipped".to_string(),
            success: true,
            request_id: None,
            code: None,
            message: format!(
                "白名单分组“{}”匹配到多条记录（{}条），未执行修改",
                group_name,
                matched_groups.len() + 1
            ),
        }),
    }
}

async fn describe_polardb_access_whitelist(
    client: &AlibabaOpenApiClient,
    account: &AccountInput,
    db_cluster_id: &str,
) -> Result<Vec<PolardbWhitelistGroup>, ApiError> {
    let mut params = BTreeMap::new();
    params.insert("DBClusterId".to_string(), db_cluster_id.to_string());

    let response = client
        .call_rpc_json(
            POLARDB_HOST,
            "DescribeDBClusterAccessWhitelist",
            POLARDB_VERSION,
            account,
            &params,
        )
        .await?;

    let groups = response
        .pointer("/Items/DBClusterIPArray")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    Ok(groups
        .into_iter()
        .filter_map(|group| {
            let name = group
                .get("DBClusterIPArrayName")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())?
                .to_string();
            let security_ips = group
                .get("SecurityIps")
                .and_then(Value::as_str)
                .or_else(|| group.get("SecurityIPList").and_then(Value::as_str))
                .map(ToString::to_string);
            Some(PolardbWhitelistGroup { name, security_ips })
        })
        .collect())
}

async fn modify_polardb_access_whitelist(
    client: &AlibabaOpenApiClient,
    account: &AccountInput,
    db_cluster_id: &str,
    group_name: &str,
    cidr: &str,
) -> Result<String, ApiError> {
    let mut params = BTreeMap::new();
    params.insert("DBClusterId".to_string(), db_cluster_id.to_string());
    params.insert("WhiteListType".to_string(), "IP".to_string());
    params.insert("ModifyMode".to_string(), "Cover".to_string());
    params.insert("DBClusterIPArrayName".to_string(), group_name.to_string());
    params.insert("SecurityIps".to_string(), cidr.to_string());

    let response = client
        .call_rpc_json(
            POLARDB_HOST,
            "ModifyDBClusterAccessWhitelist",
            POLARDB_VERSION,
            account,
            &params,
        )
        .await?;

    Ok(response
        .get("RequestId")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string())
}

async fn resolve_polardb_target_region(
    client: &AlibabaOpenApiClient,
    account: &AccountInput,
    target: &TargetInput,
    db_cluster_id: &str,
) -> Result<String, ApiError> {
    if let Some(region_id) = trim_to_option(&target.region_id) {
        return Ok(region_id.to_string());
    }

    if let Some(region_id) = trim_to_option(&account.default_region_id) {
        if polardb_cluster_exists_in_region(client, account, region_id, db_cluster_id).await? {
            return Ok(region_id.to_string());
        }
    }

    discover_polardb_region_by_cluster(client, account, db_cluster_id).await
}

async fn discover_polardb_region_by_cluster(
    client: &AlibabaOpenApiClient,
    account: &AccountInput,
    db_cluster_id: &str,
) -> Result<String, ApiError> {
    let regions = describe_regions(client, account).await?;
    let mut first_non_not_found_error: Option<ApiError> = None;

    for region in regions {
        match polardb_cluster_exists_in_region(client, account, &region, db_cluster_id).await {
            Ok(true) => return Ok(region),
            Ok(false) => continue,
            Err(err) => {
                if err.code.contains("InvalidRegionId") {
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
        "DBClusterNotFound",
        format!("没有在任何地域找到 PolarDB 集群 {}", db_cluster_id),
        None,
    ))
}

async fn polardb_cluster_exists_in_region(
    client: &AlibabaOpenApiClient,
    account: &AccountInput,
    region_id: &str,
    db_cluster_id: &str,
) -> Result<bool, ApiError> {
    let mut params = BTreeMap::new();
    params.insert("RegionId".to_string(), region_id.to_string());
    params.insert("DBClusterIds".to_string(), db_cluster_id.to_string());
    params.insert("PageSize".to_string(), "30".to_string());
    params.insert("PageNumber".to_string(), "1".to_string());

    let response = client
        .call_rpc_json(
            POLARDB_HOST,
            "DescribeDBClusters",
            POLARDB_VERSION,
            account,
            &params,
        )
        .await?;

    let clusters = response
        .pointer("/Items/DBCluster")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    Ok(clusters.iter().any(|cluster| {
        cluster
            .get("DBClusterId")
            .and_then(Value::as_str)
            .is_some_and(|id| id == db_cluster_id)
    }))
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

fn ensure_dir_exists(path_text: &str, label: &str) -> Result<(), String> {
    let path = Path::new(path_text);
    if path.exists() && path.is_dir() {
        return Ok(());
    }
    Err(format!("{label}不存在：{}", path.display()))
}

fn list_port_listening_pids(port: u16) -> Result<Vec<u32>, String> {
    let output = Command::new("lsof")
        .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN", "-t"])
        .output()
        .map_err(|err| format!("查询端口 {port} 占用失败：{err}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !output.status.success() && stdout.trim().is_empty() && !stderr.is_empty() {
        return Err(format!("查询端口 {port} 占用失败：{stderr}"));
    }

    let mut pids = stdout
        .lines()
        .filter_map(|line| line.trim().parse::<u32>().ok())
        .collect::<Vec<_>>();
    pids.sort_unstable();
    pids.dedup();
    Ok(pids)
}

fn kill_processes_on_port(port: u16) -> Result<Vec<u32>, String> {
    let pids = list_port_listening_pids(port)?;
    for pid in &pids {
        let status = Command::new("kill")
            .args(["-9", &pid.to_string()])
            .status()
            .map_err(|err| format!("结束端口 {port} 对应进程 {pid} 失败：{err}"))?;
        if !status.success() {
            return Err(format!("结束端口 {port} 对应进程 {pid} 失败"));
        }
    }

    if !pids.is_empty() {
        thread::sleep(Duration::from_millis(350));
        let remaining = list_port_listening_pids(port)?;
        if !remaining.is_empty() {
            return Err(format!("端口 {port} 仍被占用：{:?}", remaining));
        }
    }
    Ok(pids)
}

fn build_local_service_log_path(file_name: &str) -> Result<String, String> {
    let log_dir = env::temp_dir().join("sp_toolbox_logs");
    fs::create_dir_all(&log_dir)
        .map_err(|err| format!("创建日志目录失败：{} ({err})", log_dir.display()))?;
    Ok(log_dir.join(file_name).display().to_string())
}

fn run_background_shell(command: &str, context: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    let status = Command::new("cmd")
        .args(["/C", command])
        .status()
        .map_err(|err| format!("{context}失败：{err}"))?;

    #[cfg(not(target_os = "windows"))]
    let status = Command::new("sh")
        .arg("-lc")
        .arg(command)
        .status()
        .map_err(|err| format!("{context}失败：{err}"))?;

    if !status.success() {
        return Err(format!("{context}失败"));
    }
    Ok(())
}

fn start_local_backend_service() -> Result<(), String> {
    let backend_log = build_local_service_log_path("local-backend-9528.log")?;
    let command = format!(
        "cd {} && nohup php artisan serve --port={} > {} 2>&1 &",
        shell_single_quote(LOCAL_BACKEND_DIR),
        LOCAL_BACKEND_PORT,
        shell_single_quote(&backend_log)
    );
    run_background_shell(&command, "启动后端服务")
}

fn start_local_frontend_service() -> Result<(), String> {
    let frontend_log = build_local_service_log_path("local-frontend-9669.log")?;
    let command = format!(
        "cd {} && nohup npm run dev -- --port {} > {} 2>&1 &",
        shell_single_quote(LOCAL_FRONTEND_DIR),
        LOCAL_FRONTEND_PORT,
        shell_single_quote(&frontend_log)
    );
    run_background_shell(&command, "启动前端服务")
}

fn wait_for_port_listen(port: u16, timeout: Duration) -> Result<(), String> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if !list_port_listening_pids(port)?.is_empty() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(300));
    }
    Err(format!(
        "等待端口 {port} 启动超时（{} 秒）",
        timeout.as_secs()
    ))
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
    let line_ending = if content.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
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
            start_local_dev_services,
            test_ssh_shortcut,
            test_all_ssh_shortcuts,
            delete_ssh_shortcut,
            read_text_file,
            write_text_file,
            join_file_path,
            find_latest_config_backup_file
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
