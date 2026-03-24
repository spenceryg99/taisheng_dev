# Global Rule

- 当前无全局规则。

## 全局记忆

- 线上测试后台地址：`https://serp.web2018.top/admin/Login/index.html`
- 超级管理员账号：`admin`
- 超级管理员密码：`admin2019`
- 后续所有 Git commit 信息统一使用中文。

---

# Project Rules

- 对于纯 UI/视觉优化需求，优先使用 Pencil MCP 工作流。
- 默认设计文件使用项目根目录的 `design.pen`。
- UI 修改时不要改动业务逻辑、Tauri 命令名、接口参数结构。
- 完成 UI 修改后，必须运行 `npm run build` 验证。
- 若 Pencil MCP 不可用，再回退到直接改 `src/App.tsx` 与 `src/styles.css`。
- 临时产生的统计性文件或文档性文件统一存入项目根目录 `临时目录/`（`/Users/spenceryg/Documents/taisheng/阿里云工具/临时目录`）。
