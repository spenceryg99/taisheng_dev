# Project Rules

- 对于纯 UI/视觉优化需求，优先使用 Pencil MCP 工作流。
- 默认设计文件使用项目根目录的 `design.pen`。
- UI 修改时不要改动业务逻辑、Tauri 命令名、接口参数结构。
- 完成 UI 修改后，必须运行 `npm run build` 验证。
- 若 Pencil MCP 不可用，再回退到直接改 `src/App.tsx` 与 `src/styles.css`。
