#!/usr/bin/env node
// 敏感数据守卫管理 CLI 的新入口；实现保留在 bin/delete-guard.mjs，
// 这样旧的 `node bin/delete-guard.mjs ...` 命令继续可用。
import './delete-guard.mjs';
