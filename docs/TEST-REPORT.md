# 敏感数据守卫 测试报告

- 报告日期：2026-11-05（Asia/Shanghai；审计日志时间戳为 UTC）
- 机器：本机 Windows，DSH Desktop 0.2.1-rc.2，profile `desktop`
- 插件：`@local/dsh-sensitive-data-guard@0.2.1`（0.2.0 的区域模型 + 本轮保护目录合并修复），
  安装方式 `plugin_manager install_bundle`（本地目录 link）
- 插件目录：`<插件目录>`
- 备份根：`backup/`（相对插件目录解析）
- 会话：`<session-id>`
- 运行时：Node v24.22.0 / Python 3.13.2 / git 2.48.1

> `<插件目录>` = 本插件所在目录（`package.json` 所在处）；`<工作区>` = 当前 DSH 会话的工作目录。文中相对路径都相对于 `<插件目录>`。

## 结论摘要

| 文件 | 用例数 | 通过 | 失败 |
|---|---:|---:|---:|
| `test/core.test.mjs` | 22 | 22 | 0 |
| `test/gate.test.mjs` | 7 | 7 | 0 |
| `test/protect.test.mjs` | 5 | 5 | 0 |
| **合计** | **34** | **34** | **0** |

全部通过。实测命令与输出见文末「复跑方法」。

> 版本说明：保护目录合并的修复作为 **0.2.1** 发布（`package.json` 已改为 `0.2.1`），
> 0.2.0 是区域模型那一版。这轮没有改动任何运行时行为，只修了「设置文件覆盖配置保护目录」
> 这一个缺陷，并补了一条回归用例。

---

## 一、`test/core.test.mjs`（22/22 通过）

覆盖分类器（`lib/classify.js`）与备份引擎（`lib/backup.js`），不依赖 DSH Host。

| # | 用例名 | 覆盖点 | 结果 |
|---:|---|---|---|
| 1 | `classifier: Remove-Item 目录 → targets` | PowerShell 删除命令的目标解析（绝对路径原样保留） | 通过 |
| 2 | `classifier: 别名 rm -rf → targets` | Unix 别名；相对路径按 workdir 解析成绝对路径 | 通过 |
| 3 | `classifier: 删除但没有路径 → scope` | 管道删除（`Get-ChildItem \| Remove-Item`）无显式路径 → 范围取 workdir | 通过 |
| 4 | `classifier: python -c shutil.rmtree 字面量 → targets` | 解释器内联删除的字符串字面量提取 | 通过 |
| 5 | `classifier: python -c shutil.rmtree 原始字符串 r'...' → targets` | `r'...'` 前缀的字面量提取（历史回归点） | 通过 |
| 6 | `classifier: os.truncate 路径 → targets` | 截断类 API 视为破坏性写入 | 通过 |
| 7 | `classifier: prettier --write 目标目录 → targets（格式化=破坏性写入）` | formatter 分类：`--write` 的写入目标即备份目标 | 通过 |
| 8 | `classifier: node -e fs.rmSync 字面量 → targets` | Node 内联 `rmSync` 的路径提取 | 通过 |
| 9 | `classifier: git clean → scope(仓库根)` | 从子目录向上找 `.git`，范围判定为仓库根 | 通过 |
| 10 | `classifier: 未知命令 → scope（默认策略）` | `policy.opaqueCommand = 'scope'` 的默认行为 | 通过 |
| 11 | `classifier: 未知命令 + block 策略 → deny` | `opaqueCommand = 'block'` 时直接阻断 | 通过 |
| 12 | `classifier: 只读命令 → safe` | 5 条只读命令（`Get-ChildItem` / `git status` / `git log` / `npm --version` / `echo`） | 通过 |
| 13 | `classifier: robocopy /MIR → targets(dest)` | 镜像同步的破坏目标是目的端 | 通过 |
| 14 | `classifier: 系统级破坏命令 → deny` | `fsutil usn deletejournal` / `cipher /w` / `format` / `vssadmin delete shadows` | 通过 |
| 15 | `classifier: write 工具新建文件 → safe，覆盖已有 → targets` | `write` 工具按「是否已存在」区分新建与覆盖 | 通过 |
| 16 | `classifier: 未知工具 → unknown；quickClassify 同步` | 未知工具判定 + `guard()` 用的同步分类表一致 | 通过 |
| 17 | `backup: 目录备份 + 还原 + 哈希一致` | 30 个文件（含子目录）备份 → 删除 → 还原 → 逐文件 SHA-256 比对 | 通过 |
| 18 | `backup: 去重（同内容只存一份）` | 内容寻址：两个同内容文件只落一个对象，二次备份不新增对象 | 通过 |
| 19 | `backup: 单批文件数超限 → BackupLimitError` | 20 个文件 vs `maxBatchFiles: 5` → 抛 `BackupLimitError` | 通过 |
| 20 | `backup: 单文件超限 → 阻断` | 4 KiB 文件 vs `maxFileBytes: 1024` → 抛 `BackupLimitError` | 通过 |
| 21 | `backup: 软链接只记录、不跟随` | 符号链接计入 `links`，不复制内容（无建链权限时跳过） | 通过 |
| 22 | `backup: 不可写根 → init 抛错（fail-closed 依据）` | 嵌套不存在的根 → `init()` 自动创建且 `healthy === true` | 通过 |

> 命名与实际断言不一致（历史遗留）：第 22 条沿用旧名「不可写根 → init 抛错」，
> 但当前断言是「不存在的根会被递归创建，`healthy` 为 true」。
> 真正的「备份不可写 → 阻断」由 `evaluate()` 里 `initError` / `!ready` 两个分支保证，
> 未在自动化测试中覆盖（历史上做过一次 ACL 手工演练，见 `docs/DESIGN-REVISIONS.md`）。

---

## 二、`test/gate.test.mjs`（7/7 通过）

覆盖 `GateCore` 的门禁编排：令牌签发、`guard()` 同步兜底、shell 深度层、运行时钩子、分区判定、
确认码闭环、保护目录优先级、设置覆盖合并、`cwdFor` 回落链。

| # | 用例名 | 覆盖点 | 结果 |
|---:|---|---|---|
| 1 | `端到端：令牌 → guard → shell 钩子（python/node）` | 工作区删除放行并签令牌；`prepareShell` 复用令牌（不重复备份）并注入 `DSH_DELETE_GUARD_ALLOW` / `PYTHONPATH` / `NODE_OPTIONS`；Python 与 Node 钩子在允许范围内删除成功、范围外（工作区之外）删除被拒且文件保留；无令牌的破坏性调用被 `guard()` 阻断 | 通过 |
| 2 | `区域模型：工作区不备份、敏感区备份并要求确认码` | 工作区目标 → `allow` 且 `batchId === null`；敏感区目标 → `deny`，报告含 `确认码：\d{4}` 与「已经提前备份」；被拦调用不签发令牌；带 `$env:DSH_GUARD_CONFIRM='<码>';` 重发 → `allow` 且复用原批次 | 通过 |
| 3 | `受保护目录优先于「工作区不保护」的短路` | 即使目标在工作区内，命中 `protectedPaths` 也必须 `deny`（防止工作区短路绕过自保护） | 通过 |
| 4 | `设置文件里的空 protectedPaths 不能清空配置里的保护目录` | **新增回归用例**（见下节），覆盖三种情形：空数组不清空底线 / UI 追加与底线合并 / UI 清空只删追加项 | 通过 |
| 5 | `cwdFor：服务缺失时回落到 Session 头里的 cwd` | `workingDirectory` 服务不可用时回落到 `agent.session.header.cwd` | 通过 |
| 6 | `cwd 落在 .dsh 里时，不能把工作区目标误判成「工作区」` | 无效的工作区基准（位于 `.dsh` 内）必须被丢弃，目标回落成 `sensitive` 而非放行 | 通过 |
| 7 | `fail-closed：未知工具默认拒绝；备份根不可用时拒绝` | 未知工具 → `deny` 且原因含「未知工具」；`guard()` 同步返回阻断字符串 | 通过 |

### 第 4 条回归用例的由来：设置文件覆盖配置保护目录

**缺陷（0.2.0 修复轮修掉）**：`data/settings.json` 由设置页写入，而设置页每次保存都会带上
`protectedPaths`（哪怕是空数组）。旧的 `applySettingsOverlay()` 见到该字段就无条件覆盖，
于是用户在设置页点过一次「保存」之后，`cordis.patch.yml` 或 profile patch 里写的保护目录
会被清空——保护目录等于没配。

实测因果（修复前的记录）：传入 config `['**/x/*']` → 实际生效 `[]`。

**修复**：把保护目录拆成两份再合并。

| 来源 | 字段 | 说明 |
|---|---|---|
| 配置基线 | `baseProtectedPaths` ← `policy.protectedPaths`（来自 `cordis.patch.yml` / profile patch） | **底线**，任何情况下都保留 |
| 设置页追加 | `uiProtectedPaths` ← `data/settings.json` 的 `protectedPaths` | 只能**往上追加** |

生效值 = `baseProtectedPaths ∪ uiProtectedPaths`（去重、保持顺序），由 `refreshProtectedPaths()`
重新编译模式。`applySettings()` 只替换 `uiProtectedPaths`，所以：

- 设置页里清空文本框 → 只删掉追加项，配置底线仍生效；
- 设置页无法删除配置文件里声明的条目（界面上以只读小字列出，见 `client.js` 的
  `configProtectedPaths` 展示）。

配套改动：

- `GateCore` 构造函数新增第三个参数 `options.settingsDir`（默认插件目录），测试用它注入临时设置目录，
  使仓库里的 `data/settings.json` 不再影响用例结果；
- `settingsSnapshot()` 返回 `protectedPaths`（UI 追加的那份，给文本框）与
  `configProtectedPaths`（配置底线，给只读展示）。

---

## 三、`test/protect.test.mjs`（5/5 通过）

覆盖 `policy.protectedPaths` 的 .gitignore 风格模式匹配（`lib/paths.js`）与门禁接入。

| # | 用例名 | 覆盖点 | 结果 |
|---:|---|---|---|
| 1 | `protect: User/* 保护、!User/WorkSpace 放行` | `*` 匹配一段；`!` 排除；`patternCoversTarget` 判断「删除上级会连带删掉受保护目录」 | 通过 |
| 2 | `protect: 盘符锚定与任意层级` | `D:/work/secret` 只锚定 D 盘；`*.tmp` 匹配任意层级 | 通过 |
| 3 | `protect: ** 跨段与后写覆盖` | `**/node_modules/**` 跨段匹配；`!**/keep/**` 后写覆盖先写 | 通过 |
| 4 | `protect: 空列表 / 注释 / 反斜杠写法` | 空列表不保护任何路径；`#` 注释行与空行被忽略；`User\*` 反斜杠写法等价 | 通过 |
| 5 | `gate: 配置 protectedPaths 后，命中模式的删除目标被阻断` | `assertNotProtected` 对 `targets` 与 `scope` 两种 plan 都抛错；不命中的路径不抛 | 通过 |

---

## 四、手工联调验证

以下为 2026-11-05 在本机实际执行并观察到的结果。

### 4.1 区域分流：工作区删除完全不干预

```
新建 <工作区>\_dg-zonecheck\victim（a.txt、b.txt 两个文件）
Remove-Item -LiteralPath '<工作区>\_dg-zonecheck\victim' -Recurse -Force
```

结果：命令成功，目录被删除。审计记录：

```json
{"event":"gate","tool":"pwsh","plan":"scope","zone":"workspace",
 "targets":["<工作区>"],"decision":"allow","batchId":null}
```

备份批次总数在执行前后均为 35，**没有新增任何批次**——工作区确认不备份。

### 4.2 区域分流：敏感区拦截与报告内容

用一条不可能删除成功的路径做安全探测（目录本就不存在，不会造成破坏）：

```
Remove-Item -LiteralPath 'D:\__dg-nonexistent-check__' -Recurse -Force
```

返回（原文）：

```
🛑 敏感区删除已拦截（未执行）

区域：敏感区（.dsh 与工作区之外）
级别：hard

拟删除的内容：
  • D:\__dg-nonexistent-check__
      0 个文件，0 B

合计：0 个文件，0 B

已经提前备份：(无可备份文件)
备份目录：backup
还原命令：node bin/delete-guard.mjs restore (无可备份文件)

如确实要删除，请把下面的确认码发给我，我会带着它重新发起（备份已就绪，不会重复备份）：

确认码：3480
```

核对：区域、级别、逐目录明细、合计、批次、备份目录、还原命令齐全，**确认码确实在报告最后**。

### 4.3 确认码闭环：带码重发放行且不重复备份

```
$env:DSH_GUARD_CONFIRM='3480'; Remove-Item -LiteralPath 'D:\__dg-nonexistent-check__' -Recurse -Force
```

结果：门禁**放行**（不再拦截、不再要码），随后命令自身因路径不存在报 `PathNotFound`。
即：确认码校验通过、复用原批次、未重复备份。

### 4.4 设置路由读写与放宽警告

```
GET  http://127.0.0.1:<port>/plugins/dsh-sensitive-data-guard/settings
POST {{"triggerLevel":"soft"}}
POST {{"triggerLevel":"hard", ...}}
```

| 操作 | 观察结果 |
|---|---|
| GET | `{"ok":true,"settings":{...}}`，含 `triggerLevel`、`levelScope`、`levels`、`mediumMinFiles`、`mediumMinBytes`、`protectedPaths`、`configProtectedPaths`、`dshHome`、`workspaceMode`、`retention`、`settingsFile` |
| POST `soft` | `{"ok":true,"loosened":true,"from":"hard","to":"soft"}` —— 放宽被标记 |
| POST `hard` | `{"ok":true,"loosened":false,"from":"soft","to":"hard"}` —— 收紧不告警 |
| 落盘 | `data/settings.json` 写入且内容与返回值一致 |

### 4.5 设置页（Client 半）注册成功

通过客户端插槽检查确认 `settings.section` 下出现占用者：

```json
{"registrant":"…","id":"dsh-sensitive-data-guard","order":25,"active":true}
```

设置页可见字段：级别单选（每项带小字范围说明）、阈值输入（仅 medium 显示）、
保护目录文本框（一行一个，支持 `!` 排除）、**配置基线只读小字展示**
（列出 `cordis.patch.yml` 里声明的保护目录，说明这些删不掉）、保存按钮、
放宽时的红字警告、重新读取按钮、运行时信息（`.dsh` 位置 / 保留策略 / 设置文件路径）。

### 4.6 工作区基准修复的前后对比

修复前 `cwdFor()` 退回 `process.cwd()`（桌面版为 profile 目录），审计里出现过：

```json
{"tool":"pwsh","plan":"scope","zone":"workspace",
 "targets":["C:\\Users\\<用户名>\\.dsh\\profiles\\desktop"]}
```

修复后（`ctx.get('workingDirectory')` → `ensure()` → `wd.get(session)` → `agent.session.header.cwd`
→ `wd.defaultDirectory` 四级回落 + 「工作区不可能位于 `.dsh` 内」的硬兜底），
同一类调用的基准变为：

```json
{"tool":"pwsh","plan":"scope","zone":"workspace","targets":["<工作区>"],"decision":"allow","batchId":null}
```

### 4.7 保护目录优先级

`evaluate()` 中受保护目录检查位于「工作区不保护」短路**之前**
（`lib/gate.js`：先 `assertNotProtected`，再判断 `zone === ZONE.WORKSPACE`）。
该顺序由用例 `受保护目录优先于「工作区不保护」的短路` 守护，当前通过。

---

## 五、复跑方法

1. 确认插件已启用（`plugin_manager list_plugins` 或设置页可见）。
2. `status` 自检：
   ```
   node "bin\delete-guard.mjs" status
   ```
3. 自动化测试**必须逐个文件跑**：
   ```
   node test/core.test.mjs      # 22 pass / 0 fail
   node test/gate.test.mjs      #  7 pass / 0 fail
   node test/protect.test.mjs   #  5 pass / 0 fail
   ```
   > 不要用 `node --test test/`：本机沙箱下该形式会用 piped stdio 起子进程，
   > 报 `spawn EPERM`（`errno: -4048`），不是测试失败。
4. 审计日志：`backup\_audit\YYYY-MM-DD.jsonl`。
5. 还原/校验脚本：`fixtures\_dg-run\restore-runner.mjs`、`verify-batch.mjs`（仅测试用，不属于插件交付物）。
6. 若需要修改插件源码：先由用户在「设置 → 插件」停用（插件目录受自保护，模型无法改写）。

---

## 六、已知未覆盖项

- `cmd.exe` 的 `del` / `rd`、PTY 终端、`python -E/-I`、清空环境的子进程、第三方进程；
- 完全权限下的任意代码写入（同权限边界，插件不是 OS 级防篡改）；
- 插件未加载或崩溃时没有门禁；
- 「备份根不可写 → 阻断」只有代码分支保证（`initError` / `!ready`），当前无自动化用例；
- `.dsh` 区域的静默备份与分区保留（只保留最新 10 个 / 30 天）未在自动化测试中覆盖，
  仅有代码实现（`lib/backup.js` 的 `cleanup` 与 `readBatchZone`）；
- HTTP 路由的同源校验（`Origin` 与 `Host` 不一致 → 403）与 `Content-Type` 强制
  只做过手工验证，未进自动化测试。
