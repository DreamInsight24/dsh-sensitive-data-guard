# 敏感数据守卫 测试报告

- 报告日期：2026-11-05（Asia/Shanghai；审计日志时间戳为 UTC）
- 机器：本机 Windows，DSH Desktop 0.2.1-rc.2，profile `desktop`
  （0.2.5 的兼容性复核与回归测试改在 DSH Desktop 0.2.2-rc.1 上执行，见第十节；
  0.2.6 的未知工具信任流程在同一环境上回归，见第十一节）
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

---

## 七、v0.2.2 修订：PowerShell .NET 删除绕过（2026-11-05）

### 7.1 实测发现的绕过

一轮手工实测用下面的命令删除 `D:\Zip\test` 下的 12 个文件，守卫**没有拦住**：

```powershell
$target = 'D:\Zip\test'
Get-ChildItem -LiteralPath $target -File -Force | ForEach-Object {
  try { [System.IO.File]::Delete($_.FullName); Write-Output ("DELETED: " + $_.FullName) }
  catch { Write-Output ("FAILED: " + $_.FullName + " :: " + $_.Exception.Message) }
}
```

12 个文件全部被永久删除，无备份、无提醒、无确认码。

### 7.2 根因（审计日志证据）

审计里对应的三条 `gate` 事件都是：

```json
{"plan":"scope","zone":"workspace","targets":["D:\\dsh-workspaces"],"decision":"allow"}
```

- 分类器（`lib/classify.js`）只认 `Remove-Item` / `rm` / `rd` / `del` 这类命令，
  **没有任何规则覆盖 PowerShell 的 .NET 文件 API**（`[IO.File]::Delete`、
  `[IO.Directory]::Delete`、`::Move`、`::Copy`）。
- `[System.IO.File]::Delete($_.FullName)` 落在语句 `try { … }` 里，被当成未知命令；
  未知命令按 `opaqueCommand: 'scope'` 把**整个工作目录**当作范围。
- 工作区在区域模型里是「完全不保护」，于是 `zone=workspace` → 放行。
  **真实目标 `D:\Zip\test` 从头到尾没有被解析出来**，区域判定根本没有机会生效。

### 7.3 修复

| 位置 | 改动 |
|---|---|
| `lib/classify.js` | 新增 `scanPowershellFileApi()`：识别 `[System.IO.*]` / `[IO.*]` 的 `File`/`FileInfo`/`Directory`/`DirectoryInfo` 上的 `Delete`/`Move`/`Copy`，扫描整条语句（含 `try { }` / `ForEach-Object { }` 包裹） |
| `lib/classify.js` | 字面量路径 → `targets`（走正常区域流程）；**目标是变量/表达式 → `deny`（fail-closed）**，不再回落成工作区 scope |
| `lib/classify.js` | 新增 `scanCodeWrites()`：解释器里的 `fs.writeFileSync/appendFileSync/copyFileSync/renameSync`、`fs/promises`、`python open(...,'w'/'a'/'x')`、`shutil.copy/copy2/copyfile/move`、`os.rename/os.replace` → 已存在的目标按 `interpreter:write` 处理 |

> 第二项是关键：实测那条命令用的是 `$_.FullName`（变量路径），只加字面量提取挡不住。

### 7.4 新增用例与结果

| 文件 | 用例数 | 通过 | 失败 |
|---|---:|---:|---:|
| `test/core.test.mjs` | 29 | 29 | 0 |
| `test/gate.test.mjs` | 8 | 8 | 0 |
| `test/protect.test.mjs` | 5 | 5 | 0 |
| **合计** | **42** | **42** | **0** |

新增（相对 0.2.1）：

- `core`：`.NET` 字面量删除 / 短类型名+目录递归 / **变量路径删除 → deny（实测回归）** /
  `.NET Move/Copy` / 解释器覆盖已存在文件 / 解释器新建文件 / 解释器只读 `open`；
- `gate`：端到端回归——用 7.1 的原命令形态打在敏感区，断言 `deny` 且文件仍在；
  再验证字面量路径会走「备份 + 确认码」，带码重发放行并复用同一批次。

### 7.5 仍未覆盖

- 解释器写入的**动态路径**（`fs.writeFileSync(path.join(...))`）仍退化成 `scope`；
- 任意外部程序（`D:\tools\cleanup.exe D:\Zip\test`）仍退化成 `scope` → 工作区放行；
  需要更严可以把 `policy.opaqueCommand` 改成 `block`（代价是 `npm run build` 这类命令也会被拦）。

---

## 八、v0.2.3 修订：解析优先 + 解析不出转确认码（2026-11-06）

### 8.1 触发原因

0.2.2 把「.NET 删除但目标是变量」一律 `deny`，堵住了绕过，但代价是**正常操作被卡死**：
用户看到的是一个没有上下文的 fail-closed，既不知道模型想删什么，也没有申诉通道。
同时第二轮外部审阅指出四个具体缺陷，逐条复核后**全部成立**：

| 审阅意见 | 复核结果 |
|---|---|
| `Remove-Item -LiteralPath $target` 落到 `scope=workspace` | 成立：`resolveMaybe` 见 `$` 直接返回 null，路径丢失 |
| `Get-ChildItem X \| Remove-Item -Force` 丢掉管道源 | 成立：语句按 `\|` 切开，下游拿不到 X |
| `robocopy X Y /MOVE` 被判 `safe` | 成立：`/MOVE` 被当成 mirror 的别名，目标不存在就 `planSafe` |
| `node <脚本>` 扫全文 → 字符串里的删除字样误报 | 成立：`scanCode` 是纯正则全文扫描 |

### 8.2 改动

| 位置 | 改动 |
|---|---|
| `lib/classify.js` | **变量表**：`$x = '字面量'` 记入 `collectVars()`，`resolveMaybe` 能还原 `$x` |
| `lib/classify.js` | **管道回溯**：`splitStatementsRaw()` 记录每条语句是否仍在同一段构造里（管道接出，或处在未闭合的 `{ }` 内）；上游 `Get-ChildItem/dir/ls/get-item/resolve-path` 的路径借给下游无参删除，`$_.FullName` 同理 |
| `lib/classify.js` | **`robocopy /MOVE`**：源目录纳入 `targets`（`/MOVE`、`/MOV` 会删源） |
| `lib/classify.js` | **字符串/注释屏蔽**：`codeFlags()` 标记引号与注释区间，`scanCode`/`scanCodeWrites` 只认代码位置上的调用；出现 `eval`/`exec`/`child_process` 时退回全文扫描 |
| `lib/classify.js` | **`-File` 参数名冲突**：`Get-ChildItem -File -Force` 曾把 `-Force` 当路径（解析出 `\‑Force`）；现在开关后跟开关时不再取值 |
| `lib/classify.js` | 新增 `planConfirm` + `planUnresolved`：目标解析不出时按 `policy.unresolvedAction` 返回 `confirm`（默认）/ `deny` / `scope` |
| `lib/gate.js` | 新增 `guardUnresolved()`：与 `guardSensitive` 同构的确认码流程，但**不备份**，放行令牌带 `roots: []` + `allowAll: true` |
| `lib/confirm.js` | 新增未解析报告：把「❗ 本次没有备份」放在正文最前，并原样附上命令文本 |
| hooks | Node/Python 钩子识别允许清单里的 `allowAll`（只由 `guardUnresolved` 写出） |
| `lib/defaults.js` / `config.schema.json` | `policy.unresolvedAction`：`confirm`（默认）/ `deny` / `scope` |

### 8.3 新增用例与结果

| 文件 | 用例数 | 通过 | 失败 |
|---|---:|---:|---:|
| `test/core.test.mjs` | 37 | 37 | 0 |
| `test/gate.test.mjs` | 9 | 9 | 0 |
| `test/protect.test.mjs` | 5 | 5 | 0 |
| **合计** | **51** | **51** | **0** |

新增（相对 0.2.2）：

- `core`：变量表 / 管道回溯 / 无上游仍回落 `scope` / `robocopy /MOVE` /
  字符串与注释不触发 / 真删除仍认得出 / 解析不出 → `confirm`（含 `deny` 严格模式）/
  临时目录不追问；7.1 的原命令形态现在断言 `targets=['D:\Zip\test']`（能备份了）；
- `gate`：7.1 的命令形态改为「备份 + 确认码 → 带码放行复用批次」；
  新增「未解析 → 确认码（无备份）」全流程：报告含「没有备份」、错码被拒、正码放行且
  令牌 `allowAll=true`、shell 深度层写出的允许清单也带 `allowAll`。

### 8.4 仍未覆盖

- 解释器内部**动态路径**（`fs.rmSync(p)`）仍是 `scope`；这类靠 L2 钩子在运行时兜底，
  只有 PowerShell 原生的 .NET 删除没有钩子可兜，所以只有它走到了确认码流程；
- 字符串屏蔽是启发式的，`eval`/`child_process` 存在时退回全文扫描（宁可误报）。


---

## 九、v0.2.4 修订：确认码换成直接弹窗（2026-11-06）

### 9.1 触发原因

0.2.3 的确认码写在**工具返回值**里。用户实测后指出：模型自己就读得到那个 4 位码，
也完全可以自己填回去——「人在环路里」实际上没成立。要求改成「立刻弹给用户、
Agent 看不见、用户在弹窗里直接允许或拦截，不需要和 Agent 交互」。

### 9.2 依据（对着 DSH 源码核过）

从 `app.asar` 里取出 `@deepseek-ai/dsh-user-questions`、`@deepseek-ai/dsh-tool-ask-user`、
`@deepseek-ai/dsh-client-ui-user-questions` 三个包确认：

- `ctx.userQuestions.ask({ questions, agent, signal })` 是 `ask_user_question` 工具自己的通道，
  返回值**只回到调用方**；不带 `wait.callId` 时客户端仍会建卡片，settle 后移除。
- 客户端渲染 `header / question / detail / options`，`detail` 用 `<Text>` 原样显示（可多行），
  正好用来放删除清单与备份信息。
- `ask()` 要求传真实存活的**根**代理：`CALLER_NOT_LIVE` / `DELEGATED_CALLER` 直接抛错，
  所以子代理问不到人，天然 fail-closed。

### 9.3 改动

| 位置 | 改动 |
|---|---|
| `lib/gate.js` | 新增 `askHuman()`：走 `ctx.get('userQuestions').ask()`，只认「允许执行」一个选项；超时与 `exec.signal` 用 `AbortSignal.any` 合并；任何异常/拒绝都返回不放行 |
| `lib/gate.js` | 新增 `promptUser()`：把弹窗结果映射成 allow/deny，审计记 `popup-allowed` / `popup-rejected` / `popup-unavailable` |
| `lib/gate.js` | `guardSensitive()` / `guardUnresolved()` 在 `confirmVia: 'popup'` 下改为弹窗；`code` 模式保留旧流程 |
| `lib/gate.js` | 新增 `liveAgentOf(sessionId)`：shell 深度层没有 exec 里的 agent，按会话把它换回来 |
| `lib/confirm.js` | 新增 `buildPromptDetail()`（弹窗正文，不含确认码）、`buildDeclinedText()`、`buildUnavailableText()` |
| `lib/defaults.js` / `config.schema.json` | 新增 `policy.confirmVia`（popup 默认 / code）、`policy.confirmTimeoutMs`（默认 5 分钟） |

### 9.4 新增用例与结果

| 文件 | 用例数 | 通过 | 失败 |
|---|---:|---:|---:|
| `test/core.test.mjs` | 37 | 37 | 0 |
| `test/gate.test.mjs` | 13 | 13 | 0 |
| `test/protect.test.mjs` | 5 | 5 | 0 |
| **合计** | **55** | **55** | **0** |

新增：

- `gate`：用户点「允许执行」→ 直接放行且**全程没有确认码**（并断言弹窗正文里带目标路径与备份信息）；
- `gate`：用户点「拦截」→ 阻断且不下发确认码；
- `gate`：问答服务报 `NO_PROVIDER`（没有 UI 客户端）→ fail-closed 阻断；
- `gate`：目标解析不出时同样弹窗，正文含「没有备份」，令牌带 `allowAll`。

原有的三条确认码用例改为显式 `confirmVia: 'code'`，保证旧通道不回归。

### 9.5 仍未覆盖

- 真机弹窗的**视觉呈现**只能人工确认（自动化测试用假 `userQuestions` 校验的是决策链）；
- 关掉浏览器/纯 CLI 时无法弹窗，按设计一律阻断（可切 `confirmVia: 'code'`）。


---

## 十、v0.2.5：DSH 0.2.2-rc.1 兼容性复核 + 文案修正（2026-11-06）

### 10.1 兼容性复核（对着 0.2.2-rc.1 的 `app.asar` 逐项核过）

从 `resources\app.asar` 重新索引并取出相关包，确认本插件用到的接口全部未变：

| 接口 | 0.2.2-rc.1 状态 |
|---|---|
| `tools/pre-execute` 瀑布（`exec, next` → `{kind:'allow'\|'deny'\|'cancel'\|'ask'}`） | 未变（`dsh-tools/lib/pipeline.js`） |
| `tools/post-execute` 瀑布（`{kind:'accept',content}` / `{kind:'block',feedback}`） | 未变 |
| `ctx.tools.guard(exec) → string \| undefined` | 未变 |
| `ctx.shell.execute(spec)`，`ShellExecSpec.env` / `sandboxPolicy.sessionId` | 未变（`dsh-shell`） |
| `dsh-tool-pwsh` / `dsh-tool-bash` 仍调用 `ctx.shell.execute` | 是（shell 深度层仍然拦得到） |
| `ctx.webServer.register({kind,path,handler})` | 未变（`dsh-host-webserver`） |
| `ctx.get('userQuestions').ask({questions,agent,signal})` | 未变，仍要求真实存活根代理（`CALLER_NOT_LIVE` / `DELEGATED_CALLER` / `NO_PROVIDER`） |
| `ctx.get('agents').get(id)` / `.roots()` | 未变 |
| `ctx.get('workingDirectory')` | 未变 |
| Client `slots` 服务与 `settings.section` / `plugins.bundle.config` 两个槽位 | 未变，注册项要求一致 |
| `plugin_manager` 的 `set_plugin` / `set_bundle` / `install_bundle` / `remove_bundle` | 未变，自保护仍然有效 |

两处需要注意：

- `@deepseek-ai/dsh-client-ui-slots` **不在 0.2.2-rc.1 的发行包里**。`dsh.client.inject` 里
  解析不到的模块会被静默跳过（`client-modules` 的 `arriveGraphRow`：`if (dependency !== void 0)`），
  所以旧版只是多写了一行无效条目，不影响加载；0.2.5 已删掉它。
- `config.schema.json` **DSH 从不读取**：整个 `app.asar` 里搜不到 `config.schema.json` 这个文件名，
  配置校验来自插件导出的 `Config`（本插件刻意不导出，因为本地 bundle 无法 import
  `@deepseek-ai/schemastery`）。该文件自 0.2.5 起标注为「仅供参考」。

### 10.2 文案修正

0.2.4 把默认确认通道换成弹窗后，多处**用户可见**文案仍写着「4 位确认码」，与默认行为不符。
0.2.5 改为「弹窗确认」：`locale/zh.json`、`locale/en.json`、`client.js`（设置页说明、
插件页摘要、放宽告警）、`lib/settings.js` 的 `LEVEL_SCOPE`、`cordis.patch.yml` 注释、
`bin/delete-guard.mjs` 的 dry-run 提示、`config.schema.json` 描述。

### 10.3 回归测试

| 文件 | 用例数 | 通过 | 失败 |
|---|---:|---:|---:|
| `test/core.test.mjs` | 37 | 37 | 0 |
| `test/gate.test.mjs` | 13 | 13 | 0 |
| `test/protect.test.mjs` | 5 | 5 | 0 |
| **合计** | **55** | **55** | **0** |

### 10.4 仍未覆盖

- 真机弹窗在 0.2.2-rc.1 上的视觉呈现与交互仍只能人工确认；
- 本 profile 未安装 `tool-pwsh-persistent`，该工具走 `ctx.terminals` 而非 `ctx.shell`，
  shell 深度层覆盖不到（0.2.5 已写入 README 的边界清单）。

---

## 十一、v0.2.6：未知工具改成「弹窗信任」（2026-11-06）

### 11.1 触发原因

用户本地插件工具 `config2ds` 被默认的 `unknownTool: 'deny'` 拦下。`policy.safeTools` 虽然存在，
但分类器从不读它，等于死配置；而一律阻断又会让所有第三方插件工具不可用。

### 11.2 改动与用例

- `lib/classify.js`：新增 `isWhitelistableTool()` / `isWhitelistedTool()` / `unknownToolAction()`；
  `planToolCall()` 与 `quickClassify()` 都接上 `policy.safeTools`；已知破坏性工具与 `plugin_manager` 不能加白。
- `lib/gate.js`：新增 `guardUnknownTool()`（弹窗正文含工具名、注册说明、参数结构、本次调用参数）、
  `trustTool()`（写 `data/settings.json`）、`toolInfo()`；`evaluate()` 的 unknown 分支支持 `prompt`；
  `askHuman()` 改为返回选中项，`promptUser()` 适配；受信任工具仍过保护目录检查。
- `lib/settings.js`：`sanitizePatch()` 接受并过滤 `safeTools`。
- `client.js`：设置页新增「受信任的工具」卡片。
- `bin/delete-guard.mjs`：dry-run 报告未知工具的新处置。

| 文件 | 用例数 | 通过 | 失败 |
|---|---:|---:|---:|
| `test/core.test.mjs` | 38 | 38 | 0 |
| `test/gate.test.mjs` | 21 | 21 | 0 |
| `test/protect.test.mjs` | 5 | 5 | 0 |
| **合计** | **64** | **64** | **0** |

新增用例：

- `core`：`safeTools` 白名单 → safe；已知破坏性工具加白无效；
- `gate`：弹窗摊开工具说明与本次参数、信任后写入设置文件并不再询问、仅本次允许、
  用户拦截、弹窗不可达 fail-closed、`unknownTool=deny` 不弹窗、受信任工具不能碰保护目录、
  设置页空数组不清空配置底线。

### 11.3 仍未覆盖

- 真机弹窗的视觉呈现只能人工确认；
- 「信任并加入白名单」后，该工具的实际行为不再被守卫检查（设计使然，只能靠弹窗里的信息让用户判断）。