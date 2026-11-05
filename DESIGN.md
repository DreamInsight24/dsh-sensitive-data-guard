# 敏感数据守卫 · 设计说明

> 这份文档解释「为什么这样设计」，以及每个判断发生在代码的哪一层。
> 面向要改代码的人；只想用的话看 `README.md`。
> 目标机器：Windows，DSH Desktop 0.2.1-rc.2（desktop profile）。

代码位置：`<插件目录>`；包名 `@local/dsh-sensitive-data-guard`。

> 下文 `<插件目录>` 指本插件所在目录（即 `package.json` 所在处）；`bin/...`、`backup/` 这类相对路径都相对于它——换机器、换安装位置都不用改。

---

## 1. 目标与非目标

**目标**：DSH 即使处在 `danger-full-access`、审批策略为 `never`、模型完全失控的情况下，
**也不能在用户不知情时删掉/覆盖工作区之外的数据**。每一次这样的操作都要：
先备份 → 把「要删什么、多大、备份在哪」摆到用户面前 → 用户输入随机码 → 才放行。

**非目标**（明确不做，做了就是负担）：

- 不保护工作区内部。工作区是模型该干活的地方，加门禁只会让每次重构都多一步。
- 不做 OS 级防篡改（不装驱动、不改 ACL、不动影子副本/还原点/Sysmon 配置）。
- 不做「备份必然可还原」的承诺——备份失败时宁可阻断，也不假装成功。
- 不阻止用户自己动手（CLI、资源管理器、别的终端）。

---

## 2. 不变量

1. **fail-closed**：判定链上任何异常、超时、初始化失败、配额不足、`ready=false` → `deny`。
2. **先备份，后拦截**：报告里的备份必须已经落盘（可还原），才允许展示确认码。
3. **确认码一次性**：用过即失效；错误码不会触发重新备份。
4. **保护目录优先**：任何区域判定、任何级别、任何工具都绕不过保护目录检查。
5. **工作区基准必须真实**：取不到真实工作目录时按敏感区处理，不允许乐观假设。
6. **配置是底线，UI 只能加码**：设置页不能删掉配置文件里声明的保护目录。

---

## 3. 区域模型

`lib/zones.js`，三个区域 + 一个排序：

```js
ZONE = { WORKSPACE: 'workspace', DSH: 'dsh', SENSITIVE: 'sensitive' }
RANK = { workspace: 0, dsh: 1, sensitive: 2 }
```

判定（`classifyZone`）：先看是否在工作区内，再看是否在 `.dsh` 内，都不是 → `sensitive`。
多目标用 `strictestZoneOf` 取最高 rank——一次操作里只要有一个敏感目标，整次按敏感处理。

`dshHomeOf(explicit)` 的取值顺序：配置 `policy.dshHome` → `$DSH_HOME` →
`dirname($DSH_PROFILE_DIR)` → `~/.dsh`。

### 3.1 工作区基准（`cwdFor`）——这里踩过大坑

桌面版里 `process.cwd()` 是 profile 目录（`C:\Users\<u>\.dsh\profiles\desktop`），
**它本身就在 `.dsh` 里面**。早期实现把它当工作区根，结果：

- 工作区里的删除被判定成 `sensitive` → 每次都要确认码（烦）；
- 审计里出现 `zone:"workspace" targets:["C:\Users\...\.dsh\profiles\desktop"]`（错）。

现在的回落链（按可信度递减，逐层 try）：

1. `ctx.get('workingDirectory')`（可选服务，取不到为 `undefined`）
2. `wd.ensure(agent, exec.signal)` —— 最权威，会真正建目录
3. `wd.get(session)`（`agent.session` 或 `ctx.sessions.get(agent.id)`）
4. `wd.defaultDirectory`（字符串）
5. `agent.session.header.cwd`（Session 头里记的 cwd）
6. `process.cwd()`（最后兜底）

再加一层**结构性保护**（`zoneForRoots`）：工作区根**不可能**落在 `.dsh` 里面；
如果命中的候选值在 `dshHome` 内，直接丢弃该候选（置 `null`），于是没有工作区，
所有目标按 `sensitive` 处理。宁可多问一次，也不能误判成「无需保护」。

### 3.2 区域与保护目录的顺序

`evaluate()` 与 `prepareShell()` 里都是：**先 `assertNotProtected`，再判断 `zone === workspace` 短路**。
反面教材（0.2.0 修掉的回归）：先短路放行，导致「正好放在工作区里的插件目录」可以被删掉。
现在有专门的回归测试守着。

---

## 4. 决策流程

### 4.1 工具门禁（`tools/pre-execute` → `evaluate()`）

```
disposed / !enabled            → allow（并审计）
emergencyBypass                → allow（并审计）
planToolCall(...)              → safe | targets | scope | deny | unknown
  unknown                      → policy.unknownTool: deny | allow-audit
  deny                         → deny
  safe                         → 仍对 write/edit/move/delete 做保护目录检查 → allow
  targets/scope                → 见下
```

对 `targets | scope`：

```
roots = targets | [scope]
zone  = zoneForRoots(roots, workdir)   // 多目标取最严格；工作区根在 .dsh 内则丢弃
assertNotProtected(每个 root)           // ← 先于区域短路
zone === workspace && workspaceMode==='none'
    → 登记令牌（roots 含 workdir）→ allow（不备份、不提醒）
!ready / initError → deny（fail-closed）
guardSensitive(...) → allow | deny(报告)
```

工作区分支仍然要 `issueToken`：python / node 钩子靠这份「允许清单」放行，
否则子进程会自己把工作区里的删除拦掉（这也是修过的回归）。

### 4.2 决策表

| 区域 | `soft` | `medium`（未达阈值） | `medium`（达阈值） | `hard` |
|---|---|---|---|---|
| 工作区 | allow | allow | allow | allow |
| `.dsh` | allow + 静默备份 | 同左 | 同左 | 同左 |
| 敏感区 | allow + 备份 | allow + 备份 | **deny + 确认码** | **deny + 确认码** |
| 目标解析不出 | **deny + 确认码（无备份）** | 同左 | 同左 | 同左 |
| 保护目录 | deny | deny | deny | deny |

`needsConfirm(zone, stats)` 只在 `zone === sensitive` 时可能为真；
`medium` 的阈值是「文件数 ≥ `mediumMinFiles` **或** 体积 ≥ `mediumMinBytes`」。

「目标解析不出」（`plan.kind === 'confirm'`）走 `guardUnresolved()`，与 `guardSensitive()` 的差别：

| | `guardSensitive` | `guardUnresolved` |
|---|---|---|
| 备份 | 先备份（可 `restore`） | **不备份**（目标运行时才确定） |
| 触发条件 | 区域 + 级别 | 分类器拿不到字面量目标 |
| 报告 | 「已提前备份 + 批次号」 | 「❗ 本次没有备份」置于正文最前 |
| 放行令牌 | `roots = 备份根集` | `roots = []` + **`allowAll: true`** |

`allowAll` 只在这条路径上出现，作用是让确认过的命令派生出的 python/node 子进程不被
L2 钩子全拒（否则「确认了也执行不了」）。它等价于「用户对这条命令的删除范围负全责」。
策略开关 `policy.unresolvedAction`：`confirm`（默认）/ `deny` / `scope`。

### 4.3 兜底层

- 同步 `ctx.tools.guard()`：只否决，没有令牌的破坏性调用直接拦（异步判定漏了也跑不掉）。
- shell 深度层 `prepareShell()`：包装 `ctx.shell` 实例的 `execute`，原始方法挂在
  `Symbol.for('dsh.delete-guard.shell-original')` 上（热重载不叠加包装）。逻辑与 `evaluate()` 同构，
  差别是判定对象为 `spec.command` 文本，令牌按 `sessionId|workdir|command` 缓存一次，
  被拒则**抛错**（命令根本不会 spawn），放行则注入 `PYTHONPATH` / `NODE_OPTIONS`
  与临时允许清单（`_ipc`，30 分钟过期）。
- 运行时钩子（L2）：子进程里的 `os.remove / shutil.rmtree / fs.rmSync / fs.rename …`
  先查允许清单与实际范围，越界即抛错。
- 结果摘要（`tools/post-execute`）：把「谁、删了什么、备份在哪、怎么还原」回给用户。

---

## 5. 确认码子系统（`lib/confirm.js`）

**通道**：环境变量前缀，写在命令文本里。

```powershell
$env:DSH_GUARD_CONFIRM='4821'; Remove-Item -Recurse -Force D:\项目\旧版本
```

`extractConfirmCode()` 识别 `$env:DSH_GUARD_CONFIRM='1234';`、`DSH_GUARD_CONFIRM=1234`、
`set DSH_GUARD_CONFIRM=1234` 三种写法，并把这段从命令里**剥离**后再算指纹。

**指纹**：`fingerprintOf({toolName, command, args})` = `` `${toolName}|${剥离确认码并压空白后的命令}` ``。
只有「同一条命令 + 同一次会话」才能对上；改一个字符就不算同一次。

**存储**：`Map<`${sessionId}|${fingerprint}`, entry>`，
`entry = {code, expiresAt, batchId, batchDir, zone, stats, targets}`。

| 操作 | 行为 |
|---|---|
| `issue` | 生成 4 位数字（不足补 0），TTL 10 分钟，同一指纹覆盖旧条目 |
| `verify` | 命中 → **删除条目**（一次性）并返回 entry；否则 `null` |
| `peek` | 只查是否存在（用于区分「码错」与「已过期」） |
| `prune` | 惰性清理过期条目 |

**三种重发结果**：

1. 码对 → 放行，复用 `entry.batchId` 的备份，**不重新备份**，审计 `confirm/ok`。
2. 码错且仍有挂起条目 → 直接 `deny`（提示用上次报告的码），**不重新备份**，审计 `confirm/wrong-code`。
3. 已过期（无挂起条目）→ 走正常流程：重新备份 + 新码。

**报告**：`buildReport()` 固定顺序——区域/级别 → 逐目录「文件数 + 体积」→ 合计 →
备份批次号 → 备份目录 → 还原命令 → **确认码（最后一行）**。

---

## 6. 备份引擎（`lib/backup.js`）

```
<root>/_store/<aa>/<bb>/<sha256>     内容寻址对象库（去重）
<root>/<yyyy-mm-dd>/<session>/<seq>/ 批次
    manifest.jsonl                   batch 头（含 zone）/ 逐条记录 / summary 尾
    tree/<drive>/<rel>               硬链接镜像（跨卷退化为复制）
<root>/_audit/<yyyy-mm-dd>.jsonl
<root>/_state/  <root>/_ipc/
```

- 单文件 256 MiB、单批 10 GiB / 5 万文件、总量 50 GiB；超限默认 `block`。
- `verify: true` → 复制后校验大小，还原时校验 SHA-256。
- 符号链接/junction 只记录 `linkTarget`，不跟随（`followSymlinks: false`）。
- `perRoot`：每个 root 的文件数/字节数，直接喂给确认报告。
- 空批次（只有目录/链接，没有可备份文件）也返回 `batchId` + `zone` + `perRoot`，
  报告才不会退化成一句「无可备份文件」。

### 6.1 按区域清理（`cleanup()`）

```
遍历所有批次 → { zone（读 manifest 头）, mtime }
zone === 'dsh'  → 保留最新 dshRetentionCount(10) 个，且不超过 dshRetentionDays(30) 天
其它            → 保留 retentionDays(30) 天
最后收集被清空的 session/date 目录并删掉
```

工作区批次根本不存在（工作区不备份），所以没有第三套策略；审计日志不参与清理。

---

## 7. 设置子系统

### 7.1 三个来源与合并规则

```
生效值 = DEFAULTS  ←  cordis.patch.yml 的 config  ←  data/settings.json（设置页）
```

但**保护目录是例外**：它用的是并集，不是覆盖。

```js
policy.protectedPaths = dedupe(baseProtectedPaths ∪ uiProtectedPaths)
```

- `baseProtectedPaths`：来自 `cordis.patch.yml` / profile 覆盖配置，是**部署底线**。
- `uiProtectedPaths`：来自 `data/settings.json`，是用户在设置页里追加的。

这条规则是 0.2.1 修的 bug：早期实现让 `settings.json` 里的数组**直接覆盖**配置，
而设置页每次保存都会带上 `protectedPaths`，于是用户在设置页点过一次保存之后，
配置文件里写的保护目录就被永久清空了（`assertNotProtected` 再也不抛错）。
现在：空数组不会清空底线，UI 追加项与底线合并，UI 清空只删掉自己那一份。

### 7.2 校验

`lib/settings.js`：

- `LEVELS = ['soft','medium','hard']`，`LEVEL_SCOPE` 是每档的小字说明（UI 直接显示）。
- `sanitizePatch()` **只接受已知字段**，非法值抛错而不是静默纠正
  （`triggerLevel` 必须三选一；阈值必须是非负有限数；`protectedPaths` 必须是字符串数组，逐行 trim 去空）。
- `isLoosening(from, to)`：`levelRank` 越小越松。

### 7.3 运行时

`GateCore` 构造时 `applySettingsOverlay()` 叠加 `data/settings.json` 并 `refreshProtectedPaths()`；
`applySettings()` 校验 → 写入 → 重算 → 记录 `settings` 审计（带 `before/after/loosened`）。

构造函数第三个参数 `options.settingsDir` 可以改设置文件位置，**只有测试用**它做隔离
（默认仍是插件目录）。

### 7.4 HTTP 通道（`lib/http-settings.js`）

- 路由：`/plugins/dsh-sensitive-data-guard/settings`（`kind: 'exact'`，`ctx.inject(['webServer'])`）。
- `GET` → `settingsSnapshot()`；`POST/PUT` → 要求 `content-type: application/json`（否则 415）→ `applySettings`。
- 同源校验：有 `Origin` 时必须与 `Host` 一致，否则 403。跨站页面发 JSON POST 会先触发 CORS 预检，
  而我们不应答预检——等于挡掉。
- 请求体上限 64 KiB；`cache-control: no-store`。
- `webServer` 不存在时整块跳过，门禁照常工作（可选依赖）。

---

## 8. Client 半（`client.js`）

两个注册点，同一个表单组件：

| 位置 | slot | 注册参数 |
|---|---|---|
| 设置面板独立一节 | `settings.section` | `id: 'dsh-sensitive-data-guard'`, `order: 25`, `label: '敏感数据守卫'` |
| 插件 → 本插件页面 | `plugins.bundle.config` | `key: '@local/dsh-sensitive-data-guard'` |

`plugins.bundle.config` 的 owner 会传 `view: 'summary' | 'page'`：
`summary` 只渲染一行小字（列表里用），`page` 渲染完整表单（去掉大标题，页面本身已有插件名和描述）。

表单内容：级别单选（每档带 `levelScope` 小字）、阈值输入（仅 `medium` 显示）、
保护目录文本框（一行一个，支持 `!`）、**配置文件底线的只读展示**、保存/重新读取、
放宽时的红字警告、底部 `.dsh 位置 / 备份根 / 保留策略 / 设置文件` 信息块。

客户端「放宽预判」：`LEVEL_ORDER.indexOf(待选) < indexOf(当前)` 时立刻显示红字，
不必等保存——服务端返回 `loosened: true` 时再显示一次。

---

## 9. 自保护

- 自动进入 `protectedRoots`：插件目录、备份根、审计目录、profile 配置文件。
- `assertNotProtected()` 先把两边都 `realpath` 再比，符号链接骗不过去；
  `targets` 模式下还额外检查「删这个会不会连坐受保护目录」（`isInside(resolved, guard)`）。
- `classify.js` 里的 `SELF_NAME_RE = /delete-guard|sensitive-data-guard|dsh-guard/i`
  让 `plugin_manager` 对自身包名的卸载/替换被判为受保护操作；`ADMIN_CLI_RE` 同理放行 CLI 自身。
- 代价（明确接受）：模型改不了这个目录，连修文档都不行；需要用户停用后才能改。
  这是「守卫不能被守卫对象改写」的必然结果。

---

## 10. 失败模式

| 情况 | 结果 |
|---|---|
| 备份初始化失败（磁盘满/权限） | 该次及之后所有敏感操作 `deny`（`initError`） |
| 门禁未就绪（`ready=false`） | `deny` |
| 备份过程中抛错 | `deny`（不降级为警告） |
| 目标命中保护目录 | `deny` |
| 未知工具 | 默认 `deny` |
| 命令解析不出目标 | 按 `scope` 备份整个工作目录，再决定 |
| 认出是 .NET 删除/移动/复制，但目标是变量/表达式 | `deny`（不回落成工作区 scope） |
| 用户 `emergencyBypass` | 全部放行，仅审计（手工改配置才能开） |
| 插件被停用/卸载 | 立即失效；`dispose()` 置位后残留包装层也短路成放行，并还原 `ctx.shell.execute` |

---

## 11. 审计

`_audit/<date>.jsonl`，每行一个事件：

| event | 关键字段 |
|---|---|
| `gate` | tool, callId, sessionId, plan, **zone**, targets, decision, batchId, reason |
| `backup` | batchId, count, bytes, **zone**, missing, durationMs |
| `confirm` | result: `ok` / `wrong-code`, batchId |
| `confirm-required` | batchId, files, bytes, **zone** |
| `settings` | by: `ui`, before, after, loosened, patch |
| `bypass` / `restore` / `sysmon` | 见对应实现 |

`plan:"scope" zone:"workspace" targets:[...]` 这一行是排查区域误判的第一现场。

---

## 12. 测试策略

51 个用例，全部离线（不依赖 DSH Host），按文件直接跑：

| 文件 | 数量 | 关注点 |
|---|---|---|
| `test/core.test.mjs` | 37 | 分类器、路径、备份引擎、配额、manifest、还原、审计；0.2.3 新增变量表、管道回溯、`robocopy /MOVE`、字符串/注释屏蔽、`confirm` 判定 |
| `test/gate.test.mjs` | 9 | 钩子接线、区域模型+确认码全流程、.NET 删除回归、**未解析目标 → 确认码（无备份 + `allowAll`）**、受保护目录优先于工作区短路、设置覆盖不得清空配置底线、`cwdFor` 回落、非法 cwd、fail-closed |
| `test/protect.test.mjs` | 5 | `.gitignore` 风格保护模式（含 `!`、跨层、连坐） |

本机沙箱下 `node --test test/` 会因 piped stdio 报 `spawn EPERM`，必须逐文件执行。
测试用 `options.settingsDir` 指向临时目录，**不能**读仓库里的 `data/settings.json`——
否则用户在设置页点一次保存，测试结果就会跟着变（这次 bug 就是这么暴露的）。

---

## 13. 已知边界

1. 解释器写入：字面量路径的 `node -e "fs.writeFileSync('D:\a.txt',…)"`、
   `python -c "open('D:/a.txt','w')"` 已纳入备份/保护目录检查；目标由变量或表达式拼出时
   仍只能退化成 `scope`。自保护防的是删除/卸载与字面量改写，不是防同权限改写。
2. `cmd /c del`、native 二进制 unlink：只能靠文本解析，可能退化成 scope 备份。
3. 插件没加载时没有门禁；DSH 没有「插件死了也 fail-closed」的机制。
4. 与本机 DSH 无关的第三方进程删文件，拦不到（Sysmon 只做取证，且只读检测）。
5. 工作区无论如何不设防——这是设计，不是遗漏。
6. `unresolvedAction: confirm` 把最后一道闸门交给人工：解析不出目标时没有备份，
   安全边界落在「用户是否看清了那条命令」。要更严就改成 `deny`。
7. 字符串/注释屏蔽是启发式的：脚本里出现 `eval`/`exec`/`child_process` 时会退回全文扫描
   （宁可误报），因此这类脚本仍可能因为字符串里的删除字样被要求确认码。

---

## 14. 版本变更

### v0.2.0（区域模型）

- 改名与包名：`@local/delete-guard` → `@local/dsh-sensitive-data-guard`，UI 名称「敏感数据守卫」。
  目录名保留 `delete-guard` 以兼容既有安装与备份路径。
- **区域模型**取代「一刀切备份」：工作区零干预，`.dsh` 静默备份，敏感区确认码。
- **确认码**子系统（4 位、同会话同命令、10 分钟、一次性、复用备份）。
- **级别可配置**（`soft` / `medium` / `hard`，默认 `hard`），放宽有红字警告 + 审计。
- **设置页**（Client 半）+ 同源 JSON 路由，改完立即生效；`data/settings.json` 持久化。
- `.dsh` 备份保留：最新 10 个 / 30 天，与敏感区的 30 天分开算。
- 修复：工作区短路曾绕过保护目录检查；`cwdFor` 曾回落到 profile 目录导致工作区目标被误判为敏感区。

### v0.2.1（保护目录底线）

- 修复：`data/settings.json` 里的 `protectedPaths` 会永久覆盖配置文件里的同名设置，
  导致「在设置页保存过一次 → 配置里的保护目录全部失效」。
  现在改为**并集**：配置是底线，UI 只能追加；`settingsSnapshot()` 同时返回
  `protectedPaths`（UI 那份）与 `configProtectedPaths`（底线，只读展示）。
- `GateCore` 新增 `options.settingsDir`，测试用它隔离设置文件；新增回归用例。
