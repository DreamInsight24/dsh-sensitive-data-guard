# 设计说明的实施修订（与 DESIGN.md 的差异）

原始设计见 `DESIGN.md`（确认方案时的版本）。实施过程中确认了以下现实约束，
最终代码按本页修订执行；行为目标（先检查、先备份、失败即阻断）不变。

## 1. 本地 bundle 不能 import 随 dsh 发行的包

实测：本地 bundle 安装后，`import '@deepseek-ai/schemastery'` 与
`import '@deepseek-ai/dsh-pwsh-sandbox'` 均报 `ERR_MODULE_NOT_FOUND`（本机 profile 的 node_modules
不解析 dsh 安装目录）。同类本地插件 `@local/config2ds` 也只 import Node 内置模块。

影响与替代：

| 原设计 | 最终实现 |
|---|---|
| 导出 schemastery `Config` | 不导出 `Config`；`lib/defaults.js` 默认值 + `resolveConfig()` 深合并；另附 `config.schema.json` 描述 |
| 替换 `pwsh-sandbox` 行、子类化 `SandboxPwshExecutor` | 不改任何 shipped 行；包装运行中的 `ctx.shell` 实例的 `execute`（保存原型方法为原始基准，兼容 HMR/停用后重启） |

包装方式的风险控制：

- `execute` 以原型方法为基准，不叠加多层包装；
- 插件 dispose 时还原；
- 若实例被冻结/包装失败：记录告警，L0 工具门禁仍然生效（shell 深度层降级）。

## 2. 运行时钩子不使用 IPC

Windows 沙箱下子进程对命名管道/loopback 有限制。改为：
shell 深度层在 spawn 前把「允许根 + 易失根 + 过期时间」写成 JSON 文件，
通过 `DSH_DELETE_GUARD_ALLOW` 传给子进程；Python/Node 钩子读取该文件做同步校验，
缺文件/解析失败 → 拒绝删除（fail-closed）。

## 3. 测试暴露并修复的问题

1. **npm 缓存误拦**：npm 清理 `%LOCALAPPDATA%\npm-cache\_cacache\tmp` 被钩子拒绝 → `npm install` 失败。
   修复：内置易失目录加入 npm/pnpm/Yarn 缓存与 `~/.npm`、`~/.cache`。
2. **Python 原始字符串**：`shutil.rmtree(r'...')` 的字面量提取失败 → 退回 scope；钩子随后阻断。
   修复：路径正则支持 `r'...'`、`rb'...'`、`f'...'`（含插值的路径视为不确定）。
3. **格式化覆盖未备份**：`prettier --write src` 被当作“干净脚本”放行。
   修复：`--write/-w/--fix/-i/--in-place` 按破坏性写入处理，备份目标路径。
4. **os.truncate 未识别**：加入破坏性写入/截断 API 集合。
5. **受保护路径符号链接绕过**：路径检查改用 realpath 后再比较（含父目录 realpath + 文件名）。

## 4. 保留的取舍

- 未知工具默认 `deny`（可配置 allow-audit）——比原设计更严格；
- 解析不出的 shell 命令默认 `scope` 备份整个工作目录——按用户确认的策略；
- `restore/gc` 通过 CLI 执行属于用户操作：模型若用 `node ... delete-guard.mjs restore` 会得到
  明确拒绝（避免“还原”覆盖用户新数据）；`status/dry-run/restore --dry-run` 允许；
- 测试用的还原/校验脚本放在 `D:\dsh-workspaces\_dg-run\`，不属于插件交付物。

## 5. 仍未覆盖（与 README 第 7 节一致）

`cmd.exe` 子进程、PTY 终端、`python -E/-I`、清空环境、native 二进制、第三方进程、插件未加载/崩溃、
同权限任意代码写入。

## 6. 迁移到 local/delete-guard（2026-11-05）

用户要求把所有相关目录集中到 `<插件目录>`：

```
local/delete-guard/
  <插件源码>            package.json / index.js / cordis.patch.yml / lib / hooks / bin / test / locale …
  backup/               备份根（原 D:\dsh-workspaces\_delete-backup）
  docs/                 测试报告、部署清单、设计修订（原 D:\dsh-workspaces\delete-guard-docs）
  fixtures/             演练与验证脚本（原 D:\dsh-workspaces\_dg-run）
```

- 备份根默认值改为插件目录下的 `backup`（相对写法；`lib/defaults.js`、`cordis.patch.yml`、`config.schema.json`）。见第 11 节。
- 迁移用 `robocopy /E` 复制 + 校验后删除旧目录；批次、审计、`_store` 全部保留。
- 重新注册：`remove_bundle` 旧 link → `install_bundle` 新路径；`@local/delete-guard 0.1.0 <- <插件目录>`。
- 旧目录 `D:\dsh-workspaces\delete-guard`、`_delete-backup`、`delete-guard-docs`、`_dg-run` 已删除。

## 7. 分类器修复（迁移同轮）

1. **前导空格导致安全命令误判**：语句切分后第二条起带前导空格，而安全正则锚在行首 →
   `Select-Object` / `Where-Object` / `Get-ChildItem` 等被判为 opaque，触发整目录 scope 备份，
   大工作目录会被配额拦下（实测 `Get-Process | Where-Object {...} | Select-Object ...` 被误拦）。
   修复：匹配前 `trim`。
2. **纯变量赋值误判**：`$b='D:\...'` 被当成未知命令。修复：识别右侧为字面量/变量/绝对路径的纯赋值。
3. **格式化工具直接调用**：`prettier --write src`、`eslint --fix`、`black -w` 之前识别不出写入目标。
   修复：新增 formatter 分类（写入目标 = 非开关、非脚本扩展名的参数；通配符取目录）。

## 8. 保护目录改为可管理模式列表

`policy.protectedPaths` 从「精确路径列表」升级为 **.gitignore 风格模式列表**（`lib/paths.js`）：

- `*` 一段、`**` 跨段、`?` 单字符；可带盘符（不带则匹配任意盘）；大小写不敏感；
- `!` 前缀表示放行（排除），后写覆盖先写；不含 `/` 匹配任意层级，含 `/` 从根锚定；
- 目录受保护时其下内容一并受保护；删除「包含受保护目录的上级」也会被阻断
  （用模式的字面前缀做祖先检查）。

示例：`['User/*', '!User/WorkSpace']` 保护 User 下所有内容但放行 User/WorkSpace。

## 9. 卸载残留修复

现象：在插件页停用后，工具层门禁消失，但 shell 包装层仍在拦截（`dispose()` 只写了 shutdown 事件，
包装层未被移除或未被短路）。

修复：`GateCore.dispose()` 置 `disposed` 后，`prepareShell` / `evaluate` / `onPreExecute` /
`onPostExecute` / `guard` 全部短路成立即放行；`index.js` 仍保留 `ctx.shell.execute` 的还原。
这样即使包装层因热重载顺序残留，也不会再拦截。

## 10. v0.2 变更：从「删除守卫」到「敏感数据守卫」（2026-11-05）

### 10.1 改名与定位

| 项 | 0.1.0 | 0.2.0 |
|---|---|---|
| 包名 | `@local/delete-guard` | `@local/dsh-sensitive-data-guard` |
| 行 id | `delete-guard` | `dsh-sensitive-data-guard` |
| 显示名 | 删除守卫 | 敏感数据守卫 |
| 版本 | 0.1.0 | 0.2.0 |
| 管理 CLI | `bin/delete-guard.mjs` | `bin/dsh-guard.mjs`（`bin/delete-guard.mjs` 保留为等价入口） |
| 设置路由 | — | `/plugins/dsh-sensitive-data-guard/settings` |

插件目录仍然是 `<插件目录>`（沿用第 6 节的迁移结果，未再搬家），
备份根、批次、审计全部原地保留。

定位也变了：0.1.0 对**所有**破坏性操作一律先备份；0.2.0 的目标收窄为
「防止 DSH 在获得最高权限时静默删除/修改**工作区之外**的目录」。

### 10.2 区域模型（`lib/zones.js`）

每个操作目标先归入三个区域之一，多目标时取最严格的一个（`workspace < dsh < sensitive`）：

| 区域 | 判定 | 处理 |
|---|---|---|
| `workspace` | 位于当前会话工作目录（cwd）之内 | **完全不保护**：不备份、不提醒、不阻断，只写审计 |
| `dsh` | 位于 `.dsh` 根目录之内（含 `.dsh` 自身） | **静默自动备份一次**，不提醒、不阻断 |
| `sensitive` | 以上两者之外的一切路径 | 备份 + 硬提醒（4 位确认码），是否提醒由级别决定 |

`.dsh` 根目录取值顺序：`policy.dshHome` → `$DSH_HOME` → `$DSH_PROFILE_DIR` 的父目录 → `%USERPROFILE%\.dsh`。

**为什么工作区故意不设防**：插件的存在意义是防"工作区之外的意外删除"。
若连工作区也拦，正常的重构、清理、`npm`/`git` 操作会被反复打断，反而让人去关掉守卫。

去备份化的一个副作用需要专门处理：0.1.0 里 shell 深度层会按「本次已备份的范围」
生成子进程允许清单，工作区不备份后清单为空，Python/Node 钩子会把正常的工作区删除也拦掉。
修复：工作区分支仍然把「本次目标 + 工作目录」写进允许清单（`lib/gate.js` 的 `evaluate`
与 `prepareShell`），钩子据此放行。

### 10.3 确认码流程（`lib/confirm.js`）

```
1. 判定为 sensitive → 先完成备份（拿到批次 id 与目录）
2. 生成 4 位随机确认码，登记为「待确认」
   key = 会话 id + 命令指纹（剥离确认码、压缩空白），TTL 10 分钟
3. deny，返回报告：区域 / 级别 / 逐目录文件数与体积 / 合计 /
   批次 id / 备份目录 / 还原命令 / （最后一行）确认码
4. 用户把确认码告诉模型，模型带前缀重发同一条命令：
      $env:DSH_GUARD_CONFIRM='1234'; <原命令>
5. 校验通过 → 放行，并复用第 1 步的批次（不再重复备份）
```

边界行为：

- **码错误且在挂起期内** → 直接拒绝「确认码不正确」，**不重新备份**；
- **已过期**（超过 10 分钟）→ 重新备份并生成新码；
- **一次性**：校验成功后立即作废；
- 通道选环境变量前缀：模型在命令文本里带 `$env:DSH_GUARD_CONFIRM='<码>';`，
  插件用两条正则兼容 `$env:X='1234';` 与 `X=1234` 两种写法。

### 10.4 提醒级别可配置（`policy.triggerLevel`）

| 级别 | 行为 |
|---|---|
| `soft` | 仅备份，不提醒也不阻断 |
| `medium` | 文件数 ≥ `mediumMinFiles`（10）**或** 体积 ≥ `mediumMinBytes`（64 MiB）才提醒 |
| `hard`（默认） | 敏感区任何删除/覆盖都先备份再要确认码 |

级别只影响 `sensitive` 区域；`workspace` 与 `dsh` 不受影响。`medium` 的阈值判定基于备份结果
（`files` / `bytes`），所以是"先备份、再判断要不要问"。

### 10.5 设置页与 HTTP 路由

- **Client 半**（`client.js`）：`window.__ModuleLoader__.load` + `settings.section` 插槽，
  注册项 `{id: 'dsh-sensitive-data-guard', order: 25, label: '敏感数据守卫'}`。
  界面含：级别单选（每项带小字范围说明）、阈值输入（仅 medium 显示）、
  保护目录文本框（一行一个，支持 `!` 排除）、保存 / 重新读取按钮、
  放宽时的红字警告（不拦截）、运行时信息（`.dsh` 位置、保留策略、设置文件路径）。
- **Host 半**（`lib/http-settings.js`）：只注册一个精确路由
  `/plugins/dsh-sensitive-data-guard/settings`，`GET` 读、`POST`/`PUT` 写。
  自建两道闸：同源校验（`Origin` 与 `Host` 不一致 → 403）与强制 `Content-Type: application/json`
  （跨站 JSON POST 会先触发 CORS 预检，本插件不应答预检，等于拦掉）；请求体上限 64 KiB。

### 10.6 设置持久化与优先级

设置写在插件目录下的 `data/settings.json`（`lib/settings.js`），标量类字段的优先级是：

```
DEFAULTS（lib/defaults.js） < bundle cordis.patch.yml 的 config < data/settings.json
```

可改字段：`triggerLevel`、`mediumMinFiles`、`mediumMinBytes`、`protectedPaths`。
写入前用 `sanitizePatch()` 做白名单与范围校验，非法值直接报错而不是静默纠正。
保存后立即生效（`applySettings()` 直接改运行中的 `policy`，并重新编译保护目录模式），无需重启。
级别放宽（`hard → medium/soft`）不拦截，但审计里写一条 `settings` 事件并带 `loosened: true`。

**`protectedPaths` 是唯一不按上述覆盖语义处理的字段**——见 10.6.1。

#### 10.6.1 保护目录：配置底线 ∪ 设置页追加（0.2.1 修复）

第一版把 `protectedPaths` 也当成普通字段覆盖：设置页每次保存都会把该字段（哪怕空数组）
写进 `data/settings.json`，而 `applySettingsOverlay()` 见到就无条件赋值。结果是
**用户在设置页点过一次保存之后，`cordis.patch.yml` / profile patch 里写的保护目录被永久清空**，
保护目录等于没配。实测：传入 config `['**/x/*']` → 实际生效 `[]`。

修复后拆成两份再合并：

| 来源 | 字段 | 说明 |
|---|---|---|
| 配置基线 | `baseProtectedPaths` ← `policy.protectedPaths`（`cordis.patch.yml` / profile patch） | **底线**，任何情况下都保留 |
| 设置页追加 | `uiProtectedPaths` ← `data/settings.json` 的 `protectedPaths` | 只能往上追加 |

生效值 = `baseProtectedPaths ∪ uiProtectedPaths`（去重、保持顺序），由 `refreshProtectedPaths()`
统一重编译模式。`applySettings()` 只替换 `uiProtectedPaths`，于是：

- 设置页清空文本框 → 只删掉追加项，配置底线仍生效；
- 设置页**无法**删除配置文件里声明的条目，界面以只读小字列出（`settingsSnapshot()` 同 `protectedPaths`
  额外返回 `configProtectedPaths`，`client.js` 据此渲染只读展示）。

配套：`GateCore` 构造函数新增第三个参数 `options.settingsDir`（默认插件目录），
测试用它注入临时设置目录，使仓库里的 `data/settings.json` 不再影响用例结果。

守护用例：`test/gate.test.mjs` → `设置文件里的空 protectedPaths 不能清空配置里的保护目录`
（三种情形：空数组不清空底线 / UI 追加与底线合并 / UI 清空只删追加项）。

### 10.7 分区保留策略

`lib/backup.js` 的 `cleanup()` 改为分区处理（批次清单首行的 `zone` 字段标识区域，
历史批次没有该字段的按 `sensitive` 处理）：

| 区域 | 清理条件 |
|---|---|
| `dsh` | 超出最新 `backup.dshRetentionCount`（10）个 **或** 超过 `backup.dshRetentionDays`（30）天 |
| 其它（`sensitive` / 历史） | 超过 `backup.retentionDays`（30）天 |
| `workspace` | 不产生批次，无需清理 |

审计日志永不删除。清理完会回收空会话/日期目录，再按引用关系回收无对象。

### 10.8 工作区判定基准的修复（`cwdFor`）

现象：审计里出现 `zone: "workspace"` 但 `targets: ["C:\\Users\\…\\.dsh\\profiles\\desktop"]`
——桌面版宿主进程的 `process.cwd()` 就是 profile 目录，`cwdFor()` 拿不到
`workingDirectory` 服务时退回它，于是**工作区判定基准变成了 `.dsh` 里的目录**，
导致 `D:\dsh-workspaces` 里的目标被判成"敏感区"（正常干活会被反复要确认码）。

修复分两层：

1. `cwdFor()` 改为四级回落：
   `ctx.get('workingDirectory')` → `wd.ensure(agent)` → `wd.get(session)` →
   `agent.session.header.cwd` → `wd.defaultDirectory` → 最后才是 `process.cwd()`；
2. `zoneForRoots()` 加硬兜底：**工作区不可能位于 `.dsh` 之内**，若候选基准落在 `.dsh` 里就丢弃它，
   宁可把目标当敏感区（更严），也不能误判成"工作区、无需保护"。

### 10.9 自保护回归修复：工作区短路绕过受保护目录

引入区域模型时的回归：`evaluate()` 里"工作区 → 直接 allow"的分支被放在
`assertNotProtected()` **之前**，而插件目录本身就在工作区
（`<插件目录>`）之内 —— 于是删除/覆盖插件目录会被工作区短路放行，
自保护形同虚设。

修复：把受保护目录检查提到区域分流之前，`evaluate()` 与 `prepareShell()` 两处都做：

```js
const zone = this.zoneForRoots(roots, workdir);
// 受保护目录优先于区域判定：工作区短路不能绕过这一层
for (const root of roots) this.assertNotProtected(root, plan.kind);
if (zone === ZONE.WORKSPACE && this.policy.workspaceMode === 'none') { /* 放行 */ }
```

守护用例：`test/gate.test.mjs` → `受保护目录优先于「工作区不保护」的短路`（当前通过）。

### 10.10 v0.2 的验收边界

- 版本：**0.2.1**（= 0.2.0 的区域模型 + 第 10.6.1 节的保护目录合并修复；`package.json` 已改为 `0.2.1`）；
- 自动化测试 34 个，当前 **34 通过 / 0 失败**（`core` 22 / `gate` 7 / `protect` 5）；
- 手工联调已验证：区域分流、确认码闭环、设置页注册与读写、放宽告警、工作区不产生备份、
  保护目录优先级、设置文件与配置底线的合并；
- 仍未覆盖：`cmd.exe` 的 `del`/`rd`、PTY、`python -E/-I`、第三方进程、插件未加载时的空窗、
  同权限任意代码写入。

---

## 11. 可移植性修订：插件目录相关的路径改为相对写法（2026-11-05）

第一次把仓库整体交出去之前做的一次自查，发现「指向本插件目录」的路径全都写成了本机绝对路径，
换机器就要么失效、要么把备份写到别的地方。改动如下：

| 位置 | 改前 | 改后 |
|---|---|---|
| `lib/defaults.js` | `DEFAULT_BACKUP_ROOT = 'D:\dsh-workspaces\local\delete-guard\backup'` | 由 `PLUGIN_DIR` 推导：`path.join(PLUGIN_DIR, 'backup')` |
| `lib/defaults.js` | — | `resolveConfig()` 现在把相对的 `backup.root` 按 `PLUGIN_DIR` 解析 |
| `cordis.patch.yml` | `root: 'D:\dsh-workspaces\local\delete-guard\backup'` | `root: 'backup'`（相对插件目录） |
| `config.schema.json` | `"default": "D:\\dsh-workspaces\\local\\delete-guard\\backup"` | `"default": "backup"`，description 说明按插件目录解析 |
| `test/gate.test.mjs` | `TMP = D:\dsh-workspaces\_dg-run\gate-tmp\...`；断言 `cwdFor() === 'D:\dsh-workspaces'` | 由 `PLUGIN_DIR` 推导临时目录；cwd 断言用插件目录下的 fixture |
| `test/protect.test.mjs` | `SETTINGS_DIR = D:\dsh-workspaces\_dg-run\protect-settings\...` | 由 `PLUGIN_DIR` 推导 |
| 全部文档 | 绝对路径 | `<插件目录>` 占位符 + 相对路径 |

要点：

- `PLUGIN_DIR` 由 `import.meta.url` 推导（`lib/defaults.js` 里导出），不写死盘符；
- 备份根解析顺序：绝对路径原样使用；相对路径按 `PLUGIN_DIR` 解析；
- 文档里用 `<插件目录>` / `<工作区>` 两个占位符，正文中的 `bin/...`、`backup/` 都相对于插件目录；
- 顺带清掉了测试报告里的会话 id 与 Windows 用户名。

`test/core.test.mjs` 本来就用 `os.tmpdir()`，无需改动；它里面的 `D:\work`、`D:\data\victim`
是喂给分类器的合成字符串，不是真实路径。第 6 节里那些 `D:\dsh-workspaces\...` 是当时的迁移记录，
保留原样作为历史。
