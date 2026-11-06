# 敏感数据守卫（Sensitive Data Guard）

给 DeepSeek Harness（DSH）用的删除门禁。DSH 的模型在 `danger-full-access` 下可以删掉工作区之外的
任何东西；这个插件在**删除发生之前**把它拦下来：先备份，再弹窗问你。备份不成功就硬性阻断，
绝不降级成一句警告。

- 包名：`@local/dsh-sensitive-data-guard`　版本：0.2.6　适配：DSH 0.2.2-rc.1
- 默认备份根：`backup/`（相对本插件目录解析）
- 默认级别：`hard`（敏感区一律先备份再确认）

> 下文 `<插件目录>` 指本插件所在目录（`package.json` 所在处）。`backup/`、`bin/...` 这类相对路径都相对于它，换机器、换安装位置都不用改。

---

## 1. 三个区域

每个删除目标先归入一个区域，区域决定怎么处理：

| 区域 | 判定 | 处理 |
|---|---|---|
| **工作区** | 当前会话的工作目录之内 | 完全不干预：不备份、不提醒、不阻断 |
| **`.dsh`** | 本机 `.dsh` 目录之内 | 静默备份一次，不提醒、不阻断 |
| **敏感区** | 上面两者之外的任何路径 | 备份 + 弹窗确认 |

一次操作涉及多个目标时取**最严格**的区域。单个目标按上面的顺序判定，**工作区优先**：如果工作区本身就装在 `.dsh` 里面，按工作区处理。拿不到会话工作目录时按敏感区处理（宁可多问一次）。

工作区完全不保护是设计决定：插件要防的是模型把工作区之外的目录一起清掉，不是防你手滑删自己的项目。

---

## 2. 确认流程

敏感区删除（或命中级别阈值）时，守卫先备份，然后在你界面上弹一张卡片，工具调用就停在那里等你：

```
删除守卫 · 敏感区删除

允许执行这次删除吗？

拟删除的内容：
  • D:\项目\旧版本      1284 个文件，3.7 GB
  • D:\素材\临时          56 个文件，12.4 MB

合计：1340 个文件，3.71 GB
已经提前备份：2026-11-05/<session>/0007
还原命令：node bin/delete-guard.mjs restore 2026-11-05/<session>/0007

[允许执行]  [拦截]
```

- **允许执行** → 命令立刻执行，模型拿到正常结果。
- **拦截** → 命令不执行，已经做过的备份保留。
- **不回答** → 等 `policy.confirmTimeoutMs`（默认 5 分钟），超时按 fail-closed 阻断，不会自动放行。
- **弹窗发不出去**（关了浏览器、纯 CLI、从子代理发起）→ 阻断。

答案走 DSH 的用户问答通道（`ctx.userQuestions`，和 `ask_user_question` 同一套卡片）送回来，**只回到守卫**——模型看不到也拿不到，所以它没法替你点。这是 0.2.4 换掉 4 位确认码的原因：码写在工具返回值里，模型自己就能填回去。

### 目标算不出来的时候

比如 `Remove-Item -LiteralPath $env:SOME_VAR -Recurse`，目标要到运行时才确定。默认（`policy.unresolvedAction: 'confirm'`）同样弹窗，只是正文明确写出**这次没有备份**，也没法校验目标是否落在受保护目录里。想改回硬拒就设成 `deny`。

大多数「算不出来」其实能算出来：`$x = '字面量'` 会进变量表，`Get-ChildItem X | Remove-Item` 会回溯到 X，`[IO.File]::Delete($_.FullName)` 会补上上游路径。

### 没有界面时：文本确认码

`policy.confirmVia: 'code'` 切回旧流程：报告里给 4 位数字，你把它发给模型，模型带前缀重发同一条命令即可放行并复用刚才的备份。**这条通道里模型看得见那个码**，它可以在没人看的情况下自己用掉——只在确实没有界面时才用。

### 不认识的工具

插件工具（比如你自己装的 `config2ds`）不在守卫的内置清单里。默认（`policy.unknownTool: 'prompt'`）守卫会弹一张卡片，把**工具名、注册说明、参数结构、本次调用参数**都摆出来，让你选：

- **信任并加入白名单** → 写进 `data/settings.json`，以后这个工具的所有调用都不再询问，本次立即执行。
- **仅本次允许** → 只执行这一次，下次仍问。
- **拦截** → 不执行。

弹窗送不到你（关了浏览器、纯 CLI、从子代理发起）或超时，一律按 fail-closed 阻断。加白名单的工具仍然不能碰保护目录、插件自身和备份根；已知的删除/覆盖类工具（`write`、`edit`、`delete`、`pwsh` 等）不能加白。

想回到「未知工具一律阻断」就设 `policy.unknownTool: 'deny'`。

---

## 3. 安装与启用

在 DSH 的插件管理里把 `<插件目录>` 当本地目录路径安装；或让模型调用 `plugin_manager` 的 `install_bundle`（传绝对路径）。安装结果应为 `application: applied` 且无 warnings。

自检：

```powershell
node bin/delete-guard.mjs status
```

应看到备份根、健康状态、批次与占用、Sysmon 状态、钩子文件 `ok`。

停用：在 DSH 里停用该 bundle。停用立刻失效并还原被包装的 shell 方法，**不会删除备份**。

---

## 4. 设置

三个入口，改的是同一份状态：

1. 设置 → 敏感数据守卫
2. 插件 → 本插件页面
3. 文件：`data/settings.json`

优先级：`lib/defaults.js` 默认值 < `cordis.patch.yml` 的 `config` < `data/settings.json`。改完立即生效，不用重启。

UI 里只能改四项：

| 字段 | 说明 |
|---|---|
| `triggerLevel` | `soft`（只备份）/ `medium`（按阈值）/ `hard`（一律确认） |
| `mediumMinFiles` | medium 的文件数阈值（默认 10） |
| `mediumMinBytes` | medium 的体积阈值（默认 64 MiB） |
| `protectedPaths` | 保护目录，一行一个，`!` 开头表示排除 |
| `safeTools` | 受信任的只读工具名，一行一个（弹窗里点「信任并加入白名单」也会写这里） |

往放宽方向调（`hard → medium → soft`）不会被拦，但会红字警告并写一条审计。

> 完整配置项（备份限额、保留策略、钩子开关等）在 `cordis.patch.yml` 里逐条有中文注释，那是权威；`config.schema.json` 是同一份信息的机器可读版本，**DSH 不会读它**。

---

## 5. 保护目录

`policy.protectedPaths` 是 `.gitignore` 风格的模式列表，**任何级别下都禁止修改**，判定发生在「工作区直接放行」之前：

```
D:\Company\财务
C:\Windows\System32
!D:\Company\财务\公开资料    ← 以 ! 开头表示放行
```

规则：`/` 分隔、大小写不敏感；可带盘符，不带则匹配任意盘；`*` 一段、`**` 跨段、`?` 单字符；`!` 放行；后写的覆盖先写的；不含 `/` 匹配任意层级，含 `/` 从盘根锚定（任意深度用 `**/`）。

`cordis.patch.yml` 里声明的是**部署底线**，设置页只能往上追加，删不掉。

自动加入、不用手写：插件目录本身、备份根、审计日志、profile 配置文件（`cordis.patch.yml` / `cordis.yml` / `package.json`）。

---

## 6. 备份与还原

```
backup\
  _store\<aa>\<bb>\<sha256>          内容寻址对象库（相同内容只存一份）
  2026-11-05\<sessionId>\0001\       批次桶（manifest.jsonl + 硬链接镜像 tree\）
  _audit\2026-11-05.jsonl            审计（放行/备份/阻断/确认/还原/异常）
```

| 区域 | 保留 |
|---|---|
| `.dsh` | 最新 10 个批次，且不超过 30 天 |
| 敏感区 | 30 天 |
| 工作区 | 不产生备份 |

审计日志不随批次删除。超过总量配额（默认 50 GiB）时新备份直接阻断，不把磁盘打满。

还原（会用旧内容覆盖当前文件）：

```powershell
node bin/delete-guard.mjs restore latest --dry-run
node bin/delete-guard.mjs restore 2026-11-05/<session>/0007
node bin/delete-guard.mjs restore latest --to D:\restore-here --force
```

默认逐文件写回原路径；目标已存在时拒绝覆盖，`--force` 才覆盖；还原时校验 SHA-256。

---

## 7. 覆盖范围与边界

拦得到：

- 所有模型工具：`write` / `edit` 覆盖、`pwsh` / `bash` 命令、删除移动类工具、`plugin_manager` 改动本插件自身。
- 不在内置清单里的插件工具：默认弹窗问用户是否信任（可加入白名单），不让它们无声通过。
- 所有 shell 命令在 spawn **之前**完成判定与备份（包装运行中的 `ctx.shell.execute`）。
- 命令派生的 Python / Node 子进程：注入运行时钩子，`os.remove` / `shutil.rmtree` / `fs.rmSync` / `fs.rename` 等同步校验。
- Sysmon 状态检测（只读，只告警，不修改任何安全配置）。

拦不到：

1. **第三方进程**：与 DSH 无关的清理软件、计划任务删文件，插件管不着。
2. **`cmd.exe` 子进程**：`cmd /c del` 不经过 Python/Node 钩子，只有命令文本解析这一层。
3. **动态/混淆代码**：清空环境、`python -E/-I`、native 二进制直接 unlink，钩子失效。
4. **插件自己没加载或崩了**：没有门禁。用 `node bin/delete-guard.mjs status` 自检。
5. **工作区不设防**：工作区里的删除不备份、不提醒、拦不住。这是设计决定。
6. **持久 shell 工具**：若装了 `tool-pwsh-persistent`，它走 `ctx.terminals` 而不是 `ctx.shell`，shell 深度层与运行时钩子都不覆盖，只剩命令文本解析。本 profile 默认没装。

其他一律阻断（fail-closed）：单文件 > 256 MiB、单批 > 10 GiB 或 > 5 万文件、总量 > 50 GiB、命中保护目录、目标落在插件自身目录、插件内部异常。

---

## 8. 命令行

```powershell
node bin/delete-guard.mjs status [--root DIR] [--json]
node bin/delete-guard.mjs restore <批次|latest> [--to DIR] [--force] [--dry-run]
node bin/delete-guard.mjs dry-run -- Remove-Item -Recurse -Force D:\tmp\victim
node bin/delete-guard.mjs gc [--root DIR]
```

`dry-run` 只报告「会备份什么、多大、是否超限」，不删除也不写备份。

---

## 9. 许可

MIT License，Copyright (c) 2026 DreamInsight。详见 [LICENSE](LICENSE)。

> 本插件不修改任何 DSH 代码、不依赖 `@deepseek-ai/*`，但它拦截的是 DSH 发起的所有破坏性操作。
> 装到别人的机器上之前，请先读 [docs/DEPLOY-CHECKLIST.md](docs/DEPLOY-CHECKLIST.md)。
