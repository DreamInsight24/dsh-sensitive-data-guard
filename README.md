# 敏感数据守卫（Sensitive Data Guard）

> 给 DeepSeek Harness（DSH）用的**区域感知**、fail-closed 的删除门禁。
> 它只做一件事：**在 DSH 拿到最高权限时，仍然拿不走工作区之外的数据**——
> 敏感区删除先备份、再要你输入 4 位确认码；`.dsh` 静默自动备份；
> 工作区内部完全不干预。备份不成功就硬性阻断，绝不降级为警告。

- 插件包：`@local/dsh-sensitive-data-guard`（Host 插件 + Client 半 + bundle patch）
- 版本：0.2.1；适配 DSH 0.2.1-rc.2（desktop profile）
- 插件目录：`<插件目录>`（目录名是历史遗留，包名才是准的）
- 默认备份根：`backup/`（相对插件目录解析）
- 默认级别：`hard`

> 下文 `<插件目录>` 指本插件所在目录（即 `package.json` 所在处）；`bin/...`、`backup/` 这类相对路径都相对于它——换机器、换安装位置都不用改。

---

## 1. 一句话模型：三个区域

每个被删除/覆盖的目标都先归入一个区域，区域决定处理方式：

| 区域 | 判定 | 处理 |
|---|---|---|
| **工作区** `workspace` | 目标在当前会话的工作目录之内 | **完全不干预**：不备份、不提醒、不阻断 |
| **`.dsh`** `dsh` | 目标在本机 `.dsh` 目录之内 | **静默备份一次**，不提醒、不阻断 |
| **敏感区** `sensitive` | 以上两者之外的任何路径 | **备份 + 硬提醒**（4 位确认码），按级别定阈值 |

- 一次操作涉及多个目标时，取**最严格**的区域（例如同时删工作区文件和 `D:\项目`，按敏感区处理）。
- 工作区里**不可能**包含 `.dsh`；判定基准取会话真实工作目录，拿不到时按敏感区处理（宁可多问一次）。

> 为什么工作区完全不保护：它的目的不是「防手滑删自己的项目」，而是防止模型在
> `danger-full-access` 下把工作区之外的目录一起清掉。给自己写的东西加门禁只会拖慢开发。

---

## 2. 提醒级别（可在 DSH 里改）

`policy.triggerLevel`，三档，只影响**敏感区**：

| 级别 | 行为 |
|---|---|
| `soft` | 仅备份，不提醒也不阻断：敏感区删除照常执行，事后可从备份还原 |
| `medium` | 达到阈值才提醒：文件数 ≥ `mediumMinFiles`（默认 10）**或** 体积 ≥ `mediumMinBytes`（默认 64 MiB）才要确认码；未达阈值只备份 |
| `hard`（默认） | 一律提醒：敏感区任何删除/覆盖都先备份、再要确认码 |

- `.dsh` 区域**永远**只静默备份，与级别无关。
- **保护目录永远禁止修改**，与级别无关（见第 6 节）。
- 把级别往**放宽**方向改（`hard → medium → soft`）不会被拦截，但会红字警告，并写一条
  `loosened: true` 的审计事件。

---

## 3. 确认流程（hard / medium 触发时）

第一次删除被拦下来时，你看到的是这样一份报告（格式与 `lib/confirm.js` 实际输出一致）：

```
🛑 敏感区删除已拦截（未执行）

区域：敏感区（.dsh 与工作区之外）
级别：hard

拟删除的内容：
  • D:\项目\旧版本
      1284 个文件，3.7 GB
  • D:\素材\临时
      56 个文件，12.4 MB

合计：1340 个文件，3.71 GB

已经提前备份：2026-11-05/<session>/0007
备份目录：backup\2026-11-05\<session>\0007
还原命令：node bin/delete-guard.mjs restore 2026-11-05/<session>/0007

如确实要删除，请把下面的确认码发给我，我会带着它重新发起（备份已就绪，不会重复备份）：

确认码：4821
```

要点：

1. **先备份，后拦截**——报告生成时备份已经落盘，所以「拦不拦」不影响「能不能还原」。
2. 确认码固定 **4 位数字**，**生成在报告最后一行**，绑定当前会话 + 当前命令指纹，**10 分钟有效**、**一次性**。
3. 你把码发出来，模型会重发**同一条命令**，只是在前面加 `$env:DSH_GUARD_CONFIRM='4821';`。
   门禁校验通过后**直接放行并复用刚才那个备份批次**，不会重新备份一遍。
4. 码错了 → 直接拒绝，**不会**重新备份（避免用错误码反复刷备份）。
5. 码过期了 → 重新备份、重新生成新码。

---

## 4. 备份、保留与还原

```
backup\
  _store\<aa>\<bb>\<sha256>          内容寻址对象库（相同内容只存一份）
  2026-11-05\<sessionId>\0001\       批次桶
      manifest.jsonl                 首行 batch（含 zone）、逐文件记录、末行 summary
      tree\<盘符>\<相对路径>          硬链接镜像（便于人工浏览；跨卷时退化为复制）
  _audit\2026-11-05.jsonl            审计（放行/备份/阻断/确认/还原/异常）
  _state\                            序号、用量
  _ipc\                              运行时钩子的临时允许清单（30 分钟过期）
```

保留策略（`gc` 与自动清理共用）：

| 区域 | 保留 |
|---|---|
| `.dsh` | 只保留**最新 10 个**批次，且不超过 30 天 |
| 敏感区 | 30 天 |
| 工作区 | 不产生备份，无保留问题 |

审计日志不随批次删除。超限时新的备份直接阻断，绝不把磁盘打满（总量 50 GiB 配额）。

还原（**用户操作**，会用旧内容覆盖当前文件）：

```powershell
node "bin\delete-guard.mjs" restore latest --dry-run
node "bin\delete-guard.mjs" restore 2026-11-05/<session>/0007
node "bin\delete-guard.mjs" restore latest --to D:\restore-here
node "bin\delete-guard.mjs" restore latest --force
```

默认逐文件写回原路径；目标已存在时拒绝覆盖，`--force` 才覆盖；还原时校验 SHA-256。

---

## 5. 设置在哪里改

三个入口，改的是同一份状态：

1. **设置 → 敏感数据守卫**（设置面板里的独立一节）
2. **插件 → 本插件页面**（bundle 自己的配置区，描述与 rows 之间）
3. **文件**：`data\settings.json`

优先级：`lib/defaults.js` 默认值 **<** `cordis.patch.yml` 的 `config` **<** `data/settings.json`（设置页写入的）。

可在 UI 里改的只有四项：

| 字段 | 说明 |
|---|---|
| `triggerLevel` | `soft` / `medium` / `hard` |
| `mediumMinFiles` | medium 的文件数阈值 |
| `mediumMinBytes` | medium 的体积阈值（字节） |
| `protectedPaths` | 保护目录，一行一个，支持 `!` 排除（**追加**在配置文件底线之上） |

保存后**立即生效**，不需要重启。数据通道是 Host 半注册的同源 JSON 路由
`/plugins/dsh-sensitive-data-guard/settings`（GET 读 / POST 写，要求 `application/json`，
跨源 `Origin` 直接 403，请求体上限 64 KiB）。

> **保护目录是「配置底线 + UI 追加」**：`cordis.patch.yml` 里写的条目是部署底线，
> 设置页删不掉，只能看（文本框下方以只读小字列出）。设置页里新增/删除的只是「追加项」。
>
> 设置页在插件**停用**时不会出现——Client 半不加载，整个 UI 都没有了。

---

## 6. 保护目录（任何级别下都禁止修改）

`policy.protectedPaths` 是 `.gitignore` 风格的模式列表，可在设置页文本框里维护（一行一个）：

```
D:\Company\财务
C:\Windows\System32
!D:\Company\财务\公开资料    ← 以 ! 开头表示放行
```

规则：

- 用 `/` 分隔、大小写不敏感；可带盘符（`D:/xxx`），不带盘符则匹配任意盘。
- `*` 匹配一段内的任意字符，`**` 跨段匹配，`?` 匹配单个字符。
- `!` 开头表示**放行**；**同一路径以后写的规则为准**。
- 不含 `/` 的模式匹配任意层级；含 `/` 的模式从**盘根**锚定（要任意深度用 `**/` 前缀）。
- 目录一旦受保护，其下所有内容一并受保护；删除它的**上级目录**也会被阻断。

`cordis.patch.yml` 的 `policy.protectedPaths` 是**部署底线**：设置页可以在它之上追加，
但删不掉它（文本框下方会以只读小字列出这些条目）。

**自动加入、不需要你手写**：插件目录自己（`<插件目录>`）、
备份根、审计日志、profile 配置文件（`cordis.patch.yml` / `cordis.yml` / `package.json`）。

判定顺序很关键：**保护目录检查发生在「工作区直接放行」之前**。也就是说，
即使插件目录正好在某个工作区里面，也一样删不掉——这条曾经是 bug，0.2.0 已修，并有回归测试守着。

---

## 7. 四层怎么拦

| 层 | 扩展点 | 覆盖 |
|---|---|---|
| L0 工具门禁 | `tools/pre-execute` + `ctx.tools.guard` | 所有模型工具：`write/edit` 覆盖、`pwsh/bash` 命令、删除/移动类工具、`plugin_manager` 改动自身 |
| L1 shell 深度层 | 包装运行中 `ctx.shell` 实例的 `execute` | 所有 shell 命令在 spawn **之前**判定 + 备份，并注入 Python/Node 钩子环境 |
| L2 运行时钩子 | Python `sitecustomize` / Node `--require` | 子进程里的 `os.remove / shutil.rmtree / fs.rmSync / fs.rename …` 同步校验 |
| L3 OS 兜底（只读） | Sysmon 检测 | 启动时检测 Sysmon64/SysmonDrv，只告警，**不修改任何安全配置** |

任何一层判定「需要备份」时，都走同一个备份引擎；备份失败、超限、命中保护目录、
目标落在插件自身目录、插件内部异常 —— 一律**阻断**。

---

## 8. 安装 / 停用

```text
插件 → 添加 → 从本地目录安装 → <插件目录>
```

或让模型调用 `plugin_manager` 的 `install_bundle`（绝对路径）。安装结果应为
`application: applied` 且无 warnings；需要重启时会明确提示。

自检：

```powershell
node "bin\delete-guard.mjs" status
```

应看到备份根、健康状态、批次与占用、Sysmon 状态、钩子文件 `ok`。

停用：DSH 里停用该 bundle 即可（用户操作）。停用时插件会立刻失效并还原
`ctx.shell.execute`；**停用不会删除备份**。

---

## 9. 边界与已知限制（必读）

1. **第三方进程**：与 DSH 无关的清理软件/计划任务删文件，插件拦不到（L3 只是取证）。
2. **PTY 交互终端**：本 profile 未安装 `terminal` 工具，故不涉及。
3. **`cmd.exe` 子进程**：`cmd /c del`、`rd` 不经过 Python/Node 钩子，只能靠命令文本解析。
4. **动态/混淆代码**：清空环境、`python -E/-I`、native 二进制直接 unlink —— 钩子失效，只剩解析层。
5. **插件自身未加载/崩溃**：没有门禁。DSH 没有「插件死了也 fail-closed」的机制，请用 `status` 健康位自检。
6. **解释器写入绕过保护目录检查**：`node -e "fs.writeFileSync(...)"` 这类没有删除语义的写入
   不按保护目录检查。自保护防的是**删除/卸载**，不是防同权限进程改写文件；
   要严格边界请在操作系统层限制目录写权限。
7. **超限默认阻断**：单文件 > 256 MiB、单批 > 10 GiB、批文件数 > 5 万、总量 > 50 GiB。
8. **工作区不设防是设计决定**：工作区里的任何删除都不备份、不提醒、拦不住。

---

## 10. 命令

```powershell
node bin/delete-guard.mjs status [--root DIR] [--json]
node bin/delete-guard.mjs restore <批次|latest> [--to DIR] [--force] [--dry-run]
node bin/delete-guard.mjs dry-run -- Remove-Item -Recurse -Force D:\tmp\victim
node bin/delete-guard.mjs dry-run --tool write --path D:\work\a.txt
node bin/delete-guard.mjs gc [--root DIR]
```

- `status`：健康、占用、批次、Sysmon、钩子、最近事件。
- `dry-run`：只报告「会备份什么、多大、是否超限」，**不删除、不写备份**。
- `restore`：见第 4 节。
- `gc`：按区域保留策略清理过期批次与无引用对象。

`bin/dsh-guard.mjs` 是同目录的兼容入口，`node bin/dsh-guard.mjs status` 等价。

---

## 11. 目录结构

```
<插件目录>\
  package.json            # bundle 清单（dsh.bundle.patch + dsh.client）
  cordis.patch.yml        # 插入核心行 + 默认 config（中文注释）
  index.js                # Host 半：门禁接线、shell 包装、设置路由
  client.js               # Client 半：设置页 + 插件页配置块
  lib/defaults.js         # 默认值（CLI 与 Host 共用）
  lib/zones.js            # 区域模型
  lib/confirm.js          # 确认码存储与报告渲染
  lib/settings.js         # 运行时设置的读写与校验
  lib/http-settings.js    # 设置页的 HTTP 通道
  lib/classify.js         # 工具/命令分类器
  lib/backup.js           # 备份引擎（CAS/配额/manifest/restore/按区域清理）
  lib/gate.js             # 门禁核心
  lib/audit.js            # 审计 JSONL
  lib/paths.js            # 路径工具 + .gitignore 风格保护模式
  hooks/python/sitecustomize.py
  hooks/node/delete-guard.cjs
  bin/delete-guard.mjs    # CLI
  data/settings.json      # 设置页保存的值
  config.schema.json      # 配置 schema
  test/                   # 离线测试（不依赖 DSH Host）
  backup/                 # 备份根
  docs/                   # 测试报告、部署清单、设计修订
  locale/ icon.svg
  LICENSE                  # MIT
  .github/workflows/test.yml  # CI：逐文件跑三个测试
```

测试（本机沙箱下 `node --test test/` 会因 piped stdio 报 `spawn EPERM`，请逐个文件跑）：

```powershell
node test/core.test.mjs     # 22 个
node test/gate.test.mjs     # 7 个
node test/protect.test.mjs  # 5 个
```

---

## 12. 许可

MIT License，Copyright (c) 2026 DreamInsight。详见 [LICENSE](LICENSE)。

> 注意：本插件**不修改任何 DSH 代码、不依赖 `@deepseek-ai/*`**，但它拦截的是 DSH
> 发起的所有破坏性操作。把它装到别人的机器上之前，请先读 `docs/DEPLOY-CHECKLIST.md`
> 里的验证步骤，尤其是「备份根」和「受保护目录」这两项。
