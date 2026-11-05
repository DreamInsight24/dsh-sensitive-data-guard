# 敏感数据守卫 部署清单（一页）

- 插件：`@local/dsh-sensitive-data-guard@0.2.4`
- 行 id：`dsh-sensitive-data-guard`
- 插件目录：`<插件目录>`
- 备份根：`backup/`（相对插件目录解析）

> `<插件目录>` = 本插件所在目录（`package.json` 所在处）；`<工作区>` = 当前 DSH 会话的工作目录。下文相对路径都相对于 `<插件目录>`。

按顺序做，每一步都写明「怎么确认成功」和「失败就回滚」。

---

## 1. 前置检查（1 分钟）

- [ ] DSH Desktop 0.2.1-rc.2，profile 为 `desktop`
- [ ] 插件目录完整：`package.json` 里
      `name` 为 `@local/dsh-sensitive-data-guard`、`version` 为 `0.2.4`
- [ ] `package.json` 的 `dsh` 段同时含 `bundle.patch`（`./cordis.patch.yml`）与
      `client`（`platform: "web"`、`immediately: true`），`exports` 里有 `"./client"`
- [ ] Sysmon 在运行：`Get-Service Sysmon64,SysmonDrv` 均为 Running（插件只读检测，不会改动它）
- [ ] 备份根不在 C: 用户配置目录下（默认在 D:，符合要求）
- [ ] 备份根与删除目标不同树

**失败判定**：只要 `name`/`version` 不是上面这组，或 `dsh.client` 缺失（设置页会没有界面），
就不要继续——先修 `package.json` 再装。

---

## 2. 安装（1 分钟）

- [ ] 让模型执行：`plugin_manager` → `install_bundle`，target = `<插件目录>`
      （或在插件页用「本地目录安装」指向同一路径）
- [ ] 预期返回：`"stage":"enable"`、`"application":"applied"`、`"warnings":[]`，
      并显示 `+ @local/dsh-sensitive-data-guard 0.2.4 <- <插件目录>`

**确认成功**：返回里的 `application` 必须是 `applied`——它才是「已生效」的判据，
不要用日志、进程列表或页面情况推断。

**失败判定 → 回滚条件**：

| 现象 | 处理 |
|---|---|
| `application` 不是 `applied` | 停止，按返回里的 `nextStep` 处理；不要反复重装 |
| `warnings` 非空 | 先看清内容；涉及引擎版本或依赖解析的，回滚（第 7 节） |
| 报 `ERR_MODULE_NOT_FOUND: @deepseek-ai/*` | 插件代码里混入了 DSH 内部包 import；本地 bundle 不允许，必须先删掉再装 |

---

## 3. 激活验证（2 分钟）

### 3.1 命令行自检

- [ ] 让模型运行：
      `node "bin\delete-guard.mjs" status`
      （新入口 `bin\dsh-guard.mjs` 等价，旧名保留兼容）
- [ ] 应看到：
      - `健康：正常`
      - `Sysmon（最近一次检测 …）：运行中`
      - `钩子文件：python/sitecustomize.py=ok；node/delete-guard.cjs=ok`
      - 限额：单文件 256 MiB / 单批 10 GiB / 5 万文件 / 总配额 50 GiB / 保留 30 天

**失败判定**：`健康：异常` 或任一钩子 `缺失` → 不要依赖它，先修（第 6 节）。

### 3.2 设置页

- [ ] 打开 DSH「设置」，左侧应出现「**敏感数据守卫**」一节
- [ ] 页面应显示：级别单选（soft / medium / hard，每项带小字范围说明）、
      阈值输入（选中 medium 才出现）、保护目录文本框、**配置基线只读小字**
      （列出 `cordis.patch.yml` 里声明的保护目录，说明这些删不掉）、保存按钮、
      `.dsh` 位置 / 保留策略 / 设置文件路径等运行时信息

**失败判定**：设置页没出现 → 多半是 `dsh.client` 或 `exports["./client"]` 有问题，
或 Client 半加载失败；查 DSH 日志里的 `敏感数据守卫` 相关告警（会打印「设置路由注册失败」）。

### 3.3 设置路由（数据通道）

- [ ] 让模型执行（端口以当前 GUI 地址为准）：
      `Invoke-WebRequest -Uri 'http://127.0.0.1:<port>/plugins/dsh-sensitive-data-guard/settings' -UseBasicParsing`
- [ ] 应返回 200 且 JSON 里 `"ok":true`，`settings` 含 `triggerLevel`、`mediumMinFiles`、
      `mediumMinBytes`、`protectedPaths`（设置页追加的那份）、`configProtectedPaths`（配置底线）、
      `dshHome`、`retention`、`settingsFile`

**失败判定**：404 → 路由没注册（webServer 不可用或注册冲突）；403 → 跨源了（用同源页面/同机请求）。

### 3.4 敏感区探测（必须做，30 秒）

用一条不可能成功的路径探测，不会破坏任何东西：

- [ ] 让模型执行：`Remove-Item -LiteralPath 'D:\__dg-deploy-probe__' -Recurse -Force`
- [ ] 应被拦截，返回里含：
      - `🛑 敏感区删除已拦截（未执行）`
      - `区域：敏感区（.dsh 与工作区之外）`、`级别：hard`
      - 逐目录明细 + 合计
      - `已经提前备份：…`、`备份目录：…`、`还原命令：…`
      - **最后一行的 4 位确认码**（如 `确认码：3480`）

**失败判定（严重）**：如果这条命令被直接放行、没有任何拦截报告，说明门禁没生效
（可能在 `.dsh` 分区里、或 `enabled: false`、或插件未加载）→ **立即停用并排查**。

### 3.5 工作区探测（确认「不干预」）

- [ ] 让模型在**当前工作区内**建个临时目录并删除：
      `New-Item -ItemType Directory '<工作区>\_dg-deploy-ws' -Force; Remove-Item '<工作区>\_dg-deploy-ws' -Recurse -Force`
- [ ] 应**直接成功**，不应出现确认码
- [ ] 备份批次总数不变（`status` 前后对比 `批次：N`）

**失败判定**：工作区删除被要求确认码 → 工作区判定基准错了
（`cwdFor` 回落拿到 `.dsh` 里的目录），检查 `lib/gate.js` 的 `cwdFor` / `zoneForRoots`。

### 3.6 备份不可写 → 阻断（可选，需临时改 ACL，做完务必撤销）

- [ ] 对当天批次目录加拒绝写入：`icacls '<备份根>\<YYYY-MM-DD>' /deny '<你的SID>:(OI)(CI)(W)'`
- [ ] 再删一个敏感区目标 → 应返回 `备份未完成，已阻断：…`
- [ ] 撤销：`icacls '<备份根>\<YYYY-MM-DD>' /remove:d '<你的SID>'`

---

## 4. 配置入口与优先级

生效值按三级合成（对象深合并，数组/标量整体覆盖）：

```
DEFAULTS（lib/defaults.js）
  < bundle 的 cordis.patch.yml 里的 config
    < 插件目录下 data/settings.json（设置页写入）
```

- **推荐**：日常只改设置页（级别、阈值、**临时**追加的保护目录），保存后立即生效、无需重启。
- 其它字段（配额、保留策略、钩子开关等）：在
  `C:\Users\<你>\.dsh\profiles\desktop\cordis.patch.yml` 里按行 id 覆盖：

      - id: dsh-sensitive-data-guard
        name: '@local/dsh-sensitive-data-guard'
        config:
          backup:
            quotaBytes: 107374182400      # 100 GiB
            dshRetentionCount: 20         # .dsh 保留 20 个

> **保护目录的合并语义（重要）**：`policy.protectedPaths` 不做覆盖，而是求并集——
> 最终生效值 = **配置底线**（`cordis.patch.yml` / profile patch 里声明的）∪ **设置页追加的**，
> 去重后保持顺序。设置页只能往上追加，**删不掉**配置文件里声明的条目（页面上以只读小字列出）。
> `data/settings.json` 里只保存设置页那一份，空数组不会清空配置底线。
>
> 因此推荐用法：**长期、必须保护**的目录写进 `cordis.patch.yml`（底线，改配置改）；
> **临时、随手加**的目录在设置页里填（随时可删）。

---

## 5. 日常使用

| 需求 | 做法 |
|---|---|
| 看状态 / 占用 | `node bin/delete-guard.mjs status`（加 `--json` 出机器可读） |
| 看审计 | `backup\_audit\YYYY-MM-DD.jsonl`（事件：`startup` / `gate` / `backup` / `confirm` / `confirm-required` / `settings` / `bypass` / `shutdown`） |
| 预演某条命令要备份多少 | `node bin/delete-guard.mjs dry-run -- <命令>`（不删除、不写备份） |
| 还原某个批次 | **普通终端**执行 `node bin/delete-guard.mjs restore <批次\|latest> [--force] [--to 目录]` |
| 清理过期备份 | `node bin/delete-guard.mjs gc`（按分区保留策略清理，审计不删） |
| 改备份根 | `--root <目录>` 或改配置 `backup.root` |

保留策略（自动执行，也可手动 `gc`）：

- `.dsh` 区域：只保留最新 **10** 个批次，且不超过 **30** 天（`backup.dshRetentionCount` / `dshRetentionDays`）；
- 敏感区：保留 **30** 天（`backup.retentionDays`）；
- 工作区：不产生批次；

---

## 6. 故障处置

| 现象 | 判定 | 处理 |
|---|---|---|
| `status` 显示健康异常 | 备份根不可用/不可写 | 修目录权限；期间所有敏感区操作都会被 fail-closed 阻断（这是预期） |
| 钩子文件缺失 | `hooks/python/sitecustomize.py` 或 `hooks/node/delete-guard.cjs` 丢了 | 从版本库恢复；缺失时对应钩子自动禁用并告警，shell 层仍生效 |
| 设置页空白 / 报「读取设置失败」 | 设置路由没通 | 查 §3.3；门禁本身不受影响 |
| 敏感区删除被直接放行 | **门禁失效，严重** | 立即停用（第 7 节），查 `enabled`、`emergencyBypass`、审计里有无 `startup` |
| 工作区删除要确认码 | 工作区基准判定错误 | 见 §3.5 失败判定 |
| 模型说「无法修改插件代码」 | 自保护在起作用（预期） | 需要改代码时按第 7 节由用户停用 |

---

## 7. 停用 / 回滚（只有用户能做）

停用（保留安装）：

- [ ] DSH「设置 → 插件」里停用「敏感数据守卫」

停用后**立即彻底失效**：`dispose()` 会置位并让
`onPreExecute` / `evaluate` / `prepareShell` / `onPostExecute` / `guard` 全部短路，
`ctx.shell.execute` 的包装也会被还原——不会出现「已停用却仍拦截」。

重新启用：

- [ ] 停用后门禁不再加载，模型可以直接用 `plugin_manager` → `set_bundle`（target =
      `@local/dsh-sensitive-data-guard`，`enabled: true`）重新启用；
- [ ] 启用后重复 §3.1 / §3.4 / §3.5 三项验证。

卸载（保留备份）：

- [ ] 插件页卸载，或用户执行 `plugin_manager remove_bundle @local/dsh-sensitive-data-guard`
- [ ] 备份根不会被删除；需要腾空间时手工清理 `backup`

**回滚条件（出现任一即回滚）**：

1. 安装 `application` 不是 `applied`，或 `warnings` 含引擎/依赖问题；
2. §3.4 敏感区探测未被拦截；
3. 正常开发时频繁误拦工作区操作（§3.5 失败）且短时间修不好；
4. 设置页/路由导致 DSH 启动或设置面板报错。

回滚动作：停用 → （如需）`remove_bundle` → 需要时把 `data\settings.json` 与 `backup\` 保留备查。

---

## 注意事项

- 不要为了「绕过门禁」去手工改 profile 的其它文件；要临时关闭请走第 7 节。
- 完全权限（`danger-full-access`）下模型仍可用任意代码写文件；这是同权限边界。
  插件保证的是「DSH 工具链发起的删除/覆盖先备份、失败即阻断」，不是 OS 级防篡改。
- 模型无法通过 `plugin_manager` 卸载或替换本插件（`install_bundle` / `remove_bundle` /
  `set_bundle` / `set_plugin` 命中自身名字会被直接拒绝）——这是刻意的自保护。
- 修改插件源码前必须由用户停用；插件目录、备份根、审计目录、profile 的
  `cordis.patch.yml`/`cordis.yml`/`package.json` 恒为受保护路径，任何级别下都拒绝修改。
