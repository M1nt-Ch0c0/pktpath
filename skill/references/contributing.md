# 开发验证与贡献流程

[文档目录](index.md) · [agent 任务入口](../SKILL.md)

## 1. 定界与取证

- 明确要改的层、行为与成功条件；`git status --short` / `git rev-parse HEAD` 记录干净基准或已有改动。不要覆盖他人文件或复用别人的构建目录。
- 从 [架构地图](architecture.md) 找消费者/生产者；先阅读当前源码与对应测试，再给结论。区分源码事实、构造测试事实、设备观测和推测。
- 设计最小复现和反例：例如“丢失窗口使分支 incomplete”与“无丢失时仍能 complete”，不能只写一个成功 happy path。

## 2. 按层验证

| 任务层 | 最小检查 | 额外需要的证据 |
| --- | --- | --- |
| 文档 / skill | frontmatter `name/description`、相对链接、源码路径、真实 CLI 选项、`git diff --check` | diff 只含预期文档，不夹带生成头或二进制 |
| Python / wire / 重建 | unittest 全量及新增反例 | 同一会话比较 Go 侧语义；UUID/CRC/未知 TLV/质量缺口不退化 |
| Go kernel / 插件 / server | `go test ./...`、`go vet ./...`，补最小失败用例 | 配置持久化、依赖级联、effect 清理、API 错误路径；Windows 入口另验 |
| runtime JSON / bundle | 示例 JSON/hook 测试、Go kernel/plugins/server 测试 | 两层契约和物化结果；不合法 size/mode、槽位上限、禁用卸载、hook 故障和信任边界 |
| C / BPF | 目标构建、必要时双架构再生成 | 真机 inspect、load/attach、短时 record、完整会话离线重建；报告不可用目标而非伪造通过 |
| UI / 打包 / transport | 无设备测试及真实 Windows 打包/前端验收 | ADB/SSH/GUI E2E 各自独立结果；缺环境明确跳过 |

具体命令见 [构建测试](build-test.md)；不要把表格当作已经运行。CI workflow 有独立所有者时避免跨范围修改；本次文档变更不修改 workflow 或产品代码。

### 证据审计的额外验收

- 用完整 `CPU0:1, CPU16:2, CPU0:3` 和独立 CPU0/1 对照检查序号算法；宿主用例不冒充 >16 CPU 真机验证。
- 用 dict 全1但时间线有派生等级的会话，确认插件不按元数据给整会话盖章。
- 用 detail mark4660、overview 缺字段的输入，确认输出 unknown 而非0。
- 用 rx-sock 请求标签但 egress sites/partial 的输入，确认不宣称已观测 RX 无异常。
- 同一 kernel bundle 分别走嵌套直喂设备与扁平入口，检查 0/0 与 1/3 数量、BTF resolved 和实际挂接，不能只看 exit0。
- 对队列0分别测试可信读取与来源不明；当前QSTATE生产合同不可区分两者，未知0只作设备级候选，不因0=0确认或0!=1排除队列关联。非零BTF offset与合成valid标记不代替运行时成功来源。
- 严重性与可信度分开：warn可表示复核优先级；不将SEQ_GAP或独立RB_DROP计数合并成确定的丢失原因/数量。
- 同时保留反证：recorder fallback 能落盘、fwd 确实改变 netns 过滤、可信插件可执行不等同已证实越权；争议需验证，不将同行意见当独立结论。

## 3. 文档维护规则

长篇中文说明仅放 `skill/references/`，`skill/SKILL.md` 保持短任务分流，根 README 链接到目录。源码变更时同步对应专题与测试，删除过时主张；不复制一套并行 docs 导致漂移。

frontmatter 最小示例：

```yaml
---
name: pktpath-development
description: 当需要开发、测试或审查 PktPath 时使用。
---
```

description 写使用时机；保留已有有效其它键。这里是在仓库中创建 skill 目录，不是修改 agent 的共享技能库。

## 4. 提交前

```sh
git diff --check
git diff --stat
git status --short
```

逐文件审阅 diff：无 secrets、私有插件、会话、staging、二进制、未预期生成文件。保留可重跑的检查命令与完整日志；输出中有敏感信息时先脱敏再公开。

仅在已获准时推独立分支并开 PR；不直接推 main、不 force、不自动合并或 release。授权不明确时只留本地提交和 PR 草稿文字，等待确认。

## 5. PR 交付模板

- 目标、范围和明确不改事项；基准 main SHA 与提交 SHA。
- 源码依据和关键契约差异；关联的缺陷给出复现与反方解释。
- 修改文件清单。
- 验证表：命令、环境、退出码、完整日志位置；失败/跳过原因。
- 未验证：CI、设备型号/内核、arm64、Android、Windows GUI、传输、性能等，逐项列出，不写笼统“全部通过”。
- 已知风险/限制与后续独立工作，不在本 PR 暗中扩大范围。
