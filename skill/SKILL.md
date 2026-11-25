---
name: pktpath-development
description: 当需要理解、开发、测试或审查 PktPath 的采集器、证据重建、Studio 或 runtime JSON 插件时使用；依据源码选择验证流程并明确未验证边界。
---

# PktPath 开发工作流

这是仓库内可携带的开发 skill，不会自动安装到任何 agent 的共享技能库。
中文开发文档只维护在 [references/index.md](references/index.md) 及其链接的专题中。

## 开始前

1. 在仓库根执行 `git status --short`、`git rev-parse HEAD`；记录基准，不覆盖已有改动。
2. 阅读 [架构与证据边界](references/architecture.md)，确定改动层次；检查当前源码而非假定本文版本永远最新。
3. 阅读 [构建与测试](references/build-test.md)，先做不依赖设备的基线检查。
4. 本工作流不授予推送、开 PR、合并、发布、安装插件或操作真实设备的权限；按实际授权行动。不读取凭据，不调用外部代码生成 agent/CLI。

## 按任务执行

| 任务 | 必读参考 | 源码入口与验证目标 |
| --- | --- | --- |
| 分析/修复证据 DAG、wire、导出 | [架构](references/architecture.md)、[验证/贡献](references/contributing.md) | `include/pktpath_wire.h`、`analyzer/`、`studio/pkg/{wire,reconstruct,export}/`；Python/Go 对同一构造会话检查 UUID、CRC、分支、缺口和输出，不以 UI 看起来正常代替断言 |
| C/BPF 或 Linux/Android 支持 | [构建](references/build-test.md)、[平台与排障](references/platforms-troubleshooting.md) | `device/`、`bpf/`、`include/pktpath_bpf.h`；先构建目标，再在获准目标上 inspect，最后限时 record；分别报告编译、加载、挂接、采集、离线重建结果 |
| runtime JSON / bundle 插件 | [两层契约](references/plugins.md) | `device/plugin_loader.c` 与 `studio/pkg/kernel/external.go` 分开核对；Studio bundle 不直接当作设备扁平 JSON；测试配置、禁用卸载、hook 失败、物化与容量边界 |
| Studio / API / UI | [Studio](references/studio.md)、[构建](references/build-test.md) | `studio/pkg/kernel/`、`studio/pkg/server/`、`studio/web/`；Go 测试/vet 后在 Windows 实测桌面入口和前端；Linux 单测不能代替此项 |
| 仅文档 | [验证/贡献](references/contributing.md) | 保持 references 单一来源，检查相对链接、脚本真实选项、frontmatter；确认 diff 不夹带产品/生成文件 |

## 收尾交付

遵循 [贡献检查单](references/contributing.md)。报告基准 SHA、修改文件、每条实际运行命令的退出码/日志、失败或跳过原因，以及 CI/设备/GUI 未验证项。只在获得明确授权后提交远端变更，绝不将“未运行”写成“通过”。
