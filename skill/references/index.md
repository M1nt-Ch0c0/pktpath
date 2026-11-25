# PktPath 中文开发文档

本目录是中文开发文档的单一维护来源；[skill 入口](../SKILL.md) 提供 agent 任务分流，[仓库 README](../../README.md) 提供项目入口，不在多处复制长篇指南。

## 阅读路线

1. [架构、数据流与证据边界](architecture.md)
2. [构建、测试与命令契约](build-test.md)
3. [Linux / Android arm64 与排障](platforms-troubleshooting.md)
4. [Studio 微内核、API 与前端](studio.md)
5. [runtime JSON 与 Studio bundle 两层插件契约](plugins.md)
6. [开发验证与贡献流程](contributing.md)

## 本次核对范围

- 源码基准：`77e7868a060fb56d164cd2ba403c991ccaaaa60e`；2026-11-25（Asia/Shanghai，UTC+8）独立 checkout 后与远端 `main` 核对一致。后续源码变化应重新核对，不将旧审计当作当前事实。
- 本地 Linux amd64：Python 3.13.5；Go 1.27.3。实际检查见 [构建与测试](build-test.md)。这是本地结果，不代表 GitHub Actions、所有 Go/Python 最低版本或真实设备矩阵通过。
- 没有在本次文档变更中验证 Android、Linux arm64、Windows GUI、真实 eBPF 加载/挂接、SSH/ADB 采集或性能。README 的内核范围/测试声明不等于本次验证结果。
- 产品版本、wire 版本和插件 manifest 的版本字段不能混用；源码入口和限制见各专题。

许可证以 [LICENSE](../../LICENSE) 为准：主机/用户态/Studio 为 Apache-2.0，`bpf/` 声明 Dual BSD/GPL。不能把这份开发说明当作额外授权或完整法律解释。
