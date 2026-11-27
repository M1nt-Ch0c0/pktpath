# PktPath 独立 eBPF 插件模板

这是一个可直接复制使用的独立插件脚手架，用于开发自带预编译内核探针的 PktPath 插件包。

## 你能用它做什么

- 编写自定义内核探针源码，编译出适配目标架构的预编译探针文件；
- 在插件设置页提供分组开关与推荐预设；
- 可选附带离线分析逻辑，对采集到的会话输出指标与诊断建议；
- 一键对整包进行 Ed25519 签名并打包成 `.zip`，直接导入 PktPath Studio 使用。

## 快速上手

1. **编译探针**（需本机安装 `clang` 与内核/libbpf 头文件）：
   ```bash
   make arm64
   ```
   如需同时支持 x86_64 Linux，再执行 `make x86_64` 并在 `manifest.json` 中补上对应架构条目。

2. **生成签名密钥（首次使用）**：
   ```bash
   make keygen
   ```
   私钥保存在本地 `keys/private.pem`，请勿提交到代码仓库；将生成的公钥指纹公布给使用者以便核对。

3. **签名并打包**：
   ```bash
   node scripts/sign-and-pack.mjs pack --dir . --out ./dist/example-bpf-plugin.zip --key ./keys/private.pem
   ```
   不传 `--key` 也可打未签名测试包，Studio 安装预览时会明确提示“插件未签名”。

4. **导入 Studio**：
   在 PktPath Studio 的插件管理页选择生成的 `.zip` 文件即可预览签名状态并安装。

## 注意事项

- 签名覆盖包内全部文件；打包后再手动修改其中任意文件都会导致 Studio 拒绝安装。
- 预编译探针需与目标设备的架构及内核能力匹配；若目标设备缺少对应架构的探针文件，采集时会自动跳过该插件而不会中断基础采集。
