# Wave 1 前端单测（Rui）

静态前端位于 `studio-cordis/web/`，与冻结的旧 Go `studio/web/` 物理隔离。

在仓库根目录用 Node 24 直接运行（无需安装额外依赖、无需 tsc）：

```sh
node --check studio-cordis/web/*.js
node --test studio-cordis/test/web/*.test.ts
```

当前 `studio-cordis/test/web/*.test.ts` 共 40 项（`node:test`）。这些测试使用显式 DOM/事件模型，不是真浏览器点验。

离线示例预览可将本目录静态资源挂到本机 HTTP 后打开 `/?demo=1&autoload=1`。

将本 `studio-cordis/web/` 挂到 Lin 纯 Cordis 底座（不写入 Lin 仓库的空 `web/` 目录），本机启动示例：

```sh
cd /path/to/lin/studio-cordis
node src/main.ts --no-open --host 127.0.0.1 --port 18765 \
  --web-dir /path/to/rui/worktree/studio-cordis/web \
  --app-dir /tmp/pktpath-studio-cordis-app
```

浏览器打开打印的 `PKTPATH_STUDIO_READY url=...`（或 `http://127.0.0.1:18765/`）。`?demo=1` 仅用于无底座离线演示，真机验收请不要带 `demo=1`。
