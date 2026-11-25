# 可安装的外部JS队列尾延迟分析器（0.1.0候选）

不是新宿主/不是空握手。Go原重建SessionOverview后，既有external.go JSON-over-stdio真实执行包内Node/analyze.mjs；JS计算正值驻留p95、超阈样本数与不完整覆盖，返回Insight/KPI，由Go enrichOverview加入会话API响应。Cordis3仅做准入、激活代次、lease与撤销/结果接受，不替JS统计，也不替Go重建；不声称全部分析迁JS。

使用显式包内Node安装，禁止PATH Node搜索/下载：
```sh
python3 /absolute/queue-tail-analyzer/install.py --app-dir /absolute/running-owned-app --node /absolute/package/node-linux-x64/bin/node
```
安装器绑定当前Node绝对路径后走既有preview/install API，临时输入目录仅在自己的APP内、安装后删除；插件文件实际复制到PluginsDir，后续真实子进程执行。manifest.json是需绑定的模板，不直接把@EXPLICIT_NODE@拖入安装。另提供的prepared .pktplugin只适用其manifest明确绑定的当前包路径；换解包目录请重新运行安装器，不能假设包移位后旧路径仍有效。

结果仅本次overview响应的plugin_insights/plugin_kpis/plugin_notes，不修改基础重建缓存、不自动写会话磁盘结果。每次overview读取会重新分析。基于输入行而非流量总体，零值/缺失/不适用不进入正值分位数；不提升证据等级，不推断SLA或根因。sample_id等unsafe整数用Node22+source-aware JSON BigInt保真，但此插件不输出sample_ids，避免跨JS数值精度损失。当前随包Node24.22.1；Windows/任意Node版本未测。

正常运行不做文件I/O、不访问设备/网络、不fork子孙。仅受控测试显式设置PKTPATH_QUEUE_TAIL_AUDIT_DIR为已存在的自有目录时写原始输入/输出证据（可能含会话内容，真实数据不要随意启用/分享）；文件独占创建。每次notes带PID/PPID/Node与输入SHA256，用于核真实执行，不是伪造结果桩。stdin上限64MiB，非法协议/配置/JSON非零退出，Go既有15秒限制不变。失败进入plugin_notes，不默默用恒定结果。该插件依然宿主可执行代码、不是沙箱，仅可信本机开发能力；不扩大原任意子孙/安装事务/HMR保证。

合成会话只验证机制不是采集；真实流量/设备、UI浏览器呈现、Windows、超大真实会话/性能未验。Go默认及配置事务关闭不变。
