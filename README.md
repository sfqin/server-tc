# Miao 生产环境 GitHub Actions 公网探测

本仓库只承载 Miao 生产环境的公开可用性探测。GitHub 托管 Runner 每次从公网解析
`miao.lvxingzhe.top`，确认全部 A/AAAA 地址都属于配置的服务端公网 IP 集合，再连接
本次已验证的 IP，同时继续使用域名完成 HTTP Host、TLS SNI 和证书主机名校验。

不需要独立 Linux 探测机，也不需要在 Miao 业务服务器安装程序。

## 探测规则

- 固定目标：`https://miao.lvxingzhe.top/readyz`。
- 必须返回 HTTP 200。
- JSON 必须满足 `ok=true`、`environment=production`、`database=ok`。
- 每个 workflow 内间隔 10 秒探测两次，连续两次失败才触发飞书告警。
- 故障后连续两次成功发送恢复消息，并沿用同一个 incident ID。
- GitHub Actions cache 保存 incident 和待发消息状态，避免持续故障每次重复通知。
- DNS、HTTPS 和单次飞书请求各自使用有限时限，workflow 最长运行 2 分钟。

## GitHub 配置

仓库必须保持为公开仓库，只提交此处的公开探测代码。不要提交 Webhook、签名密钥、
业务代码或其他私有配置。

进入仓库的 `Settings` → `Secrets and variables` → `Actions`。

创建一个 Repository variable：

```text
MIAO_PRODUCTION_EXPECTED_IPS=116.205.225.8
```

如果已经把 `MIAO_PRODUCTION_EXPECTED_IPS` 创建为 Repository secret，也不需要重新
配置；workflow 同时兼容两种位置并优先读取 Variable。不要在两处填写不同的值。

`116.205.225.8` 是 2026-09-26 的实际解析结果。配置前应再次执行
`dig +short A miao.lvxingzhe.top` 和 `dig +short AAAA miao.lvxingzhe.top`；如果 DNS
同时发布多个 A/AAAA 地址，必须用英文逗号填写全部实际公网地址。

创建两个 Repository secrets：

```text
MIAO_PROBE_FEISHU_WEBHOOK_URL=https://open.feishu.cn/open-apis/bot/v2/hook/真实Token
MIAO_PROBE_FEISHU_SECRET=飞书机器人签名密钥
```

飞书机器人必须开启签名校验。程序只接受 `open.feishu.cn` 或
`open.larkoffice.com` 官方 HTTPS Webhook，日志不会打印 Webhook、签名密钥或完整
DNS 地址集合。

## 启用

workflow 文件位于 `.github/workflows/production-probe.yml`。代码推送到默认分支 `main`
后，GitHub 才会启用 `schedule` 和 `workflow_dispatch`。定时表达式为每 5 分钟一次：

```yaml
cron: '*/5 * * * *'
```

GitHub 的 schedule 是尽力调度，实际是约 5 分钟一次，繁忙时可能延迟或跳过，不能作为
严格的 5 分钟 SLA。公开仓库连续 60 天没有活动时，GitHub 还可能自动停用定时任务，
需要在 Actions 页面重新启用。

## 首次验收

先配置正常的 Variable 和两个 Secrets，然后进入 `Actions` →
`Probe Miao production` → `Run workflow`，保持 `expected_ips_override` 为空。

正常运行应出现两条类似日志：

```json
{"event":"production_external_probe","result":"success","category":"ok","state":"normal"}
```

随后手动再运行一次，在 `expected_ips_override` 输入一个不匹配的公网地址：

```text
1.1.1.1
```

同一个 workflow 会连续产生两次 `dns_mismatch`，飞书应只收到一条触发消息。然后再次
手动运行并保持输入为空，两次正常探测后，飞书应收到同一 incident ID 的恢复消息。

## 本地验证

需要 Python 3.9+ 和 OpenSSL：

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile production_probe.py tests/test_production_probe.py
```

## 状态缓存限制

GitHub Actions cache 不是数据库。workflow 使用并发组避免同一环境重叠运行，并为每次
运行保存新的小型状态缓存；旧缓存会由 GitHub 自动回收。如果 GitHub 清除了全部缓存，
持续故障期间可能再发送一条新的触发告警，但不会影响 DNS、TLS 和健康合同本身的判定。

如果日志出现 `state_error`，在仓库 Actions caches 页面删除
`miao-production-probe-v1-` 前缀的缓存，再手动运行一次 workflow。
