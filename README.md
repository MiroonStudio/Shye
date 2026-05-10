# Shye Experiment Simulator

中文说明见下方。

## Overview

Shye is a C#/.NET experiment simulator used to generate data for paper evaluation. It models Shye and several baseline protocols over synthetic overlay topologies, then exports raw per-run CSV files and aggregated summary tables for plotting and analysis.

This repository is intended as a reproducible experiment harness. It is not a production protocol implementation, a packet-level network emulator, or a cryptographic implementation.

## What Is Simulated

The simulator includes:

- Shye abstract protocol flow: message injection, cover traffic, local flooding, auction claims, winner certification, TTL-based progression, deduplication, and rendezvous delivery.
- Baseline protocols: `fixed_path_onion`, `random_walk`, and `flooding`.
- Overlay topologies: `random`, `regular_like`, and `power_law`.
- Adversarial settings: malicious-node fraction, observer mode, Sybil identity multiplier, grinding attempts, malicious delay, and malicious drop probability.
- Metrics: delivery success rate, latency, throughput, total broadcasts, total bytes, duplicate-drop ratio, source-identification rate, path-linking rate, path-capture probability, malicious-winner ratio, winner-cert success rate, settlement-timeout ratio, and rendezvous-delivery success rate.

The anonymity attack component is a parameterized estimator, not a full trace-reconstruction attack. When using the results in a paper, describe it as an abstract threat-model estimator and report the configured assumptions.

## Requirements

- .NET SDK 10.0 or newer

Build:

```bash
dotnet build
```

## Quick Start

Run a small smoke experiment:

```bash
dotnet run -- experiment --config configs/smoke.json
```

The command writes raw CSV files under:

```text
results/raw/<experiment-name>_<timestamp>/
```

Aggregate one run directory into a summary table:

```bash
dotnet run -- summarize --input results/raw/<run-directory> --output results/summary/<run-directory>
```

Run a sweep while overriding the number of seeds:

```bash
dotnet run -- sweep --config configs/scale-full.json --seeds 30
```

## Experiment Configurations

The `configs/` directory contains the main experiment definitions:

- `smoke.json`: small validation run.
- `scale-full.json`: scale comparison across network sizes.
- `latency-overhead.json`: TTL and latency/overhead comparison.
- `topology-compare.json`: comparison across random, regular-like, and power-law topologies.
- `anonymity-attack.json`: adversarial observer and malicious-node sweeps.
- `ablation.json`: Shye feature ablations.

Each configuration controls protocol selection, seeds, topology type, network size, traffic rate, Shye parameters, adversarial parameters, cryptographic cost model, and output options.

## Output Files

Raw experiment output is written to `results/raw/...`.

- `run_metrics.csv`: one row per simulation run, containing the main metrics used for figures.
- `messages.csv`: one row per generated real message.
- `node_state.csv`: sampled per-node state sizes, when enabled.
- `events.csv`: detailed event trace, when enabled.

Aggregated summaries are written to `results/summary/...`.

- `summary.csv`: grouped mean, standard deviation, 95% confidence interval, and sample count for each metric.

Existing paper figures are stored in `paper_figures/`.

## Reproducibility Notes

- Randomness is seed-controlled. The same config and seed set should reproduce the same simulation data on the same runtime.
- Output directories include timestamps to avoid overwriting previous runs.
- For publication-quality runs, prefer more seeds than the small smoke or draft configs.
- Record the exact config file, command line, .NET SDK version, and code revision used for each figure.
- If the repository is not under version control, archive the full source tree together with the generated data.

## Important Modeling Assumptions

- The Shye protocol is modeled at an abstract event level. It does not perform real cryptographic operations.
- Cryptographic costs are configured as fixed byte and latency costs.
- Rendezvous delivery is modeled as successful committee availability, not as full end-to-end application delivery to the sampled `destination_id`.
- The attack estimator uses configured probability multipliers and observed protocol state, rather than reconstructing identities or paths from a complete adversarial trace.
- Baseline protocols are simplified comparison points. Their fairness assumptions should be described alongside the paper figures.

## Suggested Paper Workflow

1. Run the relevant config under `configs/`.
2. Summarize the generated `run_metrics.csv`.
3. Plot from `summary.csv`.
4. Keep the raw CSV directory and summary directory for artifact review.
5. Report the config name, seed count, topology, traffic rate, adversary setting, and metric definitions in the paper or appendix.

## CLI Reference

```bash
dotnet run -- experiment --config <config.json>
dotnet run -- sweep --config <config.json> [--seeds <count>]
dotnet run -- summarize --input <run_metrics.csv-or-directory> --output <summary.csv-or-directory>
```

---

# Shye 论文实验仿真器

## 项目概览

Shye 是一个用于生成论文评测数据的 C#/.NET 实验仿真器。它在合成覆盖网络拓扑上模拟 Shye 与若干 baseline 协议，并导出原始 CSV 与聚合后的 summary 表，供后续绘图和分析使用。

这个仓库的定位是可复现实验工具。它不是生产级协议实现，不是包级网络仿真器，也不是真实密码学实现。

## 仿真内容

当前程序包含：

- Shye 抽象协议流程：消息注入、cover traffic、局部 flooding、auction claim、winner certification、TTL 推进、去重和 rendezvous delivery。
- Baseline 协议：`fixed_path_onion`、`random_walk`、`flooding`。
- 覆盖网络拓扑：`random`、`regular_like`、`power_law`。
- 对手设置：恶意节点比例、观察者模式、Sybil 身份倍率、grinding 次数、恶意延迟和恶意丢包概率。
- 指标：投递成功率、延迟、吞吐量、广播次数、总字节数、重复包丢弃比例、源识别率、路径关联率、路径捕获概率、恶意 winner 比例、winner cert 成功率、settlement timeout 比例和 rendezvous delivery 成功率。

匿名性攻击部分是参数化估计器，不是完整的 trace reconstruction 攻击算法。在论文中使用相关结果时，建议明确称为抽象 threat-model estimator，并报告对应参数假设。

## 环境要求

- .NET SDK 10.0 或更新版本

构建项目：

```bash
dotnet build
```

## 快速开始

运行一个小型 smoke 实验：

```bash
dotnet run -- experiment --config configs/smoke.json
```

运行后会在以下目录写入原始 CSV：

```text
results/raw/<experiment-name>_<timestamp>/
```

将一次运行目录聚合成 summary：

```bash
dotnet run -- summarize --input results/raw/<run-directory> --output results/summary/<run-directory>
```

运行 sweep，并覆盖 seed 数量：

```bash
dotnet run -- sweep --config configs/scale-full.json --seeds 30
```

## 实验配置

`configs/` 目录包含主要实验定义：

- `smoke.json`：小型验证实验。
- `scale-full.json`：不同网络规模下的比较。
- `latency-overhead.json`：不同 TTL 下的延迟和开销比较。
- `topology-compare.json`：随机、类规则、幂律拓扑比较。
- `anonymity-attack.json`：观察者模式与恶意节点比例 sweep。
- `ablation.json`：Shye 功能消融实验。

每个配置文件控制协议集合、seed、拓扑类型、网络规模、流量速率、Shye 参数、对手参数、密码学开销模型和输出选项。

## 输出文件

原始实验输出位于 `results/raw/...`。

- `run_metrics.csv`：每个 simulation run 一行，包含绘图使用的核心指标。
- `messages.csv`：每条真实消息一行。
- `node_state.csv`：按时间采样的节点状态大小，启用时生成。
- `events.csv`：详细事件轨迹，启用时生成。

聚合结果位于 `results/summary/...`。

- `summary.csv`：按实验参数分组后的 mean、stddev、95% confidence interval 和 sample count。

已有论文图保存在 `paper_figures/`。

## 可复现性说明

- 随机性由 seed 控制。同一配置和同一 seed 集合在相同 runtime 下应产生相同数据。
- 输出目录带有时间戳，避免覆盖历史结果。
- 用于正式论文图时，建议使用比 smoke 或草稿配置更多的 seed。
- 每张图应记录精确 config 文件、命令行、.NET SDK 版本和代码版本。
- 如果仓库没有纳入版本控制，建议将完整源码树与生成数据一起归档。

## 重要建模假设

- Shye 协议是在抽象事件层建模，不执行真实密码学操作。
- 密码学成本被建模为固定字节数和固定延迟。
- Rendezvous delivery 表示 committee 可用性成功，不等价于完整应用层端到端送达 sampled `destination_id`。
- 攻击估计器使用配置化概率乘子与协议状态，而不是从完整对手 trace 中真实重建源或路径。
- Baseline 协议是简化比较对象。论文中应同时说明其公平性假设。

## 建议论文数据流程

1. 运行 `configs/` 下对应实验配置。
2. 对生成的 `run_metrics.csv` 做 summary 聚合。
3. 从 `summary.csv` 绘图。
4. 保留 raw CSV 与 summary 目录，用于 artifact review。
5. 在论文或附录中报告 config 名称、seed 数量、拓扑、流量速率、对手设置和指标定义。

## CLI 参考

```bash
dotnet run -- experiment --config <config.json>
dotnet run -- sweep --config <config.json> [--seeds <count>]
dotnet run -- summarize --input <run_metrics.csv-or-directory> --output <summary.csv-or-directory>
```
