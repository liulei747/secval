# 本地 Reranker 独立延迟测试

这个目录只用于基准测试，不接入 Secval 搜索服务，也不会读取 `.env`。

默认模型是支持中英文的 `BAAI/bge-reranker-base`。测试读取真实Java文件，截取每个
候选最多2200个字符，模型输入最多256 Token，分别测试1、5、10、20个候选。

CPU测试：

```powershell
docker run --rm `
  --volume secval_huggingface-cache:/models/huggingface `
  --volume "${PWD}:/workspace" `
  --workdir /workspace `
  --env HF_HOME=/models/huggingface `
  secval-api:latest `
  python benchmarks/local_reranker/benchmark.py `
    --repository-root data/repositories/jeesite-Project-api `
    --device cpu `
    --output benchmarks/local_reranker/result.cpu.json
```

`result.cpu.json`记录模型加载时间、峰值进程内存、各候选数量的中位延迟、P95和
每秒处理数量。首次运行包含模型下载时间，但`model_load_seconds`只统计加载阶段。

## 本机CPU实测（2026-09-03）

环境：Docker CPU版PyTorch、最大输入256 Token、批次8、每组重复3次并取中位数。

| 候选数量 | 中位延迟 | P95 | 吞吐量 |
|---:|---:|---:|---:|
| 1 | 138.21 ms | 142.65 ms | 7.24条/秒 |
| 5 | 528.28 ms | 542.56 ms | 9.46条/秒 |
| 10 | 1010.86 ms | 1025.53 ms | 9.89条/秒 |
| 20 | 2033.39 ms | 2037.00 ms | 9.84条/秒 |

- 缓存后的模型加载时间：2.15秒。
- 峰值进程内存：1561.83 MB；加载前为416.05 MB，增量约1145.78 MB。
- 首次下载加加载共356.95秒；这是一次性缓存成本，不是每次搜索延迟。
- 当前生产镜像是CPU版PyTorch，本轮没有测试GPU。

本轮文档直接截取真实Java文件前2200字符，延迟数据有效，但它不是搜索质量评测集；
精度评测应改用平台实际召回的完整CodeChunk候选。
