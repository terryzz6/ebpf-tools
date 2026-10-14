# ebpf-tools

eBPF 工具源码及 ARM64 构建依赖。

`arm64/lib/libblazesym.a` 超过 GitHub 的单文件大小限制，因此仓库保存其 gzip 压缩版本。克隆仓库后，如需使用该静态库，请先执行：

```sh
gzip -dk arm64/lib/libblazesym.a.gz
```

`.output/` 为构建时生成的中间文件，不纳入版本控制。
