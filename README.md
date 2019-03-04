# x64

x86-64 instruction encoder in Go (work in process)

This package contains a more-or-less direct port of the instruction-encoding logic from [CensoredUsername/dynasm-rs](https://github.com/CensoredUsername/dynasm-rs). Only a relatively small subset of the features in `dynasm-rs` are supported. Not many features are working or tested yet, but the intended use-case is assembling executable code at runtime.

See the [docs](https://godoc.org/github.com/wdamron/x64) or otherwise look at the tests for a few usage examples.