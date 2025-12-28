# Makefile for pidhide eBPF program
.PHONY: all clean generate build run

# 使用立即赋值 := 避免递归引用
BPF_CLANG := clang
BPF_CFLAGS := -O2 -g -Wall -Werror

PROGRAM_NAME := pidhide

# 默认目标
all: generate build

# 生成BPF绑定代码
generate:
	@echo "Generating BPF bindings..."
	@if [ ! -f go.mod ]; then \
		go mod init ${PROGRAM_NAME}; \
	else \
		echo "go.mod already exists, skipping init"; \
	fi
	go mod tidy
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	BPF_CLANG=$(BPF_CLANG) BPF_CFLAGS="$(BPF_CFLAGS)" go generate ./...

# 编译Go程序
build: generate
	@echo "Building Go program..."
	CGO_ENABLED=0 go build -o ${PROGRAM_NAME} .

# 编译并运行示例
run: build
	@echo "Running ${PROGRAM_NAME}..."
	sudo ./${PROGRAM_NAME} -p 1234

# 直接运行（开发时使用）
dev:
	BPF_CLANG=$(BPF_CLANG) BPF_CFLAGS="$(BPF_CFLAGS)" go generate ./...
	CGO_ENABLED=0 go run . -p 1234

# 清理生成的文件
clean:
	@echo "Cleaning up..."
	rm -f ${PROGRAM_NAME}
	rm -f bpf_bpf*.go
	rm -f bpf_bpf*.o
	rm -f ./bpf/*.o
	rm -f go.mod
	rm -f go.sum

# 安装依赖
deps:
	go mod download
	go install github.com/cilium/ebpf/cmd/bpf2go@latest

# 测试BPF程序是否能正常编译
test-bpf:
	@echo "Testing BPF compilation..."
	$(BPF_CLANG) $(BPF_CFLAGS) -target bpf -c ./bpf/pidhide.bpf.c -o ./bpf/pidhide.bpf.o

# 帮助信息
help:
	@echo "可用命令:"
	@echo "  make all      - 生成代码并编译"
	@echo "  make generate - 生成BPF绑定代码"
	@echo "  make build    - 编译Go程序"
	@echo "  make run      - 编译并运行示例"
	@echo "  make dev      - 快速开发运行"
	@echo "  make clean    - 清理生成的文件"
	@echo "  make deps     - 安装依赖"
	@echo "  make test-bpf - 测试BPF编译"