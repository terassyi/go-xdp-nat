GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
CLANG := clang
CLANG_INCLUDE := -I./bpf/headers

GO_SOURCE := main.go
GO_BINARY := main 

ICMP_ONLY_SOURCE := bpf/icmp_only.c
ICMP_ONLY_BINARY := bpf/icmp_only.elf

all: build_icmp_only build_go

build_icmp_only: $(ICMP_ONLY_BINARY)

build_go: $(GO_BINARY)

clean:
	$(GOCLEAN)
	rm -f $(GO_BINARY)
	rm -f $(BPF_BINARY)

$(ICMP_ONLY_BINARY): $(ICMP_ONLY_SOURCE)
	$(CLANG) $(CLANG_INCLUDE) -DEBUG -O2 -target bpf -c $^ -o $@

$(GO_BINARY): $(GO_SOURCE)
	$(GOBUILD) -v -o $@
