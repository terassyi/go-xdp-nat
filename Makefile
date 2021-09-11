GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
CLANG := clang
CLANG_INCLUDE := -I./bpf/headers

GO_SOURCE := main.go
GO_BINARY := main 

ICMP_ONLY_SOURCE := bpf/icmp_only.c
ICMP_ONLY_BINARY := bpf/icmp_only.elf
STATIC_SOURCE := bpf/static.c
STATIC_BINARY := bpf/static.elf

all: build_icmp_only build_static build_go

build_icmp_only: $(ICMP_ONLY_BINARY)

build_static: $(STATIC_BINARY)

build_go: $(GO_BINARY)

clean:
	$(GOCLEAN)
	rm -f $(GO_BINARY)
	rm -f $(STATIC_BINARY)
	rm -f $(ICMP_ONLY_BINARY)

$(ICMP_ONLY_BINARY): $(ICMP_ONLY_SOURCE)
	$(CLANG) $(CLANG_INCLUDE) -DEBUG -O2 -target bpf -c $^ -o $@

$(STATIC_BINARY): $(STATIC_SOURCE)
	$(CLANG) $(CLANG_INCLUDE) -DEBUG -O2 -target bpf -c $^ -o $@

$(GO_BINARY): $(GO_SOURCE)
	$(GOBUILD) -v -o $@
