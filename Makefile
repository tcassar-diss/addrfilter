all: addrfilter build-af-seccomp 

addrfilter: gen-filter gen-wlgen
	go build -o bin/ ./cmd/addrfilter

build-%:
	go build -o bin/ ./cmd/$*

gen-%:
	go generate ./bpf/$*

sample: main.c
	gcc -o bin/print main.c

clean:
	rm -rf bin
