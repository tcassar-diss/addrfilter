all: ./bpf/gen.go main.go
	go generate ./bpf
	go build -o bin/addrspace .

clean:
	rm -rf bin
