all: ./bpf/gen.go main.go
	go generate ./bpf
	go build -o bin/addrspace .

sample: main.c
	gcc -o bin/print main.c

clean:
	rm -rf bin
