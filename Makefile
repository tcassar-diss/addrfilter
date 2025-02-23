all: ./bpf/gen.go main.go
	go generate ./bpf
	go build -o bin/addrfilter .

sample: main.c
	gcc -o bin/print main.c

clean:
	rm -rf bin
