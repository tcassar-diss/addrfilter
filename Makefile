all: gen-wlgen gen-filter main.go
	go generate ./bpf/filter
	go build -o bin/addrfilter .

gen-%:
	go generate ./bpf/$*

sample: main.c
	gcc -o bin/print main.c

clean:
	rm -rf bin
