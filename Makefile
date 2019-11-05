all:
	mkdir -p build
	env GO111MODULE=on CGO_ENABLED=0 go build -o build/main .