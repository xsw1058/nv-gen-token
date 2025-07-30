bin:
	GOPROXY=https://goproxy.cn,direct CGO_ENABLE=0 GO111MODULE=on GOOS=linux GOARCH=amd64 go build '-buildmode=pie' -ldflags '-extldflags -static' -gcflags ''  -o ./gen-join-token

clean:
	rm -rf ./gen-join-token

image:
	docker build --progress=plain -t harbor.mcdchina.net/mcd-public/neuvector/gen-join-token:latest .

