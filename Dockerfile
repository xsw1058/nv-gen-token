FROM golang:1.24-alpine AS build
ADD ./* ./
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories
RUN apk update && \
    apk add gpgme btrfs-progs-dev llvm15-dev gcc musl-dev
RUN GOPROXY=https://goproxy.cn,direct CGO_ENABLE=0 GO111MODULE=on GOOS=linux GOARCH=amd64 go build '-buildmode=pie' -ldflags '-extldflags -static' -gcflags ''  -o ./gen-join-token

FROM alpine:3.21.3
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories
RUN apk update && \
    apk add curl jq bash
COPY --from=build /go/gen-join-token /usr/local/bin/gen-join-token
ENTRYPOINT ["/usr/local/bin/gen-join-token"]