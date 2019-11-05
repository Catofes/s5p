FROM golang as builder
ENV GO111MODULE=on
WORKDIR /app
COPY . .
RUN go mod download
RUN env CGO_ENABLED=0 go build -o /main .

FROM alpine:3.6
RUN apk add --no-cache tzdata
COPY --from=builder /main /usr/bin/main
ENTRYPOINT ["/usr/bin/main"]
CMD ["-c", "/etc/config.json"]

