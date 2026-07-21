FROM golang:1.25-alpine AS builder

WORKDIR /src
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/dmh .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/dmh-cli ./cmd

FROM alpine:3.21

RUN apk add --no-cache ca-certificates \
    && addgroup -g 1000 dmh \
    && adduser -D -H -u 1000 -G dmh dmh

COPY --from=builder /out/dmh /out/dmh-cli /usr/local/bin/

USER dmh:dmh

CMD ["dmh"]
