FROM golang:1.23-alpine
ENV SRC=/go/src/app

WORKDIR $SRC
COPY . .

RUN go build -v .

WORKDIR $SRC/cmd

RUN go build -o /bin/dmh-cli -v .

WORKDIR $SRC

CMD ["./dmh"]
