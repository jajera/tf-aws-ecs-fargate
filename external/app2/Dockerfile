FROM golang:alpine AS builder

ENV PORT=8080

WORKDIR /go/src/app

COPY . .

RUN apk --no-cache add curl

RUN go mod init app2 \
    && go build -o app2 .

FROM alpine

ENV PORT=8080

WORKDIR /app

COPY --from=builder /go/src/app/app2 .

RUN echo '{ "name": "app2", "version": "1.0.0" }' > package.json

EXPOSE $PORT

CMD ["./app2"]