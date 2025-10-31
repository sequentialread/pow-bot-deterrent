
FROM golang:1.22-alpine as build
ARG GOARCH=
ARG GO_BUILD_ARGS=

RUN mkdir /build
WORKDIR /build
RUN apk add --update --no-cache ca-certificates git
COPY go.mod go.mod
COPY go.sum go.sum
COPY main.go main.go
RUN  go get && go build -v $GO_BUILD_ARGS -o /build/pow-bot-deterrent .

FROM alpine
WORKDIR /app
COPY --from=build /build/pow-bot-deterrent /app/pow-bot-deterrent
COPY static /app/static
COPY PoW_Bot_Deterrent_API_Tokens /app/PoW_Bot_Deterrent_API_Tokens
ENTRYPOINT ["/app/pow-bot-deterrent"]

