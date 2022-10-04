FROM golang:1.19-alpine3.16

WORKDIR /opt/app

COPY proxy.go go.mod go.sum ./

RUN go build -o druid-auth-proxy .


FROM alpine:3.16.2

ARG APP_VER

ENV APP_VER=${APP_VER}

COPY --from=0 /opt/app/druid-auth-proxy /opt/app/druid-auth-proxy

WORKDIR /opt/app

RUN apk -U add --no-cache curl

CMD ["/opt/app/druid-auth-proxy"]
