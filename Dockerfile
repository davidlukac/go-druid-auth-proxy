FROM golang:1.19-alpine3.16@sha256:2baa528036c1916b23de8b304083c68fb298c5661203055f2b1063390e3cdddb

WORKDIR /opt/app

COPY proxy.go go.mod go.sum ./

RUN mkdir -p build/ && go build -o build/jdbc-basicauth-proxy .


FROM scratch as export

COPY --from=0 /opt/app/build/jdbc-basicauth-proxy /jdbc-basicauth-proxy_amd64_alpine
