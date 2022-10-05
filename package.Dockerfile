FROM alpine:3.16.2@sha256:1304f174557314a7ed9eddb4eab12fed12cb0cd9809e4c28f29af86979a3c870

ARG APP_VER

ENV APP_VER=${APP_VER}

COPY build/jdbc-basicauth-proxy_amd64_alpine /opt/app/jdbc-basicauth-proxy

WORKDIR /opt/app

CMD ["/opt/app/jdbc-basicauth-proxy"]
