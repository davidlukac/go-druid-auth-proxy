FROM alpine:3.16.2@sha256:1304f174557314a7ed9eddb4eab12fed12cb0cd9809e4c28f29af86979a3c870

ARG APP_VER

LABEL org.opencontainers.image.title="jdbc-basicauth-proxy"
LABEL org.opencontainers.image.description="Simple JDBC to BasicAuth proxy"
LABEL org.opencontainers.image.authors="David Lukac <david.lukac@users.noreply.github.com>"
LABEL org.opencontainers.image.url="https://github.com/davidlukac/go-jdbc-basicauth-proxy"
LABEL org.opencontainers.image.source="https://github.com/davidlukac/go-jdbc-basicauth-proxy"
LABEL org.opencontainers.image.version=${APP_VER}
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.base.digest="sha256:1304f174557314a7ed9eddb4eab12fed12cb0cd9809e4c28f29af86979a3c870"
LABEL org.opencontainers.image.base.name="alpine:3.16.2"

ENV APP_VER=${APP_VER}

COPY build/jdbc-basicauth-proxy_amd64_alpine /opt/app/jdbc-basicauth-proxy

WORKDIR /opt/app

CMD ["/opt/app/jdbc-basicauth-proxy"]
