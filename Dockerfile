FROM --platform=$BUILDPLATFORM golang:1.26.5-alpine3.24 AS build

WORKDIR /src
COPY . .
RUN go mod download

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
RUN set -eux; \
    if [ "$TARGETARCH" = "arm" ]; then export GOARM="${TARGETVARIANT#v}"; fi; \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build -trimpath -ldflags="-s -w" -o /out/filter .

FROM --platform=$BUILDPLATFORM alpine:3.24 AS certs

RUN apk -U upgrade && apk add --no-cache ca-certificates \
    && mkdir -p /app /config /tmp/cache

FROM scratch

COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=certs /app /app
COPY --from=certs /config /config
COPY --from=certs /tmp /tmp
COPY --from=build /out/filter /app/filter

WORKDIR /app

ENV SUBFILTER_CONFIG=/config/config.yaml
ENV SUBFILTER_PORT=8000
ENV LOG_LEVEL=info

EXPOSE 8000/tcp

ENTRYPOINT ["/app/filter"]