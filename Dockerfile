# syntax=docker/dockerfile:1.7

FROM rust:1-alpine AS build
RUN apk add --no-cache build-base cmake perl
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked


FROM alpine:3.21 AS xray
ARG XRAY_CORE_VERSION=v26.7.28
ARG UPSTREAM_REPO=XTLS
ARG TARGETARCH
RUN apk add --no-cache curl \
    && case "${TARGETARCH}" in \
        amd64) ARCHIVE='Xray-linux-64.zip' ;; \
        arm64) ARCHIVE='Xray-linux-arm64-v8a.zip' ;; \
        *) echo "unsupported arch ${TARGETARCH}"; exit 1 ;; \
    esac \
    && BASE="https://github.com/${UPSTREAM_REPO}/Xray-core/releases/download/${XRAY_CORE_VERSION}" \
    && curl -fsSL -o "/tmp/${ARCHIVE}" "${BASE}/${ARCHIVE}" \
    && curl -fsSL -o /tmp/xray.dgst "${BASE}/${ARCHIVE}.dgst" \
    && echo "$(awk '/^SHA2-256=/ { print $2 }' /tmp/xray.dgst)  /tmp/${ARCHIVE}" | sha256sum -c - \
    && unzip -q "/tmp/${ARCHIVE}" -d /tmp/xray \
    && install -m 755 /tmp/xray/xray /usr/local/bin/xray \
    && install -d /usr/local/share/xray \
    && install -m 644 /tmp/xray/geoip.dat /usr/local/share/xray/geoip.dat \
    && install -m 644 /tmp/xray/geosite.dat /usr/local/share/xray/geosite.dat


FROM alpine:3.21 AS asn
ARG ASN_LMDB_URL=https://github.com/remnawave/asn-index/releases/latest/download/asn-prefixes.lmdb.zst
RUN apk add --no-cache zstd curl
RUN curl -fsSL -o /tmp/asn-prefixes.lmdb.zst "${ASN_LMDB_URL}" \
    && mkdir -p /usr/local/share/asn \
    && zstd -d /tmp/asn-prefixes.lmdb.zst -o /usr/local/share/asn/asn-prefixes.lmdb \
    && chmod 644 /usr/local/share/asn/asn-prefixes.lmdb


FROM alpine:3.21 AS geocheck
ARG GEOCHECK_VERSION=0.3.0
ARG GEOCHECK_RELEASE_URL=https://github.com/remnawave/geocheck/releases/download
ARG TARGETARCH
RUN apk add --no-cache curl \
    && cd /tmp \
    && ARCHIVE="geocheck_linux_${TARGETARCH}.tar.gz" \
    && curl -fsSL -O "${GEOCHECK_RELEASE_URL}/v${GEOCHECK_VERSION}/${ARCHIVE}" \
    && curl -fsSL -O "${GEOCHECK_RELEASE_URL}/v${GEOCHECK_VERSION}/checksums.txt" \
    && grep "  ${ARCHIVE}\$" checksums.txt | sha256sum -c - \
    && tar -xzf "${ARCHIVE}" geocheck \
    && install -m 0755 geocheck /usr/local/bin/geocheck


FROM alpine:3.21
LABEL org.opencontainers.image.title="Remnawave Node (Rust)" \
      org.opencontainers.image.description="Remnawave Node rewritten in Rust, with built-in XRay Core" \
      org.opencontainers.image.licenses="AGPL-3.0"

# nftables: the `nft` CLI used by the firewall plugins. ca-certificates: custom core / geodata downloads.
RUN apk add --no-cache nftables ca-certificates

COPY --from=build /src/target/release/remnawave-node /usr/local/bin/remnawave-node
COPY --from=xray /usr/local/bin/xray /usr/local/bin/xray
COPY --from=xray /usr/local/share/xray /usr/local/share/xray
COPY --from=asn /usr/local/share/asn /usr/local/share/asn
COPY --from=geocheck /usr/local/bin/geocheck /usr/local/bin/geocheck

ENTRYPOINT ["/usr/local/bin/remnawave-node"]
