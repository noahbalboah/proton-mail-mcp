# Proton Mail Bridge, headless, from Proton's own signed .deb.
#
# Package checked 2026-11-25: protonmail-bridge_3.27.2-1_amd64.deb has a good signature from
# Proton's Bridge key D51E 64D3 E63E DC3E EF78 64CE E2C7 5D68 E623 4B07 (the key on proton.me
# matches the one in the GitHub release byte for byte). The build pins that file's SHA-256.
# To upgrade: download the new .deb and its .sig, run `gpg --verify` against that key,
# then change BRIDGE_VERSION and BRIDGE_SHA256.
FROM debian:bookworm-slim@sha256:e67eeead736ff7bbe258ef088bff683635c561b1fcfefad0806c1df4ab49ce0e

ARG BRIDGE_VERSION=3.27.2
ARG BRIDGE_SHA256=cf08332dcc4a332c3592476855e2007e6daadbcdac11fab6af83470a3255a8dc

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && curl -fsSL -o /tmp/bridge.deb \
       "https://github.com/ProtonMail/proton-bridge/releases/download/v${BRIDGE_VERSION}/protonmail-bridge_${BRIDGE_VERSION}-1_amd64.deb" \
    && echo "${BRIDGE_SHA256}  /tmp/bridge.deb" | sha256sum -c - \
    && apt-get install -y --no-install-recommends /tmp/bridge.deb pass gnupg socat tini \
    && apt-get purge -y curl && apt-get autoremove -y \
    && rm -rf /tmp/bridge.deb /var/lib/apt/lists/*

# Bridge refuses IMAP connections that don't come from localhost, so socat re-listens on the
# container's internal network address and forwards to Bridge's loopback port.
RUN useradd --create-home --uid 1001 --shell /usr/sbin/nologin bridge
# Plain COPY + chmod: some hosts build with the classic builder, which has no COPY --chmod.
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY gpgparams /etc/bridge/gpgparams
RUN chmod 0755 /usr/local/bin/entrypoint.sh && chmod 0644 /etc/bridge/gpgparams

USER bridge
WORKDIR /home/bridge
EXPOSE 11143
ENTRYPOINT ["tini", "--", "/usr/local/bin/entrypoint.sh"]
CMD ["run"]
