FROM node:24.13.1-bookworm@sha256:00e9195ebd49985a6da8921f419978d85dfe354589755192dc090425ce4da2f7

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates git openssh-client \
    && rm -rf /var/lib/apt/lists/*
RUN npm install --global --force pnpm@11.10.0 && pnpm --version

ENV CI=1 \
    CIHASH=1 \
    ELECTRON_SKIP_BINARY_DOWNLOAD=1 \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

WORKDIR /seed
COPY repository/ ./
RUN pnpm install --frozen-lockfile --ignore-scripts \
    && find . -type d -name node_modules -prune -print0 \
      | tar --null --files-from=- --create --file=/opt/node-modules.tar \
    && find . -type d -name node_modules -prune -exec rm -rf {} +

COPY run-tooling.sh /usr/local/bin/cihash-t4-tooling
RUN chmod 0555 /usr/local/bin/cihash-t4-tooling
