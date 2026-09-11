# Demo Dockerfile.
# Intentionally starts "bad" (runs as root, mutable base tag handled below)
# so the pipeline has something real to catch. Hardened version is commented
# at the bottom.

FROM node:18

WORKDIR /app
COPY app/package.json ./
RUN npm install --production
COPY app/index.js ./

EXPOSE 3000
CMD ["node", "index.js"]

# ---------------------------------------------------------------------------
# HARDENED VERSION (swap this in once the pipeline flags the block above):
#
# FROM node:18-alpine3.19
#
# RUN addgroup -S appgroup && adduser -S appuser -G appgroup
#
# WORKDIR /app
# COPY app/package.json ./
# RUN npm install --production && npm cache clean --force
# COPY app/index.js ./
#
# USER appuser
# EXPOSE 3000
# CMD ["node", "index.js"]
# ---------------------------------------------------------------------------
