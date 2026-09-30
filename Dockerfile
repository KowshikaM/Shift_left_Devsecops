FROM node:24-alpine

RUN addgroup -S appgroup && adduser -S -u 1000 appuser -G appgroup

WORKDIR /app
COPY app/package.json app/package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force \
    && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx
COPY --chown=appuser:appgroup app/index.js ./

USER appuser
EXPOSE 3000
CMD ["node", "index.js"]
