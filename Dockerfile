FROM node:24-alpine

WORKDIR /app
COPY app/package.json app/package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force \
    && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx
COPY --chown=node:node app/index.js ./

USER node
EXPOSE 3000
CMD ["node", "index.js"]
