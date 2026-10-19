# Shoplist: one Node process without dependencies; the database lives in /data
FROM node:20-alpine
WORKDIR /app
COPY server.js ./
COPY public ./public
RUN mkdir /data && chown node:node /data
ENV HOST=0.0.0.0 PORT=8080 DATA_DIR=/data TRUST_PROXY=private BRANDING_DIR=/branding
USER node
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=1m --timeout=5s CMD wget -qO /dev/null http://127.0.0.1:8080/login || exit 1
CMD ["node", "server.js"]
