FROM node:20-slim

ARG APP_VERSION
ARG APP_PACKAGE

WORKDIR /app
RUN npm init -y && npm install "${APP_PACKAGE}@${APP_VERSION}"

COPY server.js .

EXPOSE 3000
CMD ["node", "server.js"]
