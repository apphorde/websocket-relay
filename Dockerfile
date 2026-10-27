FROM ghcr.io/cloud-cli/image-node:latest
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --cache /tmp/npm-cache
COPY index.js storage.mjs openapi.yaml openapi.json README.md ./
COPY public ./public
RUN mkdir -p /home/app/data
ENV DATA_PATH=/home/app/data PORT=8080
EXPOSE 8080
