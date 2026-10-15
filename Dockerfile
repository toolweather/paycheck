# Glama and other stdio hosts. The production API is the Cloudflare Worker.
# Ignore install scripts so wrangler's workerd download is not required.
# esbuild ships a platform binary as an optional dependency.
FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npm run build

FROM node:22-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/dist/stdio.js /app/dist/stdio.js
USER node
CMD ["node", "dist/stdio.js"]
