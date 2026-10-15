# Glama and other stdio hosts. The production API is the Cloudflare Worker.
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/dist/stdio.js /app/dist/stdio.js
USER node
CMD ["node", "dist/stdio.js"]
