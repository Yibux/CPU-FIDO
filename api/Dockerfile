# --- build: kompilacja TS; ten etap służy też do uruchamiania testów (api-test) ---
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json tsconfig.build.json vitest.config.ts ./
COPY migrations ./migrations
COPY src ./src
COPY test ./test
RUN npm run typecheck && npm run build

# --- runtime: tylko zależności produkcyjne, użytkownik non-root ---
FROM node:20-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY migrations ./migrations
COPY --from=build /app/dist ./dist
USER node
EXPOSE 3000
CMD ["node", "dist/server.js"]
