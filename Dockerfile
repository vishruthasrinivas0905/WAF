FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:22-alpine AS runtime
RUN apk add --no-cache python3 curl
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/server.ts ./server.ts
COPY --from=build /app/src/waf ./src/waf
COPY --from=build /app/waf ./waf
COPY --from=build /app/scripts/benchmark_waf.py ./scripts/benchmark_waf.py
EXPOSE 3000
CMD ["npm", "start"]
