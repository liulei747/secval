FROM node:22-alpine AS build
WORKDIR /app
COPY package.json tsconfig.json vite.config.ts index.html ./
COPY src ./src
RUN npm install && npm run build

FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
HEALTHCHECK --interval=15s --timeout=3s --retries=5 CMD wget -q --spider http://localhost/healthz || exit 1
