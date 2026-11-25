FROM node:22-alpine AS build
WORKDIR /app
COPY apps/web/package.json ./package.json
RUN npm install --no-audit --no-fund
COPY apps/web/ ./
RUN npm run build

FROM nginx:1.27-alpine
COPY deploy/nginx/default.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
