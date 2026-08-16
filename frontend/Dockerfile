# Frontend Dockerfile — Nginx serving static files
FROM node:20-alpine AS builder

WORKDIR /app
COPY frontend/ .

# Install Node.js dependencies if needed
RUN npm install --legacy-peer-deps 2>/dev/null || true

# Final stage — Nginx
FROM nginx:alpine

# Copy nginx config
COPY deployment/nginx/nginx.conf /etc/nginx/nginx.conf
COPY deployment/nginx/default.conf /etc/nginx/conf.d/default.conf

# Copy frontend files
COPY frontend/ /usr/share/nginx/html/

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost:80/ || exit 1

# Expose port
EXPOSE 80 443

# Run nginx
CMD ["nginx", "-g", "daemon off;"]
