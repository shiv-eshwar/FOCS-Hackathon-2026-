FROM nginx:1.14

LABEL maintainer="VaultShield Security Team"
LABEL version="1.0.0"
LABEL security-scan="unknown"

COPY app/ /usr/share/nginx/html/

EXPOSE 80
