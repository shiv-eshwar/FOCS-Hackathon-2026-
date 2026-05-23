FROM nginx:1.25-alpine
LABEL maintainer="VaultShield Security Team"
LABEL version="2.0.0"
LABEL security-scan="passed"
COPY app/ /usr/share/nginx/html/
EXPOSE 80
