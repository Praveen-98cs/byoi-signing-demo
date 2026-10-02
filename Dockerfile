FROM nginxinc/nginx-unprivileged:1.27-alpine
ARG BRANCH=unknown
ARG COMMIT=unknown
LABEL org.opencontainers.image.source="https://github.com/Praveen-98cs/byoi-signing-demo"
USER root
RUN printf '<h1>byoi-signing-demo</h1><p>branch: %s</p><p>commit: %s</p>\n' "$BRANCH" "$COMMIT" > /usr/share/nginx/html/index.html
USER 101
EXPOSE 8080
