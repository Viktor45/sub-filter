# Build stage
FROM golang:alpine AS builder

# Установка зависимостей (для статической сборки с CGO=0)
RUN apk --no-cache add ca-certificates

WORKDIR /app

# Копируем исходники
COPY . .

# Собираем статический бинарник (без CGO, с поддержкой часовых поясов)
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags '-w -s -extldflags "-static"' \
    -tags timetzdata \
    -o filter .

# Final stage
FROM scratch

# Копируем бинарник
COPY --from=builder /app/filter /filter

# Точка входа — позволяет передавать аргументы при запуске
ENTRYPOINT ["/filter"]