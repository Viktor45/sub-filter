# Build stage
FROM golang:alpine AS builder

# Установка зависимостей (для статической сборки с CGO=0)
RUN apk --no-cache add ca-certificates upx binutils

WORKDIR /app

# Копируем исходники
COPY . .

# Собираем статический бинарник (без CGO, с поддержкой часовых поясов)
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags '-w -s -extldflags "-static"' \
    -tags timetzdata \
    -o filter main.go

# Уменьшаем размер бинарника
RUN strip --strip-all /app/filter 
RUN upx /app/filter

# Final stage
FROM chainguard/static:latest

# Копируем бинарник
COPY --from=builder /app/filter /filter

EXPOSE 8000

# Точка входа — позволяет передавать аргументы при запуске
ENTRYPOINT ["/filter"]