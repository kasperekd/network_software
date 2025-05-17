FROM alpine:latest

# Устанавливаем busybox (хотя он обычно уже есть и содержит udhcpc, ping)
# и ca-certificates для HTTPS (если вдруг понадобится curl/wget для тестов)
# procps для `ps` или `top` если нужно будет отлаживать внутри контейнера
RUN apk add --no-cache busybox ca-certificates procps

# Копируем наш entrypoint скрипт
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Рабочая директория (не обязательно, но хорошая практика)
WORKDIR /app

# Команда, которая будет выполняться при запуске контейнера
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
# CMD можно использовать для передачи аргументов в ENTRYPOINT, если entrypoint.sh их ожидает.
# В данном случае не нужно.