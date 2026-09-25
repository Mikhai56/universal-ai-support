# SupportPilot — AI Customer Support

Полноценная web-панель поддержки: AI-чат, обращения, клиенты, лиды, база знаний, роли операторов и аудит изменений.

## Что уже есть

- AI-чат с базой знаний и OpenAI-compatible API;
- безопасная эскалация чувствительных обращений;
- тикеты с приоритетами, статусами, исполнителями и историей изменений;
- CRM клиентов и связь клиентов с лидами;
- lead pipeline с аудитом действий операторов;
- роли admin, operator и viewer;
- HttpOnly-сессии, rate limiting и security headers;
- PostgreSQL через DATABASE_URL с SQLite fallback для локального запуска;
- Docker-образ и health endpoint /api/health.

## Production

Один web-процесс запускается так:

    python3 app.py

или через Docker:

    docker build -t supportpilot .
    docker run --rm -p 8080:8080 \
      -e ADMIN_EMAIL=admin@example.com \
      -e ADMIN_PASSWORD='CHANGE_ME' \
      -e AI_API_KEY='YOUR_AI_KEY' \
      -e SECURE_COOKIES=1 \
      supportpilot

Для production рекомендуется HTTPS, SECURE_COOKIES=1 и PostgreSQL через DATABASE_URL. Секреты должны храниться только в настройках хостинга, а не в GitHub.

## Health check

    GET /api/health

Ожидаемый ответ содержит "ok": true.

## Vercel / хостинг

Текущая серверная часть — Python HTTP-сервис, а не стандартная Next.js/Vercel Function. Поэтому не добавляем формальный vercel.json, который создаст deployment, но не обеспечит рабочий runtime.

Docker-конфигурация переносима между Docker-хостингами. Старый render.yaml сохранён только для совместимости с прежним deployment-сценарием и больше не является архитектурной частью приложения.

## Локальный запуск

    python3 app.py

Откройте http://localhost:8080.

Для Telegram worker:

    python3 bot.py

## Безопасность

- API-ключи и токены не должны попадать в исходный код.
- Пароли операторов хранятся как PBKDF2-HMAC-SHA256 hashes.
- Браузерная сессия использует HttpOnly cookie.
- Для production включайте SECURE_COOKIES=1.
- Данные карт и CVV маскируются до сохранения в тикет.
