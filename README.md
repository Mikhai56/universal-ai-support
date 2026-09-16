# SupportPilot — Telegram + Web

AI-поддержка с базой знаний, историей обращений, безопасной эскалацией и очередью оператора.

## Возможности

- `/start` — начало диалога в Telegram;
- ответы из `knowledge_base.json`;
- автоматическая эскалация платежей, возвратов, privacy, security и юридических вопросов;
- SQLite-история тикетов и сообщений;
- `/operator` — запросить человека;
- `/queue` — очередь эскалаций для администратора;
- `/resolve_ID` — закрыть тикет и уведомить клиента;
- web-интерфейс чата через `/`;
- HTTP API: `/api/chat` и `/api/health`;
- Docker-образ для публичного развёртывания.

## Быстрый публичный запуск

Проект подготовлен для Render через `render.yaml`. В Blueprint уже описаны web-сервис и Telegram worker. Render поддерживает Docker-деплой и HTTP health check для `/api/health`. Для web-сервиса сейчас используется бесплатный compute plan; его файловая система временная, поэтому история web-тестов не рассчитана на долговременное хранение без отдельного persistent storage.

**Deploy to Render:**

https://render.com/deploy?repo=https://github.com/Mikhai56/universal-ai-support

После создания web-сервиса Render выдаст публичный адрес вида `https://supportpilot-web.onrender.com`.

## Telegram

Для Telegram worker задайте секреты в Render:

```text
TELEGRAM_BOT_TOKEN=токен_от_BotFather
ADMIN_CHAT_ID=ваш_chat_id
```

Не добавляйте эти значения в GitHub.

## Локальный запуск

```bash
python3 app.py
```

После запуска откройте `http://localhost:8080`.

Для Telegram:

```bash
python3 bot.py
```

## Безопасность

- Не вставляйте токены и API-ключи в исходный код или переписку.
- Не публикуйте `supportpilot.db`.
- Перед реальным использованием добавьте политику конфиденциальности и срок хранения истории.
- Для production рекомендуется постоянное хранилище и мониторинг.
