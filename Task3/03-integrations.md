# Схема интеграции PropDevelopment и SmartHome

## 1. Архитектурный паттерн

**Выбранный паттерн**: API Gateway + IoT Gateway (BFF + Event-Driven)

Архитектура строится на комбинации двух паттернов:
- Backend for Frontend (BFF) — для пользовательских запросов:
API Gateway обслуживает только мобильное приложение собственника. Он не принимает трафик от партнёра. Это позволяет оптимизировать Gateway под UX (быстрые ответы, агрегация данных) и не нагружать его телеметрией.

- Event-Driven + Adapter — для партнёрского взаимодействия:
IoT Gateway выступает как специализированный адаптер между миром IoT-устройств (асинхронные события, специфичные протоколы, высокий темп поступления данных) и внутренней шиной PropDevelopment. Он изолирует непредсказуемый внешний трафик от критичных внутренних сервисов.

**Причина разделения шин:**

| Критерий | API Gateway | IoT Gateway |
|---|---|---|
| Трафик | Клиентский, низкий темп | Телеметрия, высокий темп |
| Протокол | REST/HTTPS | REST/HTTPS + WebSocket (будущее) |
| Аутентификация | JWT | mTLS + HMAC |
| Rate limiting | По сессиям пользователей | По устройствам и типам событий |
| Критичность | Высокая (бизнес) | Высокая (физическая безопасность) | 
| Обслуживание | Масштабируется под нагрузку клиентов | Масштабируется под количество устройств | 

## 2. Способы взаимодействия

- Синхронный (от клиента к SmartHome Service)
- Асинхронный (от API партнёра, уведомляющего о событиях на устройствах)

## 3. Обработка ошибок и ретраев


| Тип ошибки | Пример | Стратегия | Retry |
| Ошибка клиента (4xx) | Неверный device_id, просроченный JWT | Немедленный возврат ошибки | Нет |
| Ошибка авторизации (403) | RBAC запретил, роль истекла | Немедленный возврат ошибки + аудит | Нет |
| Таймаут партнёра | Нет ответа за 5 секунд | Retry с backoff | Да |
| Ошибка сервера партнёра (5xx) | 502 Bad Gateway, 503 Service Unavailable | Retry с backoff | Да | 
| Сетевая ошибка | Connection refused, DNS resolution failed | Retry с backoff | Да |
| Отказ устройства | Устройство offline | Отказ без retry, уведомление пользователю | Нет |

## 4. Мониторинг и алёртинг

### Ключевые метрики (Prometheus)

| Метрика | Тип | Описание | Порог алерта |
|---|---|---|---|
| iot_commands_total{status} | Counter | Количество команд (success/failed/timeout) | Рост failed > 10% за 5 мин |
| iot_events_received_total{device_id, event_type} | Counter | Входящие события от партнёра | Резкое падение до 0 | 
| iot_gateway_latency_seconds{quantile} | Histogram | Задержка IoT Gateway (p50, p95, p99) | p99 > 2 сек |
| partner_api_latency_seconds{quantile} | Histogram | Время ответа партнёра	p99 > 5 сек | 
| iot_gateway_mtls_errors_total | Counter | Ошибки mTLS-аутентификации | Любое значение > 0 | 
| iot_gateway_hmac_errors_total | Counter | Ошибки HMAC-подписи webhook | Любое значение > 0 | 
| kafka_consumer_lag{partition}	Gauge | Отставание консьюмера от продюсера	> 1000 сообщений | 
| dlq_messages_total | Counter | Сообщения в dead letter queue | Любое значение > 0 | 
| rbac_denied_total{user_id, reason} | Counter | Отказы RBAC | > 10 отказов за 1 мин для одного user_id |
| device_offline_total{device_id} | Counter | Количество событий "устройство offline" | Повторение для одного устройства |


### Ключевые алерты (Alertmanager rules)

#### Критические (немедленное оповещение ИБ-специалисту):

1. PartnerAPIDown
    - Условие: `partner_api_latency_seconds{quantile="0.99"} > 5s ИЛИ iot_commands_total{status="timeout"} > 0`
    -  Длительность: 1 минута
    - Severity: critical
    - Действие: PagerDuty → ИБ-специалист → проверка mTLS/сети/партнёра

2. UnauthorizedWebhookDetected
    - Условие: `iot_gateway_mtls_errors_total > 0 ИЛИ iot_gateway_hmac_errors_total > 0`
    - Длительность: немедленно
    - Severity: critical
    - Действие: блокировка IP источника, проверка на атаку

3. DLQNotEmpty
    - Условие: `dlq_messages_total > 0`
    - Длительность: 5 минут
    - Severity: critical
    - Действие: разбор причин, ручная обработка событий

4. DeviceOfflineRepeated
    - Условие: `device_offline_total{device_id} > 3 за 10 минут`
    - Severity: high
    - Действие: уведомление администратора УК, заявка партнёру

Предупреждающие:

5. HighRBACDenialRate
    - Условие: `rate(rbac_denied_total[5m]) > 10`
    - Severity: warning
    - Действие: проверка на подбор/атаку/некорректный scope ролей

6. KafkaConsumerLag
    - Условие: `kafka_consumer_lag > 1000`
    - Severity: warning
    - Действие: масштабирование консьюмеров или проверка производительности

### Логирование (структурированные логи, JSON)

Каждая запись лога содержит:
- `trace_id`: сквозной идентификатор для отслеживания цепочки вызовов
- `span_id`: идентификатор конкретного шага
- `service`: имя сервиса (iot-gateway, smarthome-integration)
- `level`: INFO, WARN, ERROR
- `message`: описание события
- `context`: метаданные (transaction_id, device_id, user_id)

Пример:
```
{
  "trace_id": "abc-123",
  "span_id": "span-456",
  "service": "iot-gateway",
  "level": "INFO",
  "message": "Command forwarded to partner",
  "context": {
    "transaction_id": "uuid",
    "device_id": "DOM-3-12",
    "partner_endpoint": "https://partner-api.example.com",
    "latency_ms": 230
  }
}
```

## 5. Тестирование и интеграция

### Уровни тестирования

| Уровень | Что тестируется | Ответственный |
|---|---|---|
| Unit | Логика RBAC, валидация JSON, маппинг |	Разработчики SmartHome Service |
| Integration | IoT Gateway ↔ Kafka, SmartHome Service ↔ DB | DevOps + разработчики |
| Contract | API партнёра (Consumer-Driven Contracts) | Разработчики IoT Gateway |
| E2E (Sandbox) | Полный цикл: команда → устройство → событие | QA + ИБ-специалист |
| Performance | Нагрузка: 1000 событий/сек, 100 команд/сек | DevOps |
| Security | Пентест IoT Gateway, фаззинг API | ИБ-специалист | 
| Chaos | Отказ Kafka, партнёра, сети | DevOps |
