# Неймспейсы

| Неймспейс | Назначение | Размещаемые компоненты	|
|---|---|---|
| dmz-ingress | Внешний периметр, точки входа из интернета| API Gateway, IoT Gateway |
| smarthome | Бизнес-логика интеграции "Умный дом" | SmartHome Service
| tenant-core | Критичные общедоменные сервисы PropDevelopment	tenant-core-app |
| monitoring | Инфраструктура наблюдаемости	| Prometheus, Alertmanager, Grafana, SIEM-коннекторы | 


# Роли в кластере Kubernetes

| Роль | Namespace | Права роли | Группы пользователей |
| --- | --- | --- | --- |
| cluster-admin | - | Полные права на все ресурсы кластера | ИБ-специалист |
| cluster-viewer | - | Read-only доступ к неконфиденциальным ресурсам кластера (get, list, watch на pods, services, deployments, configmaps). Запрещён доступ к secrets | Менеджеры, владельцы продуктов |
| devops | в каждом | Полные права на все ресурсы неймспейса | devops-инженеры домена |
| developer | Права на get, list, watch все pods, configMaps, deployments | Разработчики домена |
