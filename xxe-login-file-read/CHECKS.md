# CHECKS — xxe-login-file-read

## Среда проверки
- ОС: Windows
- Docker Desktop 4.81.0 (Docker Compose v5.2.0)

## Команды запуска
docker compose config --quiet   # пройдено без ошибок
docker compose up --build -d
bash solution/solution.sh

## Результаты самопроверки
- Прогонов: 10
- Успешных: 10
- Флаг получен во всех 10 прогонах: flag{xxe_local_file_disclosure_via_entity}
- Обнаруженные ограничения: не выявлено
- Внешние зависимости: не требуются, весь обмен — на localhost:8082