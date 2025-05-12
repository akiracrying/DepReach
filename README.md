# DepReach: Software Composition Analysis with Reachability

**DepReach** — это инструмент композиционного анализа программного обеспечения (SCA), расширенный механизмом анализа достижимости уязвимых компонентов на основе графов вызовов функций.

## Возможности

- Генерация SBOM в формате CycloneDX
- Поиск известных уязвимостей с использованием базы данных (VDB)
- Оценка достижимости уязвимого кода:
  - Построение графа вызовов функций (call graph)
  - Анализ AST (Abstract Syntax Tree)
- Хранение результатов в базе данных и доступ через GraphQL API
- Возможность интеграции в пайплайны CI/CD

## Установка

```bash
git clone https://github.com/your-org/DepReach.git
cd DepReach
python -m venv .venv
source .venv/bin/activate  # или .venv\Scripts\activate для Windows
pip install -r requirements.txt
```

## Использование

```bash
python depreach.py --input path/to/project --output results.json
```

## Архитектура

- `cdxgen` — генерация SBOM
- `vdb/` — локальная база уязвимостей
- `reachability/` — анализ AST и построение call graph
- `graphql_db/` — FastAPI + Strawberry GraphQL API
- `tests/` — примеры использования и тестовые проекты

## GraphQL

Для работы GraphQl надо запустить сервер в папке `graphql_db`:
```bash
uvicorn server:app --reload --port 5555  
```
И дополнительно в коде `depreach.py` поменять перменную GRAPHQL_USE на _True_

Запрос:
```graphql
query {
  getVulnsByPurl(purl: "pkg:pypi/requests@2.25.1") {
    cve
    description
    severity
    reachability {
      commit
      data {
        isReachable
        changedFuncs
        reachableFuncs
      }
    }
  }
}
```

## Лицензия

MIT License