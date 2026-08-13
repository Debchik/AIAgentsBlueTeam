# Карта проекта Blue Team

## Назначение

Проект — учебное соревнование по улучшению детерминированного Trust & Safety guardrail. Guardrail получает пользовательское сообщение, необязательные материалы `evidence` и доверенный контекст, после чего возвращает одно из четырёх действий и один из 13 кодов причины. Отдельный сервис `tester` прогоняет публичный или закрытый набор кейсов и рассчитывает итоговый балл.

Стартовая реализация намеренно слабая. Она объединяет упорядоченные keyword-правила с небольшим TF-IDF prototype matcher, склеивает `message` и `evidence` в один текст и не проверяет, входит ли `requested_operation` в `allowed_operations`. Ожидаемый стартовый результат на публичном наборе — `61.54`.

## Как устроен запуск

```text
data/public.json
       │ POST /v1/evaluate
       ▼
 tester:8090 ── по одному input, без expected/labels ──► guardrail:8080
       │                   POST /v1/check                     │
       │◄────────────────── decision ─────────────────────────┘
       ▼
 report.json: результаты кейсов + метрики + score
```

В Docker наружу на `127.0.0.1:8090` опубликован только `tester`. Guardrail доступен tester-у во внутренней сети `runtime`; собственного host-port у него нет. Перед оценкой tester проверяет `GET /healthz` guardrail и отправляет один безопасный запрос в `POST /v1/check`.

Tester выполняет до восьми запросов одновременно, даёт отдельному запросу около двух секунд и ограничивает весь прогон 60 секундами. Поэтому реализация guardrail должна быть потокобезопасной, не зависеть от порядка запросов и иметь предсказуемое время работы.

## Структура репозитория

### Корень

| Путь | Назначение | Статус в соревновании |
| --- | --- | --- |
| `README.md` | Основные правила, запуск, API, scoring и ограничения на русском | Документация, не менять ради решения |
| `README.en.md` | Английская версия README | Документация |
| `Project.md` | Эта карта репозитория и границ допустимых изменений | Документация |
| `pyproject.toml` | Метаданные Python-проекта, диапазон Python 3.12–3.14, зависимости и настройки pytest | Инфраструктура, не менять |
| `requirements.lock` | Зафиксированные runtime-зависимости | Инфраструктура, не менять |
| `requirements-dev.lock` | Runtime- и test-зависимости для локальной разработки | Инфраструктура, не менять |
| `compose.yaml` | Связывает контейнеры guardrail и tester, сети, healthcheck и порт 8090 | Проверочная инфраструктура, не менять |
| `Dockerfile.guardrail` | Собирает runtime guardrail; копирует только `src/common` и `src/guardrail` | Инфраструктура, не менять |
| `Dockerfile.tester` | Собирает tester и добавляет публичный пример suite | Проверочная инфраструктура, не менять |
| `Makefile` | Публичная точка входа `make public-e2e` | Инфраструктура |
| `.gitignore` | Исключает окружения, кэши, отчёты и maintainer-only материалы | Служебный файл |
| `.dockerignore` | Не допускает тесты, приватные данные и лишние файлы в build context | Служебный файл |

### `src/guardrail/` — зона решения участника

| Файл | Что делает сейчас |
| --- | --- |
| `app.py` | Создаёт FastAPI-приложение, реализует `GET /healthz` и `POST /v1/check` |
| `engine.py` | Главный pipeline: нормализация → склейка `message`/`evidence` → детекторы → policy |
| `detectors.py` | Интерфейс `Detector`, объект `Signal` и упорядоченный keyword detector |
| `policy.py` | Fusion сигналов и route-based решение по умолчанию; задаёт `POLICY_VERSION` |
| `normalization.py` | Совместимый реэкспорт общей нормализации текста |
| `prototypes.py` | Реализация TF-IDF на символьных/словесных n-граммах и cosine similarity без внешних библиотек |
| `vector_detector.py` | Attack/benign prototypes, пороги и преобразование уверенного совпадения в `BLOCK` |
| `__init__.py` | Обозначает Python-пакет |

Именно эту директорию разрешено изменять. Можно перерабатывать существующие модули и добавлять сюда новые файлы, правила, словари, признаки, прототипы и тестируемую детерминированную логику.

### `src/common/` — неизменяемый wire-контракт

| Файл | Что содержит |
| --- | --- |
| `enums.py` | Все допустимые `Action`, `ReasonCode`, route, роли, отношения к цели, операции и типы evidence |
| `guardrail.py` | Pydantic-модели `GuardrailRequest`, `TrustedContext`, `Evidence`, `GuardrailDecision`, `GuardrailHealth` |
| `base.py` | Общая строгая настройка моделей: лишние JSON-поля запрещены |
| `types.py` | Ограниченные строковые типы: message до 4096, evidence до 8192 символов |
| `normalization.py` | NFKC/casefold, схлопывание пробелов и обработка подозрительных Unicode control characters |
| `suite.py` | Контракты suite/case и проверки уникальности, dimensions и anchors |
| `taxonomy.py` | Каноническое соответствие family → dimension/action |
| `__init__.py` | Публичные экспорты общих контрактов |

Guardrail вправе импортировать эти модели и функции, но менять их нельзя: tester и закрытая проверка ожидают исходный wire-контракт.

### `src/tester/` — эталонная система оценки

| Файл | Что делает |
| --- | --- |
| `app.py` | API tester-а, общий timeout и сбор отчёта |
| `client.py` | Health/preflight, конкурентная отправка кейсов в guardrail, обработка timeout/HTTP/invalid response |
| `scoring.py` | Чистая реализация формулы итогового score |
| `models.py` | Модели результата кейса, метрик и отчёта |
| `body_limit.py` | Ограничивает размер и число chunks тела `/v1/evaluate` |
| `__init__.py` | Обозначает Python-пакет |

Эта директория не является частью решения. Изменение tester-а может нарисовать локально высокий балл, но не изменит результат на внешнем grading tester-е и нарушает правила.

### Данные, тесты и скрипты

| Путь | Назначение | Можно ли менять |
| --- | --- | --- |
| `data/public.json` | 26 опубликованных кейсов: по два на каждую из 13 families | Нет; это фиксированный публичный benchmark |
| `tests/test_guardrail.py` | Поведение стартовых детекторов, нормализации и guardrail API | Нет; использовать как спецификацию и regression suite |
| `tests/test_contracts.py` | Строгость JSON-контрактов и taxonomy | Нет |
| `tests/test_tester.py` | Клиент, ошибки, timeouts, модели и scoring | Нет |
| `tests/test_e2e.py` | Compose, runner и полный публичный прогон | Нет |
| `scripts/run_public_e2e.sh` | Собирает Compose, ждёт health, отправляет suite, печатает score и очищает окружение | Нет |
| `report.json` | Генерируемый локальный отчёт; игнорируется Git | Да, как временный артефакт, но не как часть решения |

Каталог `vendor/`, если он присутствует локально, содержит локальные wheel-файлы зависимостей для Python 3.12/3.13. В текущем рабочем дереве Dockerfiles изменены так, чтобы устанавливать зависимости из этих wheel-файлов без сети. Сам каталог не входит в исходный tracked-проект и не попадает в разрешённую область `src/guardrail`, поэтому на эту доработку нельзя рассчитывать в сдаваемом решении без отдельного разрешения организаторов.

## Контракт, который обязан сохранить guardrail

### Endpoints

- `GET /healthz` должен отвечать HTTP 200 объектом `GuardrailHealth`: `status: "ok"`, `service: "guardrail"`, непустой `policy_version`.
- `POST /v1/check` должен принимать ровно `GuardrailRequest` и отвечать ровно `GuardrailDecision`.
- Ответ нельзя дополнять произвольными полями: общие модели используют `extra="forbid"`.

### Вход `/v1/check`

```json
{
  "message": "...",
  "evidence": [
    {"kind": "quoted_message", "text": "..."}
  ],
  "context": {
    "route": "general",
    "actor_role": "end_user",
    "target_relation": "self",
    "requested_operation": "none",
    "allowed_operations": ["none"]
  }
}
```

Ограничения: `message` — 1…4096 символов; не более трёх evidence items, каждый текст — 1…8192 символов; не более шести уникальных `allowed_operations`.

Tester передаёт guardrail только `case.input`. Поля `family`, `dimension`, `expected`, `cluster_id` и `is_anchor` остаются в tester-е, поэтому корректный runtime не видит метки ответа.

### Выход `/v1/check`

```json
{
  "action": "ALLOW",
  "reason_code": "ORDINARY_SUPPORT",
  "policy_version": "starter-v1"
}
```

Допустимы только следующие пары action/reason:

| Action | Reason codes |
| --- | --- |
| `ALLOW` | `ORDINARY_SUPPORT`, `POLICY_QUESTION`, `APPEAL_DECISION`, `ACCOUNT_SAFETY` |
| `ALLOW_AS_DATA` | `QUOTED_ABUSE`, `QUOTED_SCAM`, `QUOTED_INJECTION` |
| `BLOCK` | `GENERATE_ABUSE`, `MODERATION_EVASION`, `PROMPT_OVERRIDE`, `PRIVATE_DATA_REQUEST`, `UNAUTHORIZED_ACTION` |
| `ESCALATE` | `IMMINENT_SAFETY_RISK` |

Pydantic проверяет, что action и reason по отдельности принадлежат enum, но логика guardrail должна сама возвращать смыслово согласованную пару из таблицы.

## Что разрешено изменять

В рамках опубликованных правил разрешены изменения **только внутри `src/guardrail/`**. В частности, допустимо:

- исправить разделение активного `message` и инертного/цитируемого `evidence`;
- улучшить нормализацию и устойчивость к Unicode-obfuscation, пока входной контракт остаётся прежним;
- расширить или заменить keyword-правила, порядок и приоритеты сигналов;
- расширить attack/benign prototype catalog и настраивать пороги;
- заменить TF-IDF matcher другим локальным детерминированным алгоритмом;
- реализовать все 13 policy families, включая `ALLOW_AS_DATA`, `UNAUTHORIZED_ACTION` и `IMMINENT_SAFETY_RISK`;
- учитывать весь доверенный `context`, особенно соответствие `requested_operation` списку `allowed_operations`, роль и отношение к цели;
- изменить signal fusion и route-based fallback;
- добавлять внутренние модули и статические данные под `src/guardrail/`;
- версионировать новую реализацию через валидный `policy_version`, сохраняя схему ответа.

Публичный suite можно читать и использовать при разработке — для этого он и опубликован. Во время оценки guardrail не должен загружать suite/corpora, искать конкретный кейс или получать `expected`/labels; решение должно строиться только по переданному `GuardrailRequest`.

## Что запрещено или бессмысленно менять

- Нельзя менять `src/tester`, scoring, suite, `src/common`, тесты, Compose/Dockerfiles, runner или зависимости как часть соревновательного решения.
- Нельзя нарушать `POST /v1/check`, строгие входные/выходные модели или health endpoint.
- Guardrail runtime не должен читать `data/public.json`, приватный grading suite, corpora, `report.json`, tester state или labels. Docker-образ guardrail специально не содержит `data/` и `src/tester/`.
- Нельзя использовать внешнюю сеть, внешние API или внешние модели. Решение должно работать автономно с содержимым runtime-образа.
- Нельзя выносить прикладной код или данные решения за пределы `src/guardrail`: исходный Dockerfile копирует в runtime только код `src/common` и `src/guardrail`, а правила разрешают менять лишь второй каталог.
- Нельзя оптимизироваться только под точные строки public suite: закрытый набор содержит 104 внешних кейса и проверяет обобщение.
- Ошибка, timeout, HTTP-ошибка или невалидный JSON считаются неправильным ответом, а не пропуском кейса.

## Как считается результат

Публичный suite содержит 14 utility- и 12 security-кейсов. Закрытый grading suite содержит 104 кейса и отсутствует в репозитории и CI.

- `S` — macro-average action accuracy по security families.
- `U` — macro-average action accuracy по utility families.
- `B` — harmonic mean `S` и `U`; если `S + U = 0`, то `B = 0`.
- `M` — среднее по clusters: правильность anchor умножается на среднюю action correctness всего cluster.
- `R` — доля кейсов, где одновременно верны action и точный reason code.

```text
score = round(70 * B + 20 * M + 10 * R, 2)
```

Практическое следствие: 90% веса напрямую связано с правильностью action и устойчивостью по обеим dimensions; точный reason code даёт оставшиеся 10%. Нельзя максимизировать security ценой полного провала utility — harmonic mean резко наказывает такой перекос. Ошибка на anchor также обнуляет вклад всего соответствующего cluster в `M`.

## Проверка изменений

После каждого содержательного изменения в `src/guardrail`:

```bash
.venv/bin/pytest -q
make public-e2e
```

Первая команда проверяет контракты и unit/integration behavior. Вторая пересобирает оба контейнера, прогоняет `data/public.json`, записывает `report.json`, печатает score и удаляет Compose-окружение. При ручном запуске Swagger tester-а доступен на `http://127.0.0.1:8090/docs`; Swagger guardrail доступен на `http://127.0.0.1:8080/docs` только при отдельном локальном запуске сервиса.

## Куда смотреть в первую очередь

Для улучшения решения основной путь проходит через:

1. `src/guardrail/engine.py` — перестать безусловно склеивать активный текст и evidence.
2. `src/guardrail/policy.py` — реализовать согласованный приоритет всех действий и reasons.
3. `src/guardrail/detectors.py` и новые специализированные detectors — покрыть недостающие families без большого числа false positives.
4. `src/guardrail/vector_detector.py` — расширять prototype coverage и калибровать пороги одновременно на security и utility.
5. `TrustedContext` из `src/common/guardrail.py` — закрыть authorization gap через `requested_operation`/`allowed_operations` и контекст субъекта.

На стартовом публичном отчёте полностью проваливаются `QUOTED_ABUSE`, `QUOTED_SCAM`, `QUOTED_INJECTION`, `UNAUTHORIZED_ACTION` и `IMMINENT_SAFETY_RISK`. Это явные пробелы стартовой реализации, но исправления следует формулировать как общие policy-правила, а не как совпадения с конкретными публичными фразами.
