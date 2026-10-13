# Проверка DepReach на реальных приложениях

Подготовлено 2026-09-19. PowerShell, рабочая папка `C:\Projects\DepReach`.

## Что скачано

Это исторические версии настоящих приложений с неизменёнными исходниками
и требованиями к зависимостям. Они выбраны для воспроизводимого анализа,
а не как рекомендуемые версии для развёртывания.

| Приложение | Назначение | Релиз | Commit |
|---|---|---|---|
| [Whoogle Search](https://github.com/benbusby/whoogle-search/tree/v0.8.2) | Поисковое веб-приложение на Flask | v0.8.2 | `5ae9160d380f7188a281b70b5665e51937e5f467` |
| [Linkding](https://github.com/sissbruecker/linkding/tree/v1.20.0) | Менеджер закладок на Django | v1.20.0 | `f071423f1e29f2781b9dc31c2ce8cfce9b8a5a50` |

Папки: `tests_local\real_apps\whoogle-search` и `tests_local\real_apps\linkding`.
Для статического анализа не нужно запускать приложения или устанавливать их
зависимости. Инвентарь строится по существующим pinned requirements.txt:
36 записей у Whoogle, 38 у Linkding. Это содержимое этих манифестов,
а не подтверждённый состав реального развёрнутого окружения.

## Подготовка инструмента

Устанавливается локальная версия DepReach с текущими исправлениями.
Используется уже имеющийся на этой машине Python 3.10.
Активация venv не требуется. Выполнять блоки в одном окне PowerShell.

```powershell
Set-Location C:\Projects\DepReach
& C:\Python10\python.exe -m venv .venv-eval
if ($LASTEXITCODE -ne 0) { throw 'Не удалось создать venv' }
$py = (Resolve-Path .\.venv-eval\Scripts\python.exe).Path
& $py -m pip install -e '.[dev]' 'appthreat-vulnerability-db==6.6.1'
if ($LASTEXITCODE -ne 0) { throw 'Не удалось установить DepReach' }
& $py -m pytest tests -q
```

DepReach использует API и формат VDB 6. Установка VDB 7 без адаптации
интеграции несовместима; ограничение `<7` добавлено в зависимости проекта.

## Быстрый эксперимент без базы CVE

```powershell
& $py -m scripts.benchmark_real_apps --clone
if ($LASTEXITCODE -ne 0) { throw 'Эксперимент не завершился' }
Start-Process .\reports\real-apps-focused\whoogle-search\report.html
Start-Process .\reports\real-apps-focused\linkding\report.html
```

Скрипт проверяет commit и чистоту checkout, строит SBOM, получает исходники
точных версий из PyPI и реальные исправления из GitHub. Flask 2.2.3 добавляется
как промежуточная зависимость для проверки Werkzeug. Код приложений не исполняется.

Здесь явно выбраны три пары «пакет — CVE». Это проверяет достижимость на реальном
коде, но **не выполняет поиск всех уязвимостей**. Нулевой код завершения скрипта
означает завершение эксперимента, а не отсутствие CVE. Интернет нужен для
получения исходников и патчей. Первые наблюдения:

| Приложение / пакет | CVE | Результат |
|---|---|---|
| Whoogle / Requests 2.28.2 | CVE-2023-32681 | `reachable` |
| Whoogle / Werkzeug 2.2.3 | CVE-2024-49766 | `unknown` |
| Linkding / Requests 2.31.0 | CVE-2024-35195 | `unknown` |

Найденный путь:

```text
app.request.Request.send
 -> requests.api.get
 -> requests.api.request
 -> requests.sessions.Session.request
 -> requests.sessions.Session.send
 -> requests.sessions.SessionRedirectMixin.resolve_redirects
 -> requests.sessions.SessionRedirectMixin.rebuild_proxies
```

У Whoogle/Werkzeug патч однозначно сопоставлен с `werkzeug.security.safe_join`,
но путь не найден при наличии неразрешённых вызовов и поведения Flask.
Есть также лишние коллизии `setup.py` между исходными дистрибутивами.
У Linkding патч сопоставлен с `requests.adapters.HTTPAdapter.send`, но вызов
через выбранный адаптер не разрешён; патч также содержит изменения вне
функций. Эти результаты показывают ограничения модели, а не безопасность
или подтверждённую эксплуатацию приложений. Обе функции и пути доступны
для ручной проверки в JSON/SARIF с расположением исходного кода.

Сводка: `reports\real-apps-focused\summary.json`.

## Что такое база и почему её нужно скачать

Полный запуск работает так:

```text
requirements/SBOM -> версии пакетов -> VDB: соответствующие CVE и ссылки
                 -> исходники и fix-коммиты -> граф вызовов -> отчёт
```

VDB — локальный каталог уязвимостей AppThreat. Это отдельная часть от графа
вызовов и SQLite-кэша результатов DepReach. В прежнем пользовательском каталоге
`C:\Users\akira\AppData\Local\vdb\vdb` при предыдущей проверке был индекс,
но отсутствовал `data.vdb6` с записями CVE. Причина неполной загрузки неизвестна.
Один индекс не позволяет получить полноценные записи и ссылки на исправления.

Ниже база скачивается в отдельный каталог проекта. Старый каталог не удаляется.
Выбрана база application packages без данных дистрибутивов ОС. На дату проверки
её OCI-манифест содержал около 0.27 GiB сжатых данных; после распаковки размер
будет больше. Загрузку полной базы в этой сессии не выполняли.

```powershell
$env:VDB_HOME = Join-Path (Get-Location).Path 'data\vdb-real-apps'
$env:VDB_CACHE = Join-Path (Get-Location).Path 'data\vdb-real-apps-cache'
$env:VDB_DATABASE_URL = 'ghcr.io/appthreat/vdbxz-app:v6.5.x'
$env:VDB_APP_ONLY_DATABASE_URL = $env:VDB_DATABASE_URL
& $py -m vdb.cli --download-image

# Проверяет наличие и непустоту ОБОИХ файлов; одного exit code загрузчика мало.
& $py -c "from scripts.composition_analysis import ensure_vdb_available; ensure_vdb_available(); print('VDB ready')"
if ($LASTEXITCODE -ne 0) { throw 'VDB не готова: проверь вывод загрузчика выше' }
Get-ChildItem -LiteralPath $env:VDB_HOME -File | Select-Object Name,Length
```

Команда загрузки подтверждена [документацией VDB 6.6.1](https://github.com/AppThreat/vulnerability-db/blob/v6.6.1/README.md).
В новом окне PowerShell снова задай `$py` и переменные `VDB_*` из блоков выше.
Полнота результатов зависит от покрытия выбранной базы.

## Полные запуски обычного CLI

Для Whoogle передаём исходники Flask как промежуточную зависимость, чтобы
анализатор мог пройти из приложения через Flask в Werkzeug.

```powershell
$flaskSource = & $py -c "from scripts.source_store import download_purl_source; print(download_purl_source('pkg:pypi/flask@2.2.3', 'data'))"
if ($LASTEXITCODE -ne 0) { throw 'Не удалось получить исходники Flask' }

& $py .\depreach.py -i .\tests_local\real_apps\whoogle-search -o report.json --skip-update --cache -j 2 --dependency-source $flaskSource --sarif .\reports\whoogle-search\report.sarif
$whoogleExit = $LASTEXITCODE
Write-Host "Whoogle exit code: $whoogleExit"
if ($whoogleExit -eq 4) { throw 'Сканирование Whoogle завершилось ошибкой' }

& $py .\depreach.py -i .\tests_local\real_apps\linkding -o report.json --skip-update --cache -j 2 --sarif .\reports\linkding\report.sarif
$linkdingExit = $LASTEXITCODE
Write-Host "Linkding exit code: $linkdingExit"
if ($linkdingExit -eq 4) { throw 'Сканирование Linkding завершилось ошибкой' }

Start-Process .\reports\whoogle-search\report.html
Start-Process .\reports\linkding\report.html
```

Выход CLI: `0` — CVE не найдены в данном инвентаре/базе; `1` — для всех найденных
CVE нет пути в модели; `2` — хотя бы один путь найден; `3` — есть неопределённость
без найденных путей; `4` — ошибка сканирования. Коды 1–3 не являются сбоем команды.
`--skip-update` использует уже загруженную базу; для обновления повтори блок загрузки.

Полные отчёты записываются в `reports\whoogle-search\` и `reports\linkding\`.
Они отделены от эксперимента с тремя заранее выбранными CVE.

Смотри `reachability.status`, `mappings`, `paths`, `reasons` и `diagnostics` в JSON.
Коммит показывает изменённые функции, но может содержать также рефакторинг и
добавленные проверки; статический путь показывает возможные вызовы, но пока
не проверяет значения аргументов, HTTP-точки входа и условия эксплуатации.


## Повторный анализ после улучшений v3

На исходных 65 находках Whoogle (инвентарь и набор CVE сохранены):

| Метрика | Было | Стало |
|---|---:|---:|
| Найденные возможные пути | 3 | 8 |
| Unknown | 62 | 57 |
| Находки с установленными функциями | 23 | 35 |
| No path found без блокирующих пробелов | 0 | 0 |

Новые возможные пути включают Flask session handling и Requests HTTPAdapter.
В отдельной проверке Linkding CVE-2024-35195 также стала reachable. Переходы
через переданные callbacks явно подписаны как возможные; это не доказательство
вызова callback в каждом запуске или эксплуатации CVE.

Исходный `reports\whoogle-search\report.json` сохранён. Новые результаты
обычного CLI: `reports\whoogle-search\report-v3.json`, `report-v3.sarif`
и обновлённый `report.html`. Сравнение замороженного набора находится в
`reports\whoogle-v3-final\comparison.json`.

Теперь раскрытие **Fix diff / function mapping** в HTML показывает файлы,
контекст до изменения, добавленные/удалённые строки и исходники родителя
fix-коммита. **Evidence / limitations** показывает каждую найденную функцию,
метод сопоставления, путь либо причину неопределённости.

В JSON `function_results` и `call_path_status` разделяют два факта:
«путь в модели не найден» и «данных достаточно для отрицательного вывода».
Состояние `not_found` при итоговом `unknown` не является основанием скрыть CVE.
Ошибки неимпортируемых модулей зависимостей больше не мешают отрицательным
выводам, но реальные неразрешённые вызовы Whoogle всё ещё мешают. Модель пока
не доказывает недостижимость большинства функций этого приложения.
