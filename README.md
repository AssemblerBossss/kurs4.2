# GNOME Keyring Analyzer

Инструмент для анализа и расшифровки файлов `.keyring`

## Возможности

- Парсинг бинарной структуры файла `.keyring`
- Визуализация всех блоков: заголовок, hashed items, зашифрованный блок
- Расшифровка секретов с помощью мастер-пароля
- Вывод в человеко-читаемом формате и JSON

## Установка

```bash
git clone https://github.com/AssemblerBossss/keyring-analyzer
cd keyring-analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Использование

```bash
python cli.py <файл.keyring> [опции]
```

### Опции

| Опция | Описание |
|---|---|
| `--header` | Показать только заголовок (блоки 1–4) |
| `--hashed` | Показать только hashed items (блок 5) |
| `--encrypted` | Показать зашифрованный блок (блок 6) |
| `--decrypt` | Расшифровать и показать секреты |
| `--password`, `-p` | Мастер-пароль для расшифровки |
| `--json` | Вывод в формате JSON (только с `--decrypt`) |
| `--verbose`, `-v` | Подробный отладочный вывод |

### Примеры

```bash
# Полный дамп структуры файла
python cli.py login.keyring

# Только заголовок
python cli.py login.keyring --header

# Расшифровать секреты
python cli.py login.keyring --decrypt --password "ваш_пароль"

# Расшифровать и вывести JSON
python cli.py login.keyring --decrypt --password "ваш_пароль" --json

# Отладочный вывод при расшифровке
python cli.py login.keyring --decrypt --password "ваш_пароль" --verbose
```

## Структура проекта

```
.
├── cli.py                    # Точка входа, CLI
└── src/
    ├── binary_reader.py      # Парсер бинарного потока (big-endian)
    ├── keyring_models.py     # Модели данных (dataclasses)
    ├── keyring_parser.py     # Парсер структуры .keyring файла
    ├── keyring_crypto.py     # Криптография: KDF, AES, MD5-верификация
    └── keyring_visualizer.py # Визуализация структуры файла
```


## Где находится файл keyring

На большинстве систем с GNOME:

```bash
~/.local/share/keyrings/login.keyring
```

Файл `login.keyring` шифруется паролем входа в систему (тем же, что вводится при логине).

