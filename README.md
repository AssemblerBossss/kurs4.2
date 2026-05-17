# GNOME Keyring Analyzer

Инструмент для анализа и расшифровки файлов `.keyring` (GNOME Keyring / libsecret).

## Возможности

- Парсинг бинарной структуры файла `.keyring`
- Визуализация всех блоков: заголовок, hashed items, зашифрованный блок
- Расшифровка секретов с помощью мастер-пароля
- Генерация хэша для перебора через **Hashcat** и **John the Ripper**

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
| `--decrypt` | Расшифровать и показать секреты |
| `--password`, `-p` | Мастер-пароль для расшифровки |
| `--john` | Сгенерировать хэш для John the Ripper |

### Примеры

```bash
# Расшифровать секреты
python cli.py login.keyring --decrypt --password "ваш_пароль"

# Сгенерировать хэш для john
python cli.py login.keyring --john

# Сгенерировать хэш для John the Ripper
python cli.py login.keyring --john --save-hash john.txt
john --format=gnome-keyring john.txt --wordlist=rockyou.txt
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
    ├── keyring_hash.py       # Генератор хэшей для Hashcat и John
```

## Где находится файл keyring

На большинстве систем с GNOME:

```bash
~/.local/share/keyrings/login.keyring
```

Файл `login.keyring` шифруется паролем входа в систему (тем же, что вводится при логине).