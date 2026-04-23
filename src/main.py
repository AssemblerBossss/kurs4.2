#!/usr/bin/env python3
"""
main.py — Точка входа для визуализатора GNOME Keyring

Использует KeyringParser для парсинга файла и KeyringVisualizer для вывода.
"""

import sys
from src.keyring_parser import KeyringParser
from src.keyring_visualizer import KeyringVisualizer


def main():
    # if len(sys.argv) != 2:
    #     print(f"Использование: {sys.argv[0]} <файл.keyring>")
    #     sys.exit(1)

    # filepath = sys.argv[1]
    filepath = "login.keyring"

    try:
        # Парсинг файла
        parser = KeyringParser(filepath)
        keyring = parser.parse_all()

        # Визуализация
        visualizer = KeyringVisualizer(keyring)
        visualizer.dump_all()

    except FileNotFoundError:
        print(f"[!] Файл не найден: {filepath}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"[!] Ошибка парсинга: {e}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"[!] Непредвиденная ошибка: {e}", file=sys.stderr)
        sys.exit(3)


if __name__ == "__main__":
    main()
