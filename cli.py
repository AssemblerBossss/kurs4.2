import argparse
import sys
import json
from src.keyring_parser import KeyringParser
from src.keyring_visualizer import KeyringVisualizer
from src.keyring_crypto import decrypt_keyring
from src.keyring_hash import KeyringHashGenerator


def cli() -> None:
    parser = argparse.ArgumentParser(
        description="Анализатор GNOME Keyring",
        usage="%(prog)s [options] <файл.keyring>",
    )

    parser.add_argument("file", help="Путь к .keyring файлу")

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--header", action="store_true", help="Показать только заголовок (блоки 1-4)"
    )
    group.add_argument(
        "--hashed", action="store_true", help="Показать только hashed items (блок 5)"
    )
    group.add_argument(
        "--encrypted",
        action="store_true",
        help="Показать только зашифрованный блок (блок 6)",
    )
    group.add_argument(
        "--decrypt", action="store_true", help="Расшифровать и показать секреты"
    )
    group.add_argument(
        "--hashcat",
        action="store_true",
        help="Сгенерировать строку для hashcat (режим 23800)",
    )
    group.add_argument(
        "--john",
        action="store_true",
        help="Сгенерировать строку для John the Ripper",
    )

    # Параметры для расшифровки
    parser.add_argument("--password", "-p", help="Мастер-пароль для расшифровки")
    parser.add_argument(
        "--json", action="store_true", help="Вывод в формате JSON (только с --decrypt)"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Подробный вывод отладки"
    )

    # Параметры для сохранения хэша
    parser.add_argument("--save-hash", metavar="FILE", help="Сохранить хэш в файл")

    args = parser.parse_args()

    # Парсинг файла
    try:
        parser_obj = KeyringParser(args.file)
        keyring = parser_obj.parse_all()
    except Exception as e:
        print(f"Ошибка парсинга: {e}", file=sys.stderr)
        sys.exit(1)

    if args.hashcat:
        try:
            generator = KeyringHashGenerator(keyring)
            hash_str = generator.generate_hash("hashcat")
            print(hash_str)

            # Сохраняем в файл если нужно
            if args.save_hash:
                with open(args.save_hash, "w") as f:
                    f.write(f"{hash_str}\n")
                print(f"Хэш сохранён в: {args.save_hash}", file=sys.stderr)

            # Полезная информация
            print(f"\nИнформация для HashCat:", file=sys.stderr)
            print(f"    Режим: 23800 (GNOME Keyring)", file=sys.stderr)
            print(f"    Итераций: {keyring.header.kdf_iterations}", file=sys.stderr)
            print(
                f"    Длина соли: {len(keyring.header.kdf_salt)} байт", file=sys.stderr
            )
            print(
                f"    Размер зашифрованных данных: {len(keyring.encrypted_blob)} байт",
                file=sys.stderr,
            )
            print(f"\n    Пример запуска HashCat:", file=sys.stderr)
            print(
                f"    hashcat -m 23800 -a 0 {args.save_hash or 'hash.txt'} /usr/share/wordlists/rockyou.txt",
                file=sys.stderr,
            )

        except ValueError as e:
            print(f"Ошибка: {e}", file=sys.stderr)
            sys.exit(1)
        return

    if args.john:
        try:
            generator = KeyringHashGenerator(keyring)
            hash_str = generator.generate_hash("john")
            print(hash_str)

            # Сохраняем в файл если нужно
            if args.save_hash:
                with open(args.save_hash, "w") as f:
                    f.write(f"{hash_str}\n")
                print(f"Хэш сохранён в: {args.save_hash}", file=sys.stderr)

            # Полезная информация
            print(f"\nИнформация для John the Ripper:", file=sys.stderr)
            print(f"    Формат: gnome-keyring", file=sys.stderr)
            print(f"    Итераций: {keyring.header.kdf_iterations}", file=sys.stderr)
            print(f"\n    Пример запуска John:", file=sys.stderr)
            print(
                f"    john --format=gnome-keyring {args.save_hash or 'john.txt'} --wordlist=rockyou.txt",
                file=sys.stderr,
            )

        except ValueError as e:
            print(f"Ошибка: {e}", file=sys.stderr)
            sys.exit(1)
        return

    # Режим расшифровки
    if args.decrypt:
        if not args.password:
            print("Для расшифровки укажите --password", file=sys.stderr)
            sys.exit(1)
        success = decrypt_keyring(keyring, args.password, verbose=args.verbose)
        if not success:
            print(
                "Расшифровка не удалась (неверный пароль или повреждён файл)",
                file=sys.stderr,
            )
            sys.exit(1)

        if args.json:
            output = []
            for item in keyring.decrypted_items:
                output.append(
                    {
                        "item_id": item.item_id,
                        "display_name": item.display_name,
                        "secret": item.secret,
                        "ctime": item.ctime_str,
                        "mtime": item.mtime_str,
                        "attributes": [
                            {"name": a.name, "type": a.type_name, "value": a.value}
                            for a in item.attributes
                        ],
                    }
                )
            print(json.dumps(output, ensure_ascii=False, indent=2))
        else:
            print(f"\nРасшифровка успешна (пароль: {args.password})\n")
            for item in keyring.decrypted_items:
                print(f"Запись #{item.item_id}: {item.display_name!r}")
                print(f"  Секрет: {item.secret!r}")
                print(f"  Создана: {item.ctime_str}")
                print(f"  Изменена: {item.mtime_str}")
                if item.attributes:
                    print("  Атрибуты:")
                    for a in item.attributes:
                        print(f"    {a.name!r} = {a.value!r}")
                print()
        return

    # Режим визуализации (полный или частичный)
    vis = KeyringVisualizer(keyring)

    if args.header:
        vis.dump_magic()
        vis.dump_version_and_flags()
        vis.dump_metadata()
        vis.dump_kdf_params()
    elif args.hashed:
        vis.dump_hashed_items()
    elif args.encrypted:
        vis.dump_encrypted_block()
    else:
        vis.dump_all()


if __name__ == "__main__":
    cli()
