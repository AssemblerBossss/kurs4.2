import argparse
import sys
from src.keyring_parser import KeyringParser
from src.keyring_crypto import decrypt_keyring
from src.keyring_hash import KeyringHashGenerator
import getpass


def cli() -> None:
    parser = argparse.ArgumentParser(
        description="Анализатор GNOME Keyring",
        usage="%(prog)s [options] <файл.keyring>",
    )

    parser.add_argument("file", help="Путь к .keyring файлу")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--decrypt", action="store_true", help="Расшифровать и показать секреты"
    )
    group.add_argument(
        "--john",
        action="store_true",
        help="Сгенерировать строку для John the Ripper",
    )

    parser.add_argument("--password", "-p", help="Мастер-пароль для расшифровки")

    args = parser.parse_args()

    if args.password == "-":
        args.password = getpass.getpass("Master password: ")

    try:
        keyring = KeyringParser(args.file).parse_all()
    except Exception as e:
        print(f"Ошибка парсинга: {e}", file=sys.stderr)
        sys.exit(1)

    if args.john:
        generator = KeyringHashGenerator(keyring)
        print(generator.generate_john_hash())

    if args.decrypt:
        if not args.password:
            print("Для расшифровки укажите --password", file=sys.stderr)
            sys.exit(1)
        success = decrypt_keyring(keyring, args.password)
        if not success:
            print(
                "Расшифровка не удалась (неверный пароль или повреждён файл)",
                file=sys.stderr,
            )
            sys.exit(1)
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


if __name__ == "__main__":
    cli()
