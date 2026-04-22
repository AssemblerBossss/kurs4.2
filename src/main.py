import sys
from keyring_parser import KeyringParser
from keyring_visualizer import KeyringVisualizer


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "login.keyring"

    # 1. Парсинг — извлечение данных
    parser = KeyringParser(filepath=path)
    parser.parse_all()  # Извлекаем все данные сразу

    # 2. Визуализация — только вывод
    visualizer = KeyringVisualizer(parser)
    visualizer.dump_all()


if __name__ == "__main__":
    main()
