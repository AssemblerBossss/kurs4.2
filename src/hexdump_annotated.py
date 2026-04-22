"""
hexdump_annotated.py — Аннотированный hex-дамп файла .keyring
══════════════════════════════════════════════════════════════
Задача 3.2: Разбор бинарного формата файла .keyring
            Визуализация каждого поля с пояснением его назначения.

Вывод: offset | hex bytes | ASCII | [ПОЛЕ: значение]
"""

import struct
import sys
from datetime import datetime

from src.binary_reader import BinaryReader

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
WHITE = "\033[37m"

# Цвета для разных полей
COLOR_MAGIC = GREEN
COLOR_HEADER = CYAN
COLOR_META = YELLOW
COLOR_KDF = MAGENTA
COLOR_HASH = BLUE
COLOR_CRYPTO = RED

# Константы для типов алгоритмов
CRYPTO_NAMES = {
    0: "AES-128-CBC",
    1: "NONE (незашифрован)",
}

HASH_NAMES = {
    0: "SHA-256 (итерационный KDF)",
    1: "NONE",
}


class KeyringDumper:
    """Класс для аннотированного дампа GNOME Keyring файла."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        with open(filepath, "rb") as f:
            self.data = f.read()
        self.reader = BinaryReader(self.data)

    def dump(self) -> None:
        """Главный метод, запускающий весь дамп."""
        self._print_main_header()
        self._dump_magic()
        self._dump_version_and_flags()
        self._dump_metadata()
        # self._dump_kdf_params()
        # self._dump_hashed_items()
        # self._dump_encrypted_block()
        # self._print_footer()
        # self._print_field_map()

    @staticmethod
    def _colored(text: str, color: str) -> str:
        """Оборачивает текст ANSI-кодом цвета для цветного вывода в терминале."""
        return f"{color}{text}{RESET}"

    def _hex_row(
        self, offset: int, chunk: bytes, annotation: str = "", color: str = ""
    ) -> str:
        """
        Формирует одну строку аннотированного hex-дампа.

        Создаёт форматированную строку для вывода в терминал, содержащую:
        - смещение (offset) в шестнадцатеричном виде
        - шестнадцатеричное представление байт (по 2 символа с пробелами)
        - ASCII-представление (печатные символы, остальное — точки)
        - опциональную аннотацию со стрелкой

        Args:
            offset: Смещение в файле (байт от начала)
            chunk: Байты для отображения (обычно 16 байт)
            annotation: Пояснительный текст (например, "[MAGIC]", "[VERSION]")
            color: ANSI-код цвета для раскраски (GREEN, RED, CYAN и т.д.)

        Returns:
            Отформатированную строку для вывода в термина
        """
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        hex_col = f"{hex_part:<47}"
        asc_col = f"|{asc_part:<16}|"
        off_col = f"{offset:04x}"

        if color:
            hex_col = self._colored(hex_col, color)
            asc_col = self._colored(asc_col, color)

        ann = (
            f"  {self._colored('◄ ' + annotation, BOLD + color)}" if annotation else ""
        )
        return f"  {off_col}  {hex_col}  {asc_col}{ann}"

    def _dump_field(
        self,
        start: int,
        end: int,
        name: str,
        value_str: str = "",
        color: str = WHITE,
    ) -> None:
        """
        Выводит hex-дамп бинарного поля с аннотацией на первой строке.

        Функция разбивает поле на строки по 16 байт и выводит их в формате,
        совместимом с hex_row(). Аннотация (имя и значение поля) отображается
        только на первой строке, остальные строки выводятся без пояснений.

        Args:
            start: Начальный индекс поля (включительно)
            end: Конечный индекс поля (исключительно)
            name: Название поля (например, "MAGIC", "VERSION", "SALT")
            value_str: Значение поля в читаемом виде (например, "3", "GNOMEKEY")
            color: ANSI-код цвета для вывода (по умолчанию WHITE)
        """
        chunk_data = self.data[start:end]
        CHUNK = 16
        first = True
        for i in range(0, len(chunk_data), CHUNK):
            chunk = chunk_data[i : i + CHUNK]
            ann = f"{name}: {value_str}" if first else ""
            print(self._hex_row(start + i, chunk, ann, color))
            first = False

    def _print_main_header(self) -> None:
        """Выводит главный заголовок дампа."""
        print()
        print(self._colored("═" * 90, BOLD))
        print(
            self._colored(
                f"  АННОТИРОВАННЫЙ HEX-ДАМП: {self.filepath}  ({len(self.data)} байт)",
                BOLD,
            )
        )
        print(self._colored("═" * 90, BOLD))
        print()
        print(
            f"  {'OFFSET':<6}  {'HEX (16 байт на строку)':<47}  {'ASCII':<18}  АННОТАЦИЯ"
        )
        print("  " + "─" * 86)

    def _print_block_header(self, block_name: str, color: str) -> None:
        """Выводит заголовок блока."""
        print()
        print(self._colored(f"  ┌─ {block_name}", BOLD + color))

    def _dump_magic(self) -> None:
        """Блок 1: Сигнатура файла (16 байт)."""
        self._print_block_header(block_name="БЛОК 1: СИГНАТУРА ФАЙЛА", color=GREEN)

        magic_start = self.reader.tell()
        magic = self.reader.read_bytes(16)

        # Отображаем сигнатуру в виде escape-последовательностей
        magic_repr = repr(magic)[2:-1]  # strip b' and '
        self._dump_field(
            magic_start, magic_start + 16, "MAGIC", magic_repr, COLOR_MAGIC
        )
        print("  " + "─" * 86)

    def _dump_version_and_flags(self) -> None:
        """Блок 2: Флаги алгоритмов (4 байта: major, minor, crypto, hash)."""
        self._print_block_header("БЛОК 2: ФЛАГИ АЛГОРИТМОВ", CYAN)

        # Дамп VERSION_MAJOR и VERSION_MINOR
        for label in ["VERSION_MAJOR", "VERSION_MINOR"]:
            off = self.reader.tell()
            b = self.reader.read_bytes(1)
            self._dump_field(off, off + 1, label, str(b[0]), COLOR_HEADER)

        # Дамп CRYPTO_TYPE
        off = self.reader.tell()
        b = self.reader.read_bytes(1)
        crypto_val = b[0]
        crypto_name = CRYPTO_NAMES.get(crypto_val, f"UNKNOWN (0x{crypto_val:02x})")
        self._dump_field(
            off, off + 1, "CRYPTO_TYPE", f"{crypto_val} = {crypto_name}", COLOR_HEADER
        )

        # Дамп HASH_TYPE
        off = self.reader.tell()
        b = self.reader.read_bytes(1)
        hash_val = b[0]
        hash_name = HASH_NAMES.get(hash_val, f"UNKNOWN (0x{hash_val:02x})")
        self._dump_field(
            off, off + 1, "HASH_TYPE", f"{hash_val} = {hash_name}", COLOR_HEADER
        )

    def _dump_metadata(self) -> None:

        self._print_block_header(
            block_name="БЛОК 3: МЕТАДАННЫЕ ХРАНИЛИЩА", color=BOLD + YELLOW
        )

        name_len = self.reader.read_u32()  # используем reader!
        name_len_start = self.reader.tell() - 4

        self._dump_field(
            start=name_len_start,
            end=name_len_start + 4,
            name="NAME_LENGTH",
            value_str=str(name_len),
            color=COLOR_META,
        )

        name_bytes = self.reader.read_bytes(name_len)
        name_start = self.reader.tell() - name_len

        self._dump_field(
            start=name_start,
            end=name_start + name_len,
            name="NAME",
            value_str=name_bytes.decode("utf-8", errors="replace"),
            color=COLOR_META,
        )

        # ── ctime (8 байт) ───────────────────────────────────────────────────
        ctime_start = self.reader.tell()
        ctime = self.reader.read_time()

        try:
            ts_str = datetime.fromtimestamp(ctime).strftime("%Y-%m-%d %H:%M:%S")
        except (OSError, ValueError):
            ts_str = f"некорректное значение: {ctime}"

        self._dump_field(
            start=ctime_start,
            end=ctime_start + 8,
            name="CTIME (time_t: 2×uint32)",
            value_str=ts_str,
            color=COLOR_META,
        )

        # ── mtime (8 байт) ───────────────────────────────────────────────────
        mtime_start = self.reader.tell()
        mtime = self.reader.read_time()

        try:
            ts_str = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
        except (OSError, ValueError):
            ts_str = f"некорректное значение: {mtime}"

        self._dump_field(
            start=mtime_start,
            end=mtime_start + 8,
            name="MTIME (time_t: 2×uint32)",
            value_str=ts_str,
            color=COLOR_META,
        )

        # ── flags (4 байта) ──────────────────────────────────────────────────
        flags_start = self.reader.tell()
        flags = self.reader.read_u32()

        self._dump_field(
            start=flags_start,
            end=flags_start + 4,
            name="FLAGS",
            value_str=f"0x{flags:08x}",
            color=COLOR_META,
        )

        # ── lock_timeout (4 байта) ───────────────────────────────────────────
        timeout_start = self.reader.tell()
        timeout = self.reader.read_u32()

        self._dump_field(
            start=timeout_start,
            end=timeout_start + 4,
            name="LOCK_TIMEOUT (сек)",
            value_str=str(timeout),
            color=COLOR_META,
        )


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "login.keyring"
    dumper = KeyringDumper(filepath=path)
    dumper.dump()
