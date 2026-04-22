# keyring_visualizer.py — Отвечает только за вывод и аннотации
from typing import Dict, Any, Tuple, Optional
from datetime import datetime

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
WHITE = "\033[37m"

COLOR_MAGIC = GREEN
COLOR_HEADER = CYAN
COLOR_META = YELLOW
COLOR_KDF = MAGENTA
COLOR_HASH = BLUE
COLOR_CRYPTO = RED

CRYPTO_NAMES = {
    0: "AES-128-CBC",
    1: "NONE (незашифрован)",
}

HASH_NAMES = {
    0: "SHA-256 (итерационный KDF)",
    1: "NONE",
}


class KeyringVisualizer:
    """Визуализатор .keyring — выводит аннотированный hex-дамп."""

    def __init__(self, parser):
        """
        Args:
            parser: Экземпляр KeyringParser с уже извлечёнными данными
        """
        self.parser = parser
        self.data = parser.data

    @staticmethod
    def _colored(text: str, color: str) -> str:
        return f"{color}{text}{RESET}"

    def _hex_row(
        self, offset: int, chunk: bytes, annotation: str = "", color: str = ""
    ) -> str:
        """Формирует одну строку hex-дампа."""
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
        self, start: int, end: int, name: str, value_str: str = "", color: str = WHITE
    ) -> None:
        """Выводит hex-дамп бинарного поля с аннотацией."""
        chunk_data = self.data[start:end]
        CHUNK = 16
        first = True
        for i in range(0, len(chunk_data), CHUNK):
            chunk = chunk_data[i : i + CHUNK]
            ann = f"{name}: {value_str}" if first else ""
            print(self._hex_row(start + i, chunk, ann, color))
            first = False

    def _print_main_header(self) -> None:
        """Выводит главный заголовок."""
        print()
        print(self._colored("═" * 90, BOLD))
        print(
            self._colored(
                f"  АННОТИРОВАННЫЙ HEX-ДАМП: {self.parser.filepath}  ({len(self.data)} байт)",
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

    def dump_magic(self) -> None:
        """Визуализирует блок сигнатуры."""
        self._print_block_header("БЛОК 1: СИГНАТУРА ФАЙЛА", color=GREEN)

        # Данные уже извлечены парсером
        magic = self.parser.magic
        magic_start = 0  # Сигнатура всегда в начале

        magic_repr = repr(magic)[2:-1]
        self._dump_field(
            magic_start, magic_start + 16, "MAGIC", magic_repr, COLOR_MAGIC
        )
        print("  " + "─" * 86)

    def dump_version_and_flags(self) -> None:
        """Визуализирует блок флагов алгоритмов."""
        self._print_block_header("БЛОК 2: ФЛАГИ АЛГОРИТМОВ", CYAN)

        # Используем извлечённые данные
        offsets = self._get_version_offsets()

        # VERSION_MAJOR
        self._dump_field(
            offsets["major_start"],
            offsets["major_start"] + 1,
            "VERSION_MAJOR",
            str(self.parser.version_major),
            COLOR_HEADER,
        )

        # VERSION_MINOR
        self._dump_field(
            offsets["minor_start"],
            offsets["minor_start"] + 1,
            "VERSION_MINOR",
            str(self.parser.version_minor),
            COLOR_HEADER,
        )

        # CRYPTO_TYPE
        crypto_name = CRYPTO_NAMES.get(
            self.parser.crypto_type, f"UNKNOWN (0x{self.parser.crypto_type:02x})"
        )
        self._dump_field(
            offsets["crypto_start"],
            offsets["crypto_start"] + 1,
            "CRYPTO_TYPE",
            f"{self.parser.crypto_type} = {crypto_name}",
            COLOR_HEADER,
        )

        # HASH_TYPE
        hash_name = HASH_NAMES.get(
            self.parser.hash_type, f"UNKNOWN (0x{self.parser.hash_type:02x})"
        )
        self._dump_field(
            offsets["hash_start"],
            offsets["hash_start"] + 1,
            "HASH_TYPE",
            f"{self.parser.hash_type} = {hash_name}",
            COLOR_HEADER,
        )

    def _get_version_offsets(self) -> Dict[str, int]:
        """Вычисляет смещения для полей версии (16 байт сигнатуры)."""
        base = 16  # После сигнатуры
        return {
            "major_start": base,
            "minor_start": base + 1,
            "crypto_start": base + 2,
            "hash_start": base + 3,
        }

    def dump_metadata(self) -> None:
        """Визуализирует блок метаданных."""
        self._print_block_header("БЛОК 3: МЕТАДАННЫЕ ХРАНИЛИЩА", BOLD + YELLOW)

        offsets = self._get_metadata_offsets()

        # NAME_LENGTH
        name_len = len(self.parser.name.encode("utf-8"))
        self._dump_field(
            offsets["name_len_start"],
            offsets["name_len_start"] + 4,
            "NAME_LENGTH",
            str(name_len),
            COLOR_META,
        )

        # NAME
        self._dump_field(
            offsets["name_start"],
            offsets["name_start"] + name_len,
            "NAME",
            self.parser.name,
            COLOR_META,
        )

        # CTIME
        ctime_str = datetime.fromtimestamp(self.parser.ctime).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        self._dump_field(
            offsets["ctime_start"],
            offsets["ctime_start"] + 8,
            "CTIME (time_t: 2×uint32)",
            ctime_str,
            COLOR_META,
        )

        # MTIME
        mtime_str = datetime.fromtimestamp(self.parser.mtime).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        self._dump_field(
            offsets["mtime_start"],
            offsets["mtime_start"] + 8,
            "MTIME (time_t: 2×uint32)",
            mtime_str,
            COLOR_META,
        )

        # FLAGS
        self._dump_field(
            offsets["flags_start"],
            offsets["flags_start"] + 4,
            "FLAGS",
            f"0x{self.parser.flags:08x}",
            COLOR_META,
        )

        # LOCK_TIMEOUT
        self._dump_field(
            offsets["timeout_start"],
            offsets["timeout_start"] + 4,
            "LOCK_TIMEOUT (сек)",
            str(self.parser.lock_timeout),
            COLOR_META,
        )

    def _get_metadata_offsets(self) -> Dict[str, int]:
        """Вычисляет смещения для полей метаданных."""
        # После сигнатуры (16) + версии (4) = 20 байт
        base = 20
        name_len = len(self.parser.name.encode("utf-8"))

        return {
            "name_len_start": base,
            "name_start": base + 4,
            "ctime_start": base + 4 + name_len,
            "mtime_start": base + 4 + name_len + 8,
            "flags_start": base + 4 + name_len + 16,
            "timeout_start": base + 4 + name_len + 20,
        }

    def dump_all(self) -> None:
        """Выводит полный аннотированный дамп."""
        self._print_main_header()
        self.dump_magic()
        self.dump_version_and_flags()
        self.dump_metadata()
        # ... остальные блоки
