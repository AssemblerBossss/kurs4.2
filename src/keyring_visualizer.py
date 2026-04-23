# keyring_visualizer.py — Отвечает только за вывод и аннотации
from datetime import datetime

from src.keyring_models import (
    KeyringFile,
    HashedItem,
    HashedAttribute,
    FieldOffset,
    CRYPTO_NAMES,
    HASH_NAMES,
    KeyringHeader,
)

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


class KeyringVisualizer:
    """Визуализатор .keyring — выводит аннотированный hex-дамп."""

    def __init__(self, keyring: KeyringFile):
        """
        Args:
            keyring: Экземпляр KeyringFile с уже извлечёнными данными
        """

        self.keyring = keyring
        self.data = keyring.data if hasattr(keyring, "data") else None

        # Если у keyring нет поля data, читаем файл заново
        if self.data is None:
            with open(keyring.filepath, "rb") as f:
                self.data = f.read()

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

    def _dump_field_from_offset(
        self, offset: FieldOffset, name: str, value_str: str = "", color: str = WHITE
    ) -> None:
        """Выводит hex-дамп, используя объект FieldOffset."""
        self._dump_field(
            start=offset.start,
            end=offset.end,
            name=name,
            value_str=value_str,
            color=color,
        )

    def _print_main_header(self) -> None:
        """Выводит главный заголовок."""
        print()
        print(self._colored("═" * 90, BOLD))
        print(
            self._colored(
                f"  АННОТИРОВАННЫЙ HEX-ДАМП: {self.keyring.filepath}  ({self.keyring.file_size} байт)",
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

        magic = self.keyring.header.magic
        magic_repr = repr(magic)[2:-1]

        self._dump_field(
            start=0, end=16, name="MAGIC", value_str=magic_repr, color=COLOR_MAGIC
        )

    def dump_version_and_flags(self) -> None:
        """Визуализирует блок флагов алгоритмов."""
        self._print_block_header("БЛОК 2: ФЛАГИ АЛГОРИТМОВ", CYAN)

        header: KeyringHeader = self.keyring.header
        offsets = header.offsets

        # VERSION_MAJOR
        self._dump_field_from_offset(
            offset=offsets["version_major"],
            name="VERSION_MAJOR",
            value_str=str(header.version_major),
            color=COLOR_HEADER,
        )

        # VERSION_MINOR
        self._dump_field_from_offset(
            offset=offsets["version_minor"],
            name="VERSION_MINOR",
            value_str=str(header.version_minor),
            color=COLOR_HEADER,
        )

        # CRYPTO_TYPE
        crypto_name = CRYPTO_NAMES.get(
            header.crypto_type, f"UNKNOWN (0x{header.crypto_type:02x})"
        )

        self._dump_field_from_offset(
            offset=offsets["crypto_type"],
            name="CRYPTO_TYPE",
            value_str=f"{header.crypto_type} = {crypto_name}",
            color=COLOR_HEADER,
        )

        # HASH_TYPE
        hash_name = HASH_NAMES.get(
            header.hash_type, f"UNKNOWN (0x{header.hash_type:02x})"
        )

        self._dump_field_from_offset(
            offset=offsets["hash_type"],
            name="HASH_TYPE",
            value_str=f"{header.hash_type} = {hash_name}",
            color=COLOR_HEADER,
        )

    # ─── Блок 3: Метаданные ──────────────────────────────────────────────────

    def dump_metadata(self) -> None:
        """Визуализирует блок метаданных."""
        self._print_block_header("БЛОК 3: МЕТАДАННЫЕ ХРАНИЛИЩА", BOLD + YELLOW)

        header = self.keyring.header
        offsets = header.offsets

        # NAME_LENGTH
        name_len = len(header.name.encode("utf-8"))
        self._dump_field_from_offset(
            offset=offsets["name_len"],
            name="NAME_LENGTH",
            value_str=str(name_len),
            color=COLOR_META,
        )

        # NAME
        self._dump_field_from_offset(
            offset=offsets["name"],
            name="NAME",
            value_str=header.name,
            color=COLOR_META,
        )

        # CTIME
        self._dump_field_from_offset(
            offset=offsets["ctime"],
            name="CTIME (time_t: 2×uint32)",
            value_str=header.ctime_str,
            color=COLOR_META,
        )

        # MTIME
        self._dump_field_from_offset(
            offset=offsets["mtime"],
            name="MTIME (time_t: 2×uint32)",
            value_str=header.mtime_str,
            color=COLOR_META,
        )

        # FLAGS
        self._dump_field_from_offset(
            offset=offsets["flags"],
            name="FLAGS",
            value_str=f"0x{header.flags:08x}",
            color=COLOR_META,
        )

        # LOCK_TIMEOUT
        self._dump_field_from_offset(
            offset=offsets["lock_timeout"],
            name="LOCK_TIMEOUT (сек)",
            value_str=str(header.lock_timeout),
            color=COLOR_META,
        )

    def dump_kdf_params(self) -> None:
        """Визуализирует блок параметров KDF."""
        self._print_block_header("БЛОК 4: ПАРАМЕТРЫ KDF", BOLD + MAGENTA)

        header = self.keyring.header
        offsets = header.offsets

        # HASH_ITERATIONS
        self._dump_field_from_offset(
            offset=offsets["kdf_iterations"],
            name="HASH_ITERATIONS",
            value_str=str(header.kdf_iterations),
            color=COLOR_KDF,
        )

        # SALT
        self._dump_field_from_offset(
            offset=offsets["kdf_salt"],
            name="SALT (8 байт)",
            value_str=header.kdf_salt.hex(),
            color=COLOR_KDF,
        )

        # RESERVED[4]
        self._dump_field_from_offset(
            offset=offsets["kdf_reserved"],
            name="RESERVED[4] (должны быть 0x00)",
            value_str="",
            color=COLOR_META,
        )

        # ─── Блок 5: Hashed Items ────────────────────────────────────────────────

    def dump_hashed_items(self) -> None:
        """Визуализирует блок hashed items (незашифрованные атрибуты)."""
        self._print_block_header(
            "БЛОК 5: HASHED ITEMS (незашифрованные атрибуты)", BOLD + BLUE
        )

        header = self.keyring.header
        offsets = header.offsets

        # NUM_ITEMS
        self._dump_field_from_offset(
            offsets["num_items"],
            "NUM_ITEMS",
            str(len(self.keyring.hashed_items)),
            COLOR_HASH,
        )

        # Перебираем элементы
        for item in self.keyring.hashed_items:
            print()  # Разделитель между элементами

            # ITEM ID
            self._dump_field_from_offset(
                offset=item.offsets["id"],
                name=f"  ITEM[{item.idx}].ID",
                value_str=str(item.item_id),
                color=COLOR_HASH,
            )

            # ITEM TYPE
            self._dump_field_from_offset(
                offset=item.offsets["type"],
                name=f"  ITEM[{item.idx}].TYPE",
                value_str=str(item.item_type),
                color=COLOR_HASH,
            )

            # NUM_ATTRS
            self._dump_field_from_offset(
                offset=item.offsets["num_attrs"],
                name=f"  ITEM[{item.idx}].NUM_ATTRS",
                value_str=str(len(item.attributes)),
                color=COLOR_HASH,
            )

            # Атрибуты
            for attr in item.attributes:
                # ATTR NAME
                self._dump_field_from_offset(
                    offset=attr.offsets["name"],
                    name=f"    ATTR[{attr.name}].NAME",
                    value_str=repr(attr.name),
                    color=COLOR_HASH,
                )

                # ATTR TYPE
                type_desc = "0=str, 1=int"
                self._dump_field_from_offset(
                    offset=attr.offsets["type"],
                    name=f"    ATTR[{attr.name}].TYPE ({type_desc})",
                    value_str=str(attr.type_id),
                    color=COLOR_HASH,
                )

                # ATTR HASH
                if attr.type_id == 0:  # string
                    if "hash" in attr.offsets:
                        self._dump_field_from_offset(
                            offset=attr.offsets["hash"],
                            name=f"    ATTR[{attr.name}].STR_HASH ({len(attr.hash_str) if attr.hash_str else 0} B)",
                            value_str=repr(attr.hash_str),
                            color=COLOR_HASH,
                        )
                    else:
                        # fallback (если вдруг нет)
                        self._dump_field(
                            start=attr.offsets["hash_len"].end,
                            end=attr.offsets["hash_len"].end + 32,
                            name=f"    ATTR[{attr.name}].STR_HASH",
                            value_str=repr(attr.hash_str),
                            color=COLOR_HASH,
                        )
                else:  # int
                    self._dump_field_from_offset(
                        offset=attr.offsets["hash"],
                        name=f"    ATTR[{attr.name}].INT_HASH",
                        value_str=(
                            f"0x{attr.hash_int:08x}"
                            if attr.hash_int is not None
                            else ""
                        ),
                        color=COLOR_HASH,
                    )

    # ─── Блок 6: Зашифрованный блок ──────────────────────────────────────────

    def dump_encrypted_block(self) -> None:
        """Визуализирует зашифрованный блок."""
        self._print_block_header("БЛОК 6: ЗАШИФРОВАННЫЙ БЛОК", BOLD + RED)

        header = self.keyring.header
        offsets = header.offsets

        # NUM_ENCRYPTED
        self._dump_field_from_offset(
            offset=offsets["encrypted_size"],
            name="NUM_ENCRYPTED (байт)",
            value_str=str(self.keyring.encrypted_size),
            color=COLOR_CRYPTO,
        )

        # Зашифрованные данные
        if self.keyring.encrypted_size > 0:
            enc_offset = offsets["encrypted_data"]

            # Первые 16 байт (MD5 верификации)
            self._dump_field(
                start=enc_offset.start,
                end=enc_offset.start + min(16, self.keyring.encrypted_size),
                name="ENCRYPTED[0:16] (после расш. = MD5 верификации)",
                value_str="",
                color=COLOR_CRYPTO,
            )

            # Остальные байты
            if self.keyring.encrypted_size > 16:
                self._dump_field(
                    start=enc_offset.start + 16,
                    end=enc_offset.start + self.keyring.encrypted_size,
                    name=f"ENCRYPTED[16:{self.keyring.encrypted_size}] (зашифрованные записи)",
                    value_str="",
                    color=COLOR_CRYPTO,
                )

    # ─── Карта полей (статическая) ───────────────────────────────────────────

    def _print_field_map(self) -> None:
        """Выводит карту полей файла (статическая информация)."""
        print()
        print(self._colored("═" * 90, BOLD))
        print(self._colored("  КАРТА ПОЛЕЙ ФАЙЛА", BOLD))
        print(self._colored("═" * 90, BOLD))
        print()
        print(f"  {'ПОЛЕ':<40} {'СМЕЩЕНИЕ':<12} {'РАЗМЕР':<10} {'ОПИСАНИЕ'}")
        print("  " + "─" * 86)

        fields = [
            ("MAGIC", "0x0000", "16 B", "Сигнатура: GnomeKeyring\\n\\r\\x00\\n"),
            ("VERSION_MAJOR", "0x0010", "1 B", "Старший байт версии формата"),
            ("VERSION_MINOR", "0x0011", "1 B", "Младший байт версии формата"),
            ("CRYPTO_TYPE", "0x0012", "1 B", "Тип шифрования (0 = AES-128-CBC)"),
            ("HASH_TYPE", "0x0013", "1 B", "Тип KDF (0 = SHA-256 итерационный)"),
            ("NAME", "0x0014", "var", "guint32 длина + байты имени"),
            ("CTIME", "var", "8 B", "Время создания (2 × guint32 big-endian)"),
            ("MTIME", "var", "8 B", "Время изменения (2 × guint32 big-endian)"),
            ("FLAGS", "var", "4 B", "Флаги (бит 0 = lock_on_idle)"),
            ("LOCK_TIMEOUT", "var", "4 B", "Таймаут блокировки в секундах"),
            ("HASH_ITERATIONS", "var", "4 B", "Число итераций SHA-256 для KDF"),
            ("SALT", "var", "8 B", "Соль для KDF (случайные байты)"),
            ("RESERVED[4]", "var", "16 B", "Зарезервировано, должно быть 0"),
            ("NUM_ITEMS", "var", "4 B", "Число записей в hashed section"),
            ("HASHED_ITEMS[]", "var", "var", "Незашифрованные хеши атрибутов"),
            ("  .item_id", "  -", "4 B", "Идентификатор записи"),
            ("  .item_type", "  -", "4 B", "Тип записи"),
            ("  .num_attributes", "  -", "4 B", "Число атрибутов"),
            ("  .attr[n].name", "  -", "var", "Имя атрибута (guint32 + bytes)"),
            ("  .attr[n].type", "  -", "4 B", "Тип атрибута (0=str, 1=int)"),
            ("  .attr[n].hash", "  -", "var", "Хеш значения атрибута (str или int)"),
            ("NUM_ENCRYPTED", "var", "4 B", "Размер зашифрованного блока в байтах"),
            ("ENCRYPTED_DATA", "var", "var", "AES-128-CBC(PKCS7(MD5||plaintext))"),
            ("  [0:16]", "  -", "16 B", "MD5(plaintext) — хеш верификации"),
            ("  [16:n]", "  -", "var", "Зашифрованные записи"),
        ]
        for name, off, sz, desc in fields:
            print(f"  {name:<40} {off:<12} {sz:<10} {desc}")
        print()

    def dump_all(self) -> None:
        """Выводит полный аннотированный дамп."""
        self._print_main_header()
        self.dump_magic()
        self.dump_version_and_flags()
        self.dump_metadata()
        self.dump_kdf_params()
        self.dump_hashed_items()
        self.dump_encrypted_block()
        self._print_field_map()
