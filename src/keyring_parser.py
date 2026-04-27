from typing import Any
from src.binary_reader import BinaryReader
from src.keyring_models import (
    MAGIC,
    MAGIC_SIZE,
    NULL_STRING,
    KeyringHeader,
    HashedAttribute,
    HashedItem,
    KeyringFile,
    FieldOffset,
)


class KeyringParser:
    """Парсер файла .keyring — извлекает структурированные данные без вывода."""

    def __init__(self, filepath: str):
        with open(filepath, "rb") as f:
            self.data = f.read()

        self.reader = BinaryReader(self.data)
        self.filepath: str = filepath

        # Смещения всех полей (для визуализатора)
        self._offsets: dict[str, Any] = {}

    # ─── Приватные методы для сохранения смещений ─────────────────────────────
    def _save_offset(self, name: str, start: int, end: int) -> None:
        """Сохраняет смещение поля."""
        self._offsets[name] = FieldOffset(start=start, end=end)

    def _save_offset_pair(self, name: str, start: int) -> None:
        """Сохраняет смещение с автоматическим определением конца (текущая позиция)."""
        self._save_offset(name, start, self.reader.tell())

    def _parse_magic(self) -> bytes:
        """Извлекает сигнатуру (16 байт)."""
        start = self.reader.tell()
        magic = self.reader.read_bytes(MAGIC_SIZE)
        self._save_offset_pair("magic", start)

        if magic != MAGIC:
            raise ValueError(
                f"Неверная сигнатура. Ожидалось: {MAGIC!r}, получено: {magic!r}"
            )

        return magic

    def _parse_version_block(self) -> tuple[int, int, int, int, dict[str, FieldOffset]]:
        """Извлекает major, minor, crypto, hash и их смещения."""
        offsets = {}

        start = self.reader.tell()
        version_major = self.reader.read_u8()
        offsets["version_major"] = FieldOffset(start, self.reader.tell())

        start = self.reader.tell()
        version_minor = self.reader.read_u8()
        offsets["version_minor"] = FieldOffset(start, self.reader.tell())

        start = self.reader.tell()
        crypto_type = self.reader.read_u8()
        offsets["crypto_type"] = FieldOffset(start, self.reader.tell())

        start = self.reader.tell()
        hash_type = self.reader.read_u8()
        offsets["hash_type"] = FieldOffset(start, self.reader.tell())

        if version_major != 0:
            raise ValueError(
                f"Неподдерживаемая версия формата: {version_major}.{version_minor} "
                f"(поддерживается только версия 0, crypto=0, AES-128-CBC)"
            )

        return version_major, version_minor, crypto_type, hash_type, offsets

    def _parse_name(self) -> tuple[str, dict[str, FieldOffset]]:
        """Извлекает имя хранилища (guint32 len + bytes)."""
        offsets = {}

        # Длина имени
        len_start = self.reader.tell()
        name_len = self.reader.read_u32()
        offsets["name_len"] = FieldOffset(len_start, self.reader.tell())

        # Само имя
        name_start = self.reader.tell()
        if name_len == NULL_STRING:
            name = ""
        else:
            name_bytes = self.reader.read_bytes(name_len)
            name = name_bytes.decode("utf-8", errors="replace")
        offsets["name"] = FieldOffset(name_start, self.reader.tell())

        return name, offsets

    def _parse_metadata(self) -> tuple[int, int, int, int, dict[str, FieldOffset]]:
        """Извлекает ctime, mtime, flags, lock_timeout и их смещения."""
        offsets = {}

        # CTIME
        start = self.reader.tell()
        ctime = self.reader.read_time()
        offsets["ctime"] = FieldOffset(start, self.reader.tell())

        # MTIME
        start = self.reader.tell()
        mtime = self.reader.read_time()
        offsets["mtime"] = FieldOffset(start, self.reader.tell())

        # FLAGS
        start = self.reader.tell()
        flags = self.reader.read_u32()
        offsets["flags"] = FieldOffset(start, self.reader.tell())

        # LOCK_TIMEOUT
        start = self.reader.tell()
        lock_timeout = self.reader.read_u32()
        offsets["lock_timeout"] = FieldOffset(start, self.reader.tell())

        return ctime, mtime, flags, lock_timeout, offsets

    def _parse_kdf_params(self) -> tuple[int, bytes, bytes, dict[str, FieldOffset]]:
        """Извлекает параметры KDF и их смещения."""
        offsets = {}

        # HASH_ITERATIONS
        start = self.reader.tell()
        iterations = self.reader.read_u32()
        offsets["kdf_iterations"] = FieldOffset(start, self.reader.tell())

        # SALT (8 байт)
        start = self.reader.tell()
        salt = self.reader.read_bytes(8)
        offsets["kdf_salt"] = FieldOffset(start, self.reader.tell())

        # RESERVED[4] (16 байт)
        start = self.reader.tell()
        reserved = self.reader.read_bytes(16)
        offsets["kdf_reserved"] = FieldOffset(start, self.reader.tell())

        return iterations, salt, reserved, offsets

    def _parse_hashed_attributes(
        self, num_attrs: int
    ) -> tuple[list[HashedAttribute], dict]:
        """Извлекает атрибуты hashed item."""
        attrs = []
        attrs_offsets = {}

        for ai in range(num_attrs):
            attr_offsets = {}

            # ATTR NAME
            name_len_start = self.reader.tell()
            name_len = self.reader.read_u32()
            attr_offsets["name_len"] = FieldOffset(name_len_start, self.reader.tell())

            name_start = self.reader.tell()
            name_bytes = self.reader.read_bytes(name_len)
            name = name_bytes.decode("utf-8", errors="replace")
            attr_offsets["name"] = FieldOffset(name_start, self.reader.tell())

            # ATTR TYPE
            type_start = self.reader.tell()
            attr_type = self.reader.read_u32()
            attr_offsets["type"] = FieldOffset(type_start, self.reader.tell())

            # ATTR HASH
            if attr_type == 0:  # string hash
                # Смещение поля длины хеша
                hash_len_start = self.reader.tell()
                hash_len = self.reader.read_u32()
                hash_len_end = self.reader.tell()
                attr_offsets["hash_len"] = FieldOffset(hash_len_start, hash_len_end)

                # Смещение самого хеша
                hash_start = self.reader.tell()
                hash_bytes = self.reader.read_bytes(hash_len)
                hash_str = hash_bytes.decode("utf-8", errors="replace")
                hash_end = self.reader.tell()
                attr_offsets["hash"] = FieldOffset(hash_start, hash_end)

                attrs.append(
                    HashedAttribute(
                        name=name,
                        type_id=attr_type,
                        hash_str=hash_str,
                        hash_int=None,
                        offsets=attr_offsets,
                    )
                )
            else:  # int hash
                hash_start = self.reader.tell()
                hash_int = self.reader.read_u32()
                hash_end = self.reader.tell()
                attr_offsets["hash"] = FieldOffset(hash_start, hash_end)

                attrs.append(
                    HashedAttribute(
                        name=name,
                        type_id=attr_type,
                        hash_str=None,
                        hash_int=hash_int,
                        offsets=attr_offsets,
                    )
                )

            attrs_offsets[f"attr_{ai}"] = attr_offsets

        return attrs, attrs_offsets

    def _parse_hashed_items(self) -> tuple[list[HashedItem], dict]:
        """Извлекает hashed items (незашифрованные атрибуты)."""
        items = []
        items_offsets = {}

        # NUM_ITEMS
        num_items_start = self.reader.tell()
        num_items = self.reader.read_u32()
        self._offsets["num_items"] = FieldOffset(num_items_start, self.reader.tell())

        for idx in range(num_items):
            item_offsets = {}

            # ITEM ID
            id_start = self.reader.tell()
            item_id = self.reader.read_u32()
            item_offsets["id"] = FieldOffset(id_start, self.reader.tell())

            # ITEM TYPE
            type_start = self.reader.tell()
            item_type = self.reader.read_u32()
            item_offsets["type"] = FieldOffset(type_start, self.reader.tell())

            # NUM_ATTRS
            num_attrs_start = self.reader.tell()
            num_attrs = self.reader.read_u32()
            item_offsets["num_attrs"] = FieldOffset(num_attrs_start, self.reader.tell())

            # ATTRIBUTES
            attrs, attrs_offsets = self._parse_hashed_attributes(num_attrs)
            item_offsets["attributes"] = attrs_offsets

            items.append(
                HashedItem(
                    idx=idx,
                    item_id=item_id,
                    item_type=item_type,
                    attributes=attrs,
                    offsets=item_offsets,
                )
            )
            items_offsets[f"item_{idx}"] = item_offsets

        return items, items_offsets

    def _parse_encrypted_block(self) -> tuple[bytes, dict]:
        """Извлекает зашифрованный блок."""
        offsets = {}

        # NUM_ENCRYPTED (размер зашифрованного блока)
        size_start = self.reader.tell()
        encrypted_size = self.reader.read_u32()
        offsets["encrypted_size"] = FieldOffset(size_start, self.reader.tell())

        # Зашифрованные данные
        if encrypted_size > 0:
            data_start = self.reader.tell()
            encrypted_data = self.reader.read_bytes(encrypted_size)
            offsets["encrypted_data"] = FieldOffset(data_start, self.reader.tell())
        else:
            encrypted_data = b""
            offsets["encrypted_data"] = FieldOffset(
                self.reader.tell(), self.reader.tell()
            )

        return encrypted_data, offsets

    def parse_all(self) -> KeyringFile:
        """
        Извлекает все данные последовательно и возвращает KeyringFile.
        """
        # Блок 1: Сигнатура
        magic = self._parse_magic()

        # Блок 2: Версия и флаги
        ver_major, ver_minor, crypto, hash_type, version_offsets = (
            self._parse_version_block()
        )
        self._offsets.update(version_offsets)

        # Блок 3: Имя + метаданные
        name, name_offsets = self._parse_name()
        self._offsets.update(name_offsets)

        ctime, mtime, flags, lock_timeout, meta_offsets = self._parse_metadata()
        self._offsets.update(meta_offsets)

        # Блок 4: KDF параметры
        iterations, salt, reserved, kdf_offsets = self._parse_kdf_params()
        self._offsets.update(kdf_offsets)

        # Блок 5: Hashed items
        hashed_items, items_offsets = self._parse_hashed_items()
        self._offsets["hashed_items"] = items_offsets

        # Блок 6: Зашифрованный блок
        encrypted_data, enc_offsets = self._parse_encrypted_block()
        self._offsets.update(enc_offsets)

        # Сохраняем общий размер файла
        self._offsets["file_end"] = FieldOffset(len(self.data), len(self.data))

        # Создаём объект заголовка
        header = KeyringHeader(
            magic=magic,
            version_major=ver_major,
            version_minor=ver_minor,
            crypto_type=crypto,
            hash_type=hash_type,
            name=name,
            ctime=ctime,
            mtime=mtime,
            flags=flags,
            lock_timeout=lock_timeout,
            kdf_iterations=iterations,
            kdf_salt=salt,
            kdf_reserved=reserved,
            offsets=self._offsets,
        )

        # Создаём итоговый объект
        return KeyringFile(
            filepath=self.filepath,
            file_size=len(self.data),
            data=self.data,
            header=header,
            hashed_items=hashed_items,
            encrypted_blob=encrypted_data,
        )
