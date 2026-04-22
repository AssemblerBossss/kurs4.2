import struct


class BinaryReader:
    """
    Последовательный парсер big-endian бинарного потока.

    Хранит внутренний курсор (offset) и продвигает его
    при каждом чтении. Все числа читаются в формате big-endian.
    """

    # Sentinel-значение: строка отсутствует (NULL)
    _NULL_STRING: int = 0xFFFF_FFFF

    # Форматы struct для удобства переиспользования
    _FMT_U8 = struct.Struct(">B")  # 1 байт,  unsigned
    _FMT_U32 = struct.Struct(">I")  # 4 байта, unsigned big-endian

    def __init__(self, data: bytes):
        self._data = data
        self._offset = 0

    def tell(self) -> int:
        """Возвращает текущую позицию курсора (в байтах от начала)."""
        return self._offset

    def remaining(self):
        """Сколько байт ещё не прочитано."""
        return len(self._data) - self._offset

    def read_bytes(self, n: int) -> bytes:
        """
        Читает ровно n байт и сдвигает курсор.

        Raises:
            ValueError: если байт недостаточно.
        """
        if self._offset + n > len(self._data):
            raise ValueError(
                f"Неожиданный конец файла: запрошено {n} байт "
                f"по смещению 0x{self._offset:04x}, доступно {len(self._data) - self._offset}"
            )
        chunk = self._data[self._offset : self._offset + n]
        self._offset += n

        return chunk

    def read_u8(self) -> int:
        """1 байт → unsigned int (0–255)."""
        return self._FMT_U8.unpack(self.read_bytes(1))[0]

    def read_u32(self) -> int:
        """4 байта big-endian → unsigned int (0–4 294 967 295)."""
        return self._FMT_U32.unpack(self.read_bytes(4))[0]

    def read_time(self) -> int:
        """
        Читает 64-битную метку времени Unix (time_t).

        Формат хранения: два последовательных guint32 (hi, lo),
        объединяемых в одно 64-битное число: result = (hi << 32) | lo.

        Returns:
            Количество секунд с 1970-01-01 00:00:00 UTC.
        """
        hi = self.read_u32()
        lo = self.read_u32()
        return (hi << 32) | lo

    def read_string(self) -> str | None:
        """
        Читает строку в формате: guint32 (длина) + bytes (UTF-8).

        Специальное значение длины 0xFFFFFFFF означает NULL —
        метод вернёт None вместо строки.

        Returns:
            Декодированная строка или None, если длина == 0xFFFFFFFF.
        """
        length = self.read_u32()

        if length == self._NULL_STRING:
            return None

        raw = self.read_bytes(length)
        return raw.decode("utf-8", errors="replace")
