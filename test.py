import ctypes
import sys

# Проверим, что количество передаваемых аргументов корректно (= 5)
if len(sys.argv) != 5:
    print("Usage: python3 test.py <lib_path> <key> <input_file> <output_file>")
    sys.exit(1)

lib_path = sys.argv[1]
key_char = sys.argv[2][0] 
input_file = sys.argv[3]
output_file = sys.argv[4]

try:
    lib = ctypes.CDLL(lib_path)  # Динамическая загрузка нашей библиотеки по переданному пути
except OSError as e:
    print(f"Error loading library: {e}")
    sys.exit(1)

# Настраиваем типы
lib.set_key.argtypes = [ctypes.c_char]  # char для ключа
lib.set_key.restype = None

lib.caesar.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]  
lib.caesar.restype = None

# Читаем входной файл в binary mode
with open(input_file, 'rb') as f:
    data = f.read()
len_data = len(data)

# Создаём буфер для данных
buffer = bytearray(data)  # Копируем в изменяемый буфер

# Устанавливаем ключ
lib.set_key(key_char.encode('utf-8')[0])

# Вызываем caesar src == dst
lib.caesar(buffer, buffer, len_data)  # Библиотека сама скастует bytearray к нужному типу

# Записываем результат в output file в binary mode
with open(output_file, 'wb') as f:
    f.write(buffer)

print(f"Processed {input_file} -> {output_file} with key '{key_char}'")

# Для проверки: двойной XOR должен вернуть оригинал
lib.caesar(buffer, buffer, len_data)
with open("decrypted.txt", 'wb') as f:  
    f.write(buffer)
print("Double XOR check: decrypted.txt should match input.txt")