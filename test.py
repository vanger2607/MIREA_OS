import ctypes
import sys

try:
    lib = ctypes.CDLL("./libcaesar.so") # Загружаем динамическую библиотеку
except OSError as e:
    print(f"Error while loadin library: {e}")
    sys.exit(1)
# определяем типы аргуметов и возвращаемого значения для функций, так как у нас ОС linux можно было вроде это и не делать, но так спокойнее
lib.caesar_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_int]
lib.caesar_encrypt.restype = ctypes.c_void_p # указываем void_ptr чтобы потом смогли очистить, так как malloc возвращает void и free принимает указатель на void

lib.caesar_decrypt.argtypes = [ctypes.c_char_p, ctypes.c_int]
lib.caesar_decrypt.restype = ctypes.c_void_p

text = b"hello" # передаём байты, потому C ожидает char* с null-терминатором
shift = 3
encrypted_ptr = lib.caesar_encrypt(text, shift)
encrypted_str = ctypes.cast(encrypted_ptr, ctypes.c_char_p).value.decode("utf-8") # кастуемый к указателю на чар и получаем значение, декодируем
print(encrypted_str)  # ожидаемый вывод: khoor

decrypted_ptr = lib.caesar_decrypt(ctypes.cast(encrypted_ptr, ctypes.c_char_p), shift)
decrypted_str = ctypes.cast(decrypted_ptr, ctypes.c_char_p).value.decode("utf-8")
print(decrypted_str) # ожидаемый вывод: hello
# Чистим память за собой:
libc = ctypes.CDLL("libc.so.6")
libc.free.argtypes = [ctypes.c_void_p]
libc.free(encrypted_ptr)
libc.free(decrypted_ptr)
