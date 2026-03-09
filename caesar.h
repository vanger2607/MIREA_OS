#ifndef CAESAR_H
#define CAESAR_H

#ifdef __cplusplus
extern "C" {
#endif

// Установка ключа для XOR-преобразования
void set_key(char key);

// Функция шифрования/дешифрования (XOR симметричен)
void caesar(void* src, void* dst, int len);

#ifdef __cplusplus
}
#endif

#endif

