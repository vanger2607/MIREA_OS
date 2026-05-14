#ifndef CAESAR_H
#define CAESAR_H

#ifdef __cplusplus
extern "C" {
#endif


// Функция шифрования/дешифрования (XOR симметричен)
void caesar(void* src, void* dst, int len, volatile char* secure_key_ptr);

#ifdef __cplusplus
}
#endif

#endif

