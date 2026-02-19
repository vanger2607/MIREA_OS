#include "caesar.h"

// Статическая переменная для хранения ключа (доступна только внутри библиотеки)
static char encryption_key = 0;

void set_key(char key) {
    encryption_key = key;
}

void caesar(void* src, void* dst, int len) {
    if (src == NULL || dst == NULL || len <= 0) {
        return;  // Ничего не делаем при invalid input
    }
    
    // Кастуем void* к unsigned char* для побайтового доступа: unsigned char трактует как байты 0-255 (без знака),
    // dst_bytes[i] — синтаксический сахар для *(dst_bytes + i),
    unsigned char* src_bytes = (unsigned char*)src;
    unsigned char* dst_bytes = (unsigned char*)dst;
    
    for (int i = 0; i < len; i++) {
        dst_bytes[i] = src_bytes[i] ^ encryption_key;  // Побайтовый XOR
    }
}