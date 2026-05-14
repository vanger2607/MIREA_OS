#include <stdlib.h>
#include "caesar.h"

void caesar(void* src, void* dst, int len, volatile char* secure_key_ptr) {
    if (src == NULL || dst == NULL || len <= 0 || secure_key_ptr == NULL) {
        return;  // Ничего не делаем при invalid input
    }
    
    // Кастуем void* к unsigned char* для побайтового доступа: unsigned char трактует как байты 0-255 (без знака),
    // dst_bytes[i] — синтаксический сахар для *(dst_bytes + i),
    unsigned char* src_bytes = (unsigned char*)src;
    unsigned char* dst_bytes = (unsigned char*)dst;
    
    for (int i = 0; i < len; i++) {
        dst_bytes[i] = src_bytes[i] ^ (*secure_key_ptr);  // Побайтовый XOR
    }
}