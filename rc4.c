#include "rc4.h"

void rc4_init(volatile RC4_State* state, 
              const unsigned char* global_key, int key_len, 
              const unsigned char* salt, int salt_len) {
    int i, j = 0;
    int total_len = key_len + salt_len;

    // Инициализация S-блока значениями от 0 до 255
    for (i = 0; i < 256; i++) {
        state->S[i] = (unsigned char)i;
    }
    
    state->i = 0;
    state->j = 0;
    
    // Перемешивание S-блока на основе ключа и соли (KSA)
    for (i = 0; i < 256; i++) {
        int key_idx = i % total_len;
        
        // Прямое чтение из mmap в математическое выражение.
        //  "склеиваем" ключ и соль без копирования.
        if (key_idx < key_len) {
            j = (j + state->S[i] + global_key[key_idx]) % 256;
        } else {
            j = (j + state->S[i] + salt[key_idx - key_len]) % 256;
        }

        // Обмен элементов (swap)
        unsigned char temp = state->S[i];
        state->S[i] = state->S[j];
        state->S[j] = temp;
    }
}

void rc4_crypt(volatile RC4_State* state, unsigned char* data, int len) {
    int i = state->i;
    int j = state->j;
    
    // Генерация псевдослучайного потока и побайтовый XOR с данными
    for (int k = 0; k < len; k++) {
        i = (i + 1) % 256;
        j = (j + state->S[i]) % 256;
        
        // Обмен элементов
        unsigned char temp = state->S[i];
        state->S[i] = state->S[j];
        state->S[j] = temp;
        
        // Получаем случайный байт из S-блока и делаем XOR
        unsigned char K = state->S[(state->S[i] + state->S[j]) % 256];
        data[k] ^= K;
    }
    
    // Сохраняем обновленные индексы обратно в состояние
    state->i = i;
    state->j = j;
}