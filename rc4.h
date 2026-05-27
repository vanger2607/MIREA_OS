#ifndef RC4_H
#define RC4_H

// Создаем новый тип данных RC4_State с помощью typedef
typedef struct {
    unsigned char S[256];
    int i;
    int j;
} RC4_State;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Инициализация внутреннего состояния (KSA - Key-Scheduling Algorithm).
 * Читает мастер-ключ напрямую по указателю global_key, чтобы избежать
 * создания незащищенных копий ключа в регистрах или памяти (Zero-copy).
 */
void rc4_init(volatile RC4_State* state, 
              const unsigned char* global_key, int key_len, 
              const unsigned char* salt, int salt_len);

/*
 * Шифрование и дешифрование данных.
 * RC4 симметричен, поэтому одна функция используется и для шифрования, и для расшифровки.
 */
void rc4_crypt(volatile RC4_State* state, unsigned char* data, int len);

#ifdef __cplusplus
}
#endif

#endif // RC4_H