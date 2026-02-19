#ifndef CAESAR_H
#define CAESAR_H



// Устанавливает ключ шифрования (один байт)
void set_key(char key);

// Выполняет XOR-шифрование/дешифрование len байт из src в dst
// src и dst могут быть одним и тем же буфером
void caesar(void* src, void* dst, int len);

#endif 
