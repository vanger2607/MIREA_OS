#ifndef CAESAR_H // проверка, что CAESAR_H не был объявлен до этого
#define CAESAR_H

extern char* caesar_encrypt(const char* text, int shift); // extern, чтобы показать, что мы объявляем функции, реализованы они будут в другом файле
extern char* caesar_decrypt(const char* text, int shif);

#endif

