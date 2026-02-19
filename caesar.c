#include <stdlib.h>
#include <string.h>
#include "caesar.h"

char* caesar_encrypt(const char* text, int shift){
	if (text == NULL) return NULL; // Если пришла пуста вернем пустота
	// Нормализуем сдвиг: чтобы при отрицательном сдвиге он был положительным и при сдвиге > 26 мы бы оставались в пределах 0-25
	shift = (shift % 26 + 26) % 26; // + 26 защита от отрицательных чисел, чтобы всё было математически верно -3 % 26 = -3 -3 + 26 = 23 23 % 26 = 23
	size_t len = strlen(text); // используем size_t тип для длин массивов и размеров
	// Выделяем память под новую строку + null-терминатор
	char* result = malloc(len + 1);
	// Если не удалось выделить память вернём null
	if (result == NULL) return NULL;
	for (size_t i = 0; i < len; i++){
		char c = text[i];
		// проверяем входит ли символ в диапазон a-z
		if (c >= 'a' && c <= 'z'){
			// result[i] эквивалентно *(result + i)
			// представим a-z как массив с индексами от нуля до 25, тогда сначала приведем символ к индексу массива (c - 'a') после прибавим сдвиг
			// возьмем остаток от полученного числа, чтобы "заколцеваться" 25->0
			// прибавим 'a' чтобы получилась искомая буква
			result[i] = 'a' + (c - 'a' + shift) % 26; 
		}
		else {
			result[i] = c; // копируем символ ничего не меняя
		}}
	result[len] = '\0';

	return result;
	
}

char* caesar_decrypt(const char* text, int shift){
	// Дешифрование = шифрование с отрицательным сдвигом
	return caesar_encrypt(text, -shift);
}
