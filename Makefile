CC = gcc # компилятор
CFLAGS = -Wall -Wextra -pedantic -fPIC # флаги согласно pdf + флаг fPIC говорящий, что код можно загрузить в любое место памяти
# нужен для динамической библиотеки
LDFLAGS = -shared # ключ указывает на то, что собирается библиотека, а не исполняемый файл
# задаём цель all
all: libcaesar.so
# цель-файл libcaesar.so зависит от caesar.o, нужно выполнить команду ниже
libcaesar.so: caesar.o
	gcc $(LDFLAGS) -o libcaesar.so caesar.o # флаг -o означает имя выходного объекта
caesar.o: caesar.c caesar.h
	$(CC) $(CFLAGS) -c caesar.c -o caesar.o # флаг -c означает compile only, без линковки, так бы компилятор пытался бы создать исполняемый файл
install: libcaesar.so
	cp libcaesar.so /usr/local/bin
	ldconfig
	# cp копирует файл библиотеки в систему директорию, чтобы библиотека стала доступна, ldconfig обновляет линкер, чтобы он обнаружил скопированный файл
test: libcaesar.so
	python3 test.py # Запускаем питон скрипт
clean:
	rm -f *.o *.so # удаляет все .o и .so файлы в текущей дириктории, флаг -f "force" не падает с ошибкой, если нет таких файлов.
.PHONY: all install test clean # Говорим make, что эти цели - не файлы, а абстрактные действия.
