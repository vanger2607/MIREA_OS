CC = gcc # компилятор
CFLAGS = -Wall -Wextra -pedantic -fPIC # флаги согласно pdf + флаг fPIC говорящий, что код можно загрузить в любое место памяти, нужен для динамической библиотеки
LDFLAGS = -shared # ключ указывает на то, что собирается библиотека, а не исполняемый файл

# задаём цель all
all: libcaesar.so

# цель-файл libcaesar.so зависит от caesar.o, нужно выполнить команду ниже
libcaesar.so: caesar.o
	$(CC) $(LDFLAGS) -o libcaesar.so caesar.o 
# флаг -o означает имя выходного объекта

caesar.o: caesar.c caesar.h
	$(CC) $(CFLAGS) -c caesar.c -o caesar.o 
# флаг -c означает compile only, без линковки, так бы компилятор пытался бы создать исполняемый файл

install: libcaesar.so
	sudo cp libcaesar.so /usr/local/lib/ 
# cp копирует файл библиотеки в системную директорию, чтобы библиотека стала доступна
	sudo ldconfig 
# ldconfig обновляет линкер, чтобы он обнаружил скопированный файл

test: libcaesar.so input.txt
	python3 test.py ./libcaesar.so K input.txt output.txt 
# Запускаем питон скрипт с аргументами: путь к .so, ключ 'K', input/output файлы

clean:
	rm -f *.o *.so output.txt decrypted.txt 
# удаляет все .o и .so и output.txt и 
# decrypted.txt файлы, в текущей директории, флаг -f "force" не падает с ошибкой, если нет таких файлов

.PHONY: all install test clean # Говорим make, что эти цели - не файлы, а абстрактные действия

# Создаём тестовый файл для make test (если его нет)
input.txt:
	echo "Hello, world!" > input.txt