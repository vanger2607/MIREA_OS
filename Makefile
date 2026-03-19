CXX = g++ # компилятор (заменили gcc на g++, так как  C++)
C = gcc
#-pthread (обязательный флаг для работы со std::atomic и POSIX-потоками)
# -pedantic строгое соответсвие стандарту плюсов и си
#  -O2 - оптимизация
CXXFLAGS = -Wall -Wextra -pedantic -O2 -pthread 

LIB_LDFLAGS = -shared # ключ указывает на то, что собирается библиотека

# НОВЫЕ ФЛАГИ ЛИНКОВКИ ДЛЯ ПРОГРАММЫ:
# -L. говорит линкеру: "ищи библиотеки в текущей директории тоже"
# -lcaesar заставляет прилинковать файл libcaesar.so (префикс lib и .so опускаются)
# -Wl,-rpath,. вшивает путь к библиотеке прямо в бинарник, чтобы программа 
# могла найти .so файл в текущей папке без необходимости делать make install
APP_LDFLAGS = -L. -lcaesar -Wl,-rpath,.

# задаём цель all: теперь она собирает и библиотеку, и саму программу
all: libcaesar.so secure_copy

# ----------------- БИБЛИОТЕКА -----------------

# цель-файл libcaesar.so зависит от caesar.o, нужно выполнить команду ниже
libcaesar.so: caesar.o
	$(CXX) $(LIB_LDFLAGS) -o libcaesar.so caesar.o 
# флаг -o означает имя выходного объекта

# компилируем исходник библиотеки. 
# Флаг -fPIC нужен именно здесь, чтобы код можно было загрузить в любое место памяти
caesar.o: caesar.c caesar.h
	$(C) $(CXXFLAGS) -fPIC -c caesar.c -o caesar.o 
# флаг -c означает compile only, без линковки

# ----------------- ПРОГРАММА -----------------

# НОВАЯ ЦЕЛЬ: собираем исполняемый файл. Он зависит от своего .o файла и от библиотеки
secure_copy: secure_copy.o libcaesar.so
	$(CXX) $(CXXFLAGS) -o secure_copy secure_copy.o $(APP_LDFLAGS)

# НОВАЯ ЦЕЛЬ: объектный файл программы. 
# Зависит от readerwriterqueue.h
secure_copy.o: secure_copy.cpp caesar.h readerwriterqueue.h atomicops.h
	$(CXX) $(CXXFLAGS) -c secure_copy.cpp -o secure_copy.o

# ----------------- УТИЛИТЫ -----------------

install: libcaesar.so
	sudo cp libcaesar.so /usr/local/lib/ 
# cp копирует файл библиотеки в системную директорию, чтобы библиотека стала доступна глобально
	sudo ldconfig 
# ldconfig обновляет кэш линкера, чтобы система "увидела" новую библиотеку

# Обновили тест: теперь он тестирует C++ программу через стандартный ввод (stdin)
test: all input.txt
	cat input.txt | ./secure_copy output.txt 77 
# Читаем input.txt, передаем через пайп (|) в программу. Ключ = 77, результат в output.txt
test_2: all output.txt
	cat output.txt | ./secure_copy output_decrypted.txt 77
clean:
	rm -f *.o *.so secure_copy output.txt output_decrypted.txt input.txt file*.txt
# удаляем все промежуточные .o, библиотеку .so, бинарник программы и текстовые файлы.

.PHONY: all install test clean # Говорим make, что эти цели - не файлы, а абстрактные действия

# Создаём тестовый файл для make test (если его нет)
input.txt:
	echo "Hello, world! This is a test for our lock-free queue." > input.txt
