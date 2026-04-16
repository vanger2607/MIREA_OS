CXX = g++ # компилятор (заменили gcc на g++, так как  C++)
C = gcc
#-pthread (обязательный флаг для работы со std::atomic и POSIX-потоками)
# -pedantic строгое соответсвие стандарту плюсов и си
#  -O2 - оптимизация
CXXFLAGS = -Wall -Wextra -pedantic -O2 -pthread 

LIB_LDFLAGS = -shared # ключ указывает на то, что собирается библиотека

#ФЛАГИ ЛИНКОВКИ ДЛЯ ПРОГРАММЫ:
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
# Зависит только от caesar.h (убрали удаленные readerwriterqueue.h и atomicops.h)
secure_copy.o: secure_copy.cpp caesar.h
	$(CXX) $(CXXFLAGS) -c secure_copy.cpp -o secure_copy.o

# ----------------- УТИЛИТЫ -----------------

install: libcaesar.so
	sudo cp libcaesar.so /usr/local/lib/ 
# cp копирует файл библиотеки в системную директорию, чтобы библиотека стала доступна глобально
	sudo ldconfig 
# ldconfig обновляет кэш линкера, чтобы система "увидела" новую библиотеку

# ----------------- ТЕСТЫ -----------------

# ТЕСТ: Проверка правильного падения при неверном флаге
test_invalid_mode: all input.txt
	@echo "\n=== Проверка падения при неверном флаге ==="
	@if ./secure_copy --mode=wrong_mode input.txt output_dir 77 2>/dev/null; then \
		echo "[ОШИБКА] Программа не упала при неверном флаге!"; exit 1; \
	else \
		echo "[УСПЕХ] Программа штатно завершилась с ошибкой (как и ожидалось)."; \
	fi

# ТЕСТ: Проверка хеша
test_hash: all
	@echo "\n=== Проверка целостности данных (MD5 Hash) ==="
	@mkdir -p test_hash_in test_hash_out test_hash_dec
	@echo "Secret message for hash test" > test_hash_in/file1.txt
	@./secure_copy test_hash_in/file1.txt test_hash_out 77 > /dev/null
	@./secure_copy test_hash_out/file1.txt test_hash_dec 77 > /dev/null
	@md5sum test_hash_in/file1.txt | awk '{print $$1}' > hash_orig.txt
	@md5sum test_hash_dec/file1.txt | awk '{print $$1}' > hash_dec.txt
	@if diff -q hash_orig.txt hash_dec.txt > /dev/null; then \
		echo "[УСПЕХ] Хеши полностью совпадают!"; \
	else \
		echo "[ОШИБКА] Хеши различаются!"; \
	fi
	@rm -f hash_orig.txt hash_dec.txt

gen_heavy:
	@mkdir -p input_test output_test
	@if [ ! -f input_test/heavy_1.bin ]; then \
		echo "\n=== Генерация тяжелых файлов (8x50MB) ==="; \
		for i in 1 2 3 4 5 6 7 8; do \
			dd if=/dev/urandom of=input_test/heavy_$$i.bin bs=1M count=50 2>/dev/null; \
		done; \
	fi

bench_par: all gen_heavy
	@echo "\n=== Запуск ПАРАЛЛЕЛЬНОГО режима ==="
	sudo sh -c 'sync && echo 3 > /proc/sys/vm/drop_caches'
	./secure_copy --mode=parallel input_test/heavy_*.bin output_test 5

bench_seq: all gen_heavy
	@echo "\n=== Запуск ПОСЛЕДОВАТЕЛЬНОГО режима ==="
	sudo sh -c 'sync && echo 3 > /proc/sys/vm/drop_caches'
	./secure_copy --mode=sequential input_test/heavy_*.bin output_test 5

bench_auto: all gen_heavy
	@echo "\n=== Запуск AUTO режима ==="
	sudo sh -c 'sync && echo 3 > /proc/sys/vm/drop_caches'
	./secure_copy input_test/heavy_*.bin output_test 5

cache_test: bench_seq bench_par bench_auto

# ----------------- ОЧИСТКА -----------------

clean:
	rm -f *.o *.so secure_copy output.txt output_decrypted.txt input.txt file*.txt
	rm -rf output_dir output_decrypted_dir test_hash_in test_hash_out test_hash_dec
	rm -rf input_test output_test decrypted_test
	rm -f stat.txt log.txt hash_orig.txt hash_dec.txt
# удаляем все промежуточные .o, библиотеку .so, бинарник программы и текстовые файлы.

.PHONY: all install test test_2 test_invalid_mode test_hash gen_heavy bench_par bench_seq bench_auto cache_test clean # Говорим make, что эти цели - не файлы, а абстрактные действия

# Создаём тестовый файл для make test (если его нет)
input.txt:
	echo "Hello, world! This is a test for ..." > input.txt