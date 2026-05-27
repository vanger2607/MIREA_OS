CXX = g++ # компилятор (заменили gcc на g++, так как  C++)
C = gcc
#-pthread (обязательный флаг для работы со std::atomic и POSIX-потоками)
# -pedantic строгое соответсвие стандарту плюсов и си
#  -O2 - оптимизация
CXXFLAGS = -Wall -Wextra -pedantic -O2 -pthread -std=c++17
CFLAGS = -Wall -Wextra -pedantic -O2 -pthread -std=c11
LIB_LDFLAGS = -shared # ключ указывает на то, что собирается библиотека

#ФЛАГИ ЛИНКОВКИ ДЛЯ ПРОГРАММЫ:
# -L. говорит линкеру: "ищи библиотеки в текущей директории тоже"
# -lcaesar заставляет прилинковать файл libcaesar.so (префикс lib и .so опускаются)
# -Wl,-rpath,. вшивает путь к библиотеке прямо в бинарник, чтобы программа 
# могла найти .so файл в текущей папке без необходимости делать make install
APP_LDFLAGS = -L. -lrc4 -Wl,-rpath,.

# задаём цель all: теперь она собирает и библиотеку, и саму программу
all: librc4.so secure_copy

# ----------------- БИБЛИОТЕКА -----------------

# цель-файл librc4.so зависит от rc4.o, нужно выполнить команду ниже
librc4.so: rc4.o
	$(C) $(LIB_LDFLAGS) -o librc4.so rc4.o 
# флаг -o означает имя выходного объекта

# компилируем исходник библиотеки. 
# Флаг -fPIC нужен именно здесь, чтобы код можно было загрузить в любое место памяти
rc4.o: rc4.c rc4.h
	$(C) $(CFLAGS) -fPIC -c rc4.c -o rc4.o 
# флаг -c означает compile only, без линковки

# ----------------- ПРОГРАММА -----------------

# НОВАЯ ЦЕЛЬ: собираем исполняемый файл. Он зависит от своего .o файла и от библиотеки
secure_copy: secure_copy.o librc4.so
	$(CXX) $(CXXFLAGS) -o secure_copy secure_copy.o $(APP_LDFLAGS)

# НОВАЯ ЦЕЛЬ: объектный файл программы. 
# Зависит только от rc4.h
secure_copy.o: secure_copy.cpp rc4.h
	$(CXX) $(CXXFLAGS) -c secure_copy.cpp -o secure_copy.o

# ЦЕЛЬ ДЛЯ ДЕМОНСТРАЦИИ АТАКИ: Собирает бинарник с условным макросом SIMULATE_ATTACK
secure_copy_attack: secure_copy.cpp librc4.so
	$(CXX) $(CXXFLAGS) -DSIMULATE_ATTACK -o secure_copy_attack secure_copy.cpp $(APP_LDFLAGS)

# ЦЕЛЬ ДЛЯ ДЕМОНСТРАЦИИ ОБЫЧНОЙ ОШИБКИ: Собирает бинарник с макросом SIMULATE_SEGFAULT
secure_copy_segfault: secure_copy.cpp librc4.so
	$(CXX) $(CXXFLAGS) -DSIMULATE_SEGFAULT -o secure_copy_segfault secure_copy.cpp $(APP_LDFLAGS)


# ----------------- УТИЛИТЫ -----------------

install: librc4.so
	sudo cp librc4.so /usr/local/lib/ 
# cp копирует файл библиотеки в системную директорию, чтобы библиотека стала доступна глобально
	sudo ldconfig 
# ldconfig обновляет кэш линкера, чтобы система "увидела" новую библиотеку

# ----------------- КОМПЛЕКСНЫЕ ТЕСТЫ СИСТЕМЫ -----------------

# Мастер-цель для запуска всех базовых тестов
test_all: test_hash test_edge_cases test_invalid_args
	@echo "\n[ОТЛИЧНО] Все базовые тесты успешно пройдены!"

# ТЕСТ 1: Строгая проверка хэш-сумм (MD5) для текстовых и бинарных файлов
test_hash: secure_copy
	@echo "\n=== Тест 1: Проверка целостности данных (Хэш-суммы) ==="
	@rm -rf test_env && mkdir -p test_env
	@echo "[INFO] Генерация тестовых данных..."
	@echo "Secure data test" > test_env/file1.txt
	@dd if=/dev/urandom of=test_env/data.bin bs=1M count=2 2>/dev/null
	@echo "[INFO] Упаковка файлов..."
	@./secure_copy -add -key "testkey" -image test_env/vault.img test_env/file1.txt test_env/data.bin >/dev/null
	@echo "[INFO] Извлечение файлов..."
	@./secure_copy -get -key "testkey" -image test_env/vault.img -out test_env/out_file1.txt /file1.txt >/dev/null
	@./secure_copy -get -key "testkey" -image test_env/vault.img -out test_env/out_data.bin /data.bin >/dev/null
	@echo "[INFO] Сверка хэшей..."
	@md5sum test_env/file1.txt | awk '{print $$1}' > test_env/hash1.txt
	@md5sum test_env/out_file1.txt | awk '{print $$1}' > test_env/hash2.txt
	@diff test_env/hash1.txt test_env/hash2.txt && echo "[УСПЕХ] Текстовый файл совпал!" || (echo "[ОШИБКА] Текстовый файл поврежден!"; exit 1)
	@md5sum test_env/data.bin | awk '{print $$1}' > test_env/hash3.txt
	@md5sum test_env/out_data.bin | awk '{print $$1}' > test_env/hash4.txt
	@diff test_env/hash3.txt test_env/hash4.txt && echo "[УСПЕХ] Бинарный файл (2 МБ) совпал!" || (echo "[ОШИБКА] Бинарный файл поврежден!"; exit 1)
	@rm -rf test_env

# ТЕСТ 2: Краевые случаи (Дубликаты, O_EXCL, Неверный пароль)
test_edge_cases: secure_copy
	@echo "\n=== Тест 2: Проверка краевых случаев и защит ==="
	@rm -rf test_edge && mkdir -p test_edge
	@echo "secret" > test_edge/file.txt
	
	@echo "\n[+] Проверка дедупликации (-add):"
	@./secure_copy -add -key "key" -image test_edge/vault.img test_edge/file.txt test_edge/file.txt 2>&1 | grep -q "Пропуск дубликата" && echo "  -> [УСПЕХ] Дубликаты корректно заблокированы." || (echo "  -> [ОШИБКА]"; exit 1)
	
	@echo "\n[+] Проверка O_EXCL (-get):"
	@./secure_copy -get -key "key" -image test_edge/vault.img -out test_edge/file.txt /file.txt 2>&1 | grep -q "уже существует" && echo "  -> [УСПЕХ] Перезапись существующего файла заблокирована." || (echo "  -> [ОШИБКА]"; exit 1)
	
	@echo "\n[+] Проверка обработки отсутствующего файла:"
	@./secure_copy -get -key "key" -image test_edge/vault.img -out test_edge/ghost.txt /ghost.txt 2>&1 | grep -q "не найден" && echo "  -> [УСПЕХ] Поиск несуществующего файла отработал корректно." || (echo "  -> [ОШИБКА]"; exit 1)
	
	@echo "\n[+] Проверка реакции на неверный пароль:"
	@./secure_copy -get -key "wrong_pass" -image test_edge/vault.img -out test_edge/bad_decrypt.txt /file.txt >/dev/null
	@if ! cmp -s test_edge/file.txt test_edge/bad_decrypt.txt; then echo "  -> [УСПЕХ] Файл с неверным ключом расшифрован в 'мусор' (хэши разошлись)."; else echo "  -> [ОШИБКА] Данные совпали при неверном ключе!"; exit 1; fi
	
	@rm -rf test_edge

# ТЕСТ 3: Экстремальная нагрузка (15 файлов по 4 ГБ)
# ВНИМАНИЕ: Требует ~60 ГБ реального свободного места на диске!
test_stress: secure_copy
	@echo "\n=== Тест 3: Экстремальная нагрузка (15 файлов по 4 ГБ) ==="
	@rm -rf test_stress_env && mkdir -p test_stress_env
	@echo "[INFO] Создание 15 sparse-файлов по 4294967295 байт (максимум для uint32_t)..."
	@for i in $$(seq 1 15); do truncate -s 4294967295 test_stress_env/huge_$$i.bin; done
	@echo "[ВНИМАНИЕ] Начинается шифрование. Образ займет ~60 ГБ физического места!"
	@echo "[INFO] Это может занять от 10 минут до часа в зависимости от процессора и диска..."
	@time ./secure_copy -add -key "stresskey" -image test_stress_env/stress_vault.img test_stress_env/huge_*.bin
	@echo "\n[INFO] Проверка таблицы файлов (-list):"
	@./secure_copy -list -image test_stress_env/stress_vault.img
	@echo "\n[УСПЕХ] Стресс-тест успешно пройден!"
	@rm -rf test_stress_env

# ----------------- ОЧИСТКА -----------------

clean:
	rm -f *.o *.so secure_copy secure_copy_attack secure_copy_segfault input.txt disk.img
	rm -f stat.txt log.txt attack_out.log segfault_out.log
	rm -rf test_env test_edge test_stress_env

.PHONY: all install test_invalid_args test_security test_segfault test_all test_hash test_edge_cases test_stress clean

# Создаём тестовый файл
input.txt:
	echo "Hello, world! This is a test." > input.txt
