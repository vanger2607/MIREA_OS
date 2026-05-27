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

# ----------------- ТЕСТЫ -----------------

# ТЕСТ: Проверка защиты памяти (Имитация атаки с выводом логов)
test_security: secure_copy_attack input.txt
	@echo "\n=== Проверка защиты памяти (Ожидается SIGSEGV и перехват) ==="
	@echo "--- НАЧАЛО ВЫВОДА ПРОГРАММЫ ---"
	@./secure_copy_attack -add -key "secret" -image disk.img input.txt 2>&1 | tee attack_out.log || true
	@echo "--- КОНЕЦ ВЫВОДА ПРОГРАММЫ ---"
	@if grep -q "SECURITY ERROR" attack_out.log; then \
		echo "\n[УСПЕХ] Попытка взлома успешно перехвачена обработчиком!"; \
	else \
		echo "\n[ОШИБКА] Защита не сработала или получено неверное сообщение!"; exit 1; \
	fi
	@rm -f secure_copy_attack attack_out.log disk.img

# ТЕСТ: Проверка различения ошибок (Обычный SEGFAULT)
test_segfault: secure_copy_segfault input.txt
	@echo "\n=== Проверка различения ошибок (Ожидается обычный SEGFAULT) ==="
	@echo "--- НАЧАЛО ВЫВОДА ПРОГРАММЫ ---"
	@./secure_copy_segfault -add -key "secret" -image disk.img input.txt 2>&1 | tee segfault_out.log || true
	@echo "--- КОНЕЦ ВЫВОДА ПРОГРАММЫ ---"
	@if grep -q "SEGFAULT ERROR" segfault_out.log; then \
		echo "\n[УСПЕХ] Обработчик верно распознал обычную ошибку памяти!"; \
	else \
		echo "\n[ОШИБКА] Обработчик не распознал ошибку или перепутал её с атакой!"; exit 1; \
	fi
	@rm -f secure_copy_segfault segfault_out.log disk.img

# ТЕСТ: Проверка правильного падения при отсутствии обязательных аргументов
test_invalid_args: all
	@echo "\n=== Проверка падения при неверных аргументах ==="
	@if ./secure_copy -add input.txt 2>/dev/null; then \
		echo "[ОШИБКА] Программа не упала при отсутствии образа и ключа!"; exit 1; \
	else \
		echo "[УСПЕХ] Программа штатно завершилась с ошибкой Usage (как и ожидалось)."; \
	fi

# ----------------- ОЧИСТКА -----------------

clean:
	rm -f *.o *.so secure_copy secure_copy_attack secure_copy_segfault input.txt disk.img
	rm -f stat.txt log.txt attack_out.log segfault_out.log

.PHONY: all install test_invalid_args test_security test_segfault clean

# Создаём тестовый файл
input.txt:
	echo "Hello, world! This is a test." > input.txt
