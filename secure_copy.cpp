#include <iostream>
#include <fstream>
#include <pthread.h>
#include <csignal>
#include <unistd.h>
#include <sched.h>
#include <cstdlib>
#include <atomic>
#include <string>
#include <vector>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <sys/stat.h>
#include <cstring> 
#include <time.h> // Для clock_gettime
#include <getopt.h>

#include <sys/mman.h>  // Для хранения ключа и безопасного выделения памяти
#include <signal.h>
#include <random>

#include <fcntl.h> // Для O_WRONLY, O_CREAT
#include "rc4.h" 
#include <filesystem>
#include <sys/file.h> // Для функции flock

namespace fs = std::filesystem;

const size_t BLOCK_SIZE = 4096;
const int MAX_COUNT = 5;
// Флаг для сигналов остается volatile sig_atomic_t
volatile sig_atomic_t keep_running = 1;

// Глобальные переменные для защищенной памяти
void* global_secure_memory_pointer = nullptr; 
const size_t SECURE_MEMORY_SIZE = 16;

/*
 Функция для окончательного уничтожения данных в памяти.
 */
void cleanup_secure_memory() {
    if (global_secure_memory_pointer != nullptr) {
        // Снимаем защиту, чтобы иметь возможность записать нули
        if (mprotect(global_secure_memory_pointer, SECURE_MEMORY_SIZE, PROT_READ | PROT_WRITE) == -1) {
            perror("Ошибка снятия защиты при финальной очистке памяти");
        }
        // Затираем данные
        memset(global_secure_memory_pointer, 0, SECURE_MEMORY_SIZE);
        // Освобождаем ресурс
        munmap(global_secure_memory_pointer, SECURE_MEMORY_SIZE);
        global_secure_memory_pointer = nullptr;
    }
}

/*
 Обработчик ошибок сегментации (SIGSEGV).
    Он проверяет, произошло ли нарушение доступа в защищенной области памяти, 
    и выводит соответствующее сообщение.
 */
void handle_sigsegv(int signal_number, siginfo_t *signal_information, void *context) {
    (void)signal_number;
    (void)context;

    uintptr_t fault_address = reinterpret_cast<uintptr_t>(signal_information->si_addr);
    uintptr_t secure_start = reinterpret_cast<uintptr_t>(global_secure_memory_pointer);
    uintptr_t secure_end = secure_start + SECURE_MEMORY_SIZE;

    if (global_secure_memory_pointer != nullptr && fault_address >= secure_start && fault_address < secure_end) {
        std::cerr << "\n[SECURITY ERROR] Попытка модификации защищенного ключа!\n";
    } else {
        std::cerr << "\n[SEGFAULT ERROR] Обычная ошибка доступа к памяти.\n";
    }
    
    // Затираем ключ
    cleanup_secure_memory();
    
    std::cerr << "Ресурсы очищены. Аварийное завершение.\n";
    exit(EXIT_FAILURE); 
}

void handle_sigint(int sig) {
    (void)sig;
    keep_running = 0; 
}

#include <random>

// Функция генерации криптографической соли
void generate_salt(unsigned char* salt, size_t length = 16) {
    // std::random_device запрашивает энтропию напрямую у операционной системы
    std::random_device rd;
    
    // std::mt19937 — это алгоритм "Вихрь Мерсенна" (Mersenne Twister),
    std::mt19937 gen(rd());
    
    // Настраиваем равномерное распределение, чтобы каждое число было в диапазоне 0 до 255 
    // (значение одного байта) выпадало с одинаковой вероятностью
    std::uniform_int_distribution<> dis(0, 255);
    
    for (size_t i = 0; i < length; ++i) {
        salt[i] = static_cast<unsigned char>(dis(gen));
    }
}


// Размер строго 24 байта (4 + 4 + 16).
#pragma pack(push, 1)
struct ContainerHeader {
    uint32_t file_length;
    uint32_t name_length;
    unsigned char salt[16];
};
#pragma pack(pop)

// Структура для хранения путей к файлу
struct FileInfo {
    std::string archive_name; // Относительный путь для сохранения в архиве (напр. "dir/file.txt")
    std::string real_path;    // Абсолютный/реальный путь на диске для чтения
};
/**
 * ГЛОБАЛЬНЫЙ КОНТЕКСТ:
 * Общие данные для главных потоков.
 */
struct GlobalContext {
    std::vector<FileInfo> input_files;
    int out_fd; // Дескриптор для выходного образа

    std::mutex write_mutex;      // Мьютекс для безопасного бронирования места в образе
    std::mutex key_access_mutex; // Мьютекс для синхронизации изменения прав доступа
    std::atomic<size_t> file_idx{0}; 
    std::mutex log_mutex;
    std::ofstream log_file;

    GlobalContext(int fd, const std::vector<FileInfo>& files) 
        : input_files(files), out_fd(fd) {
        log_file.open("log.txt", std::ios::app);
    }
    ~GlobalContext() {
        if (log_file.is_open()) log_file.close();
        if (out_fd >= 0) close(out_fd); // Гарантированное закрытие образа
    }
};

// Потокобезопасное логирование с try_lock
void log_message(GlobalContext* gctx, const std::string& filename) {
    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    
    ss << "[" << std::put_time(std::localtime(&now_c), "%Y-%m-%d %H:%M:%S") << "] "
       << "[PID: " << gettid() << "] "
       << "Processed file: " << filename << "\n";

    while (keep_running) {
        if (gctx->log_mutex.try_lock()) {
            if (gctx->log_file.is_open()) {
                gctx->log_file << ss.str();
                gctx->log_file.flush();
            }
            gctx->log_mutex.unlock();
            break;
        } else {
            sched_yield();
        }
    }
}

/**
 * ВЕРХНИЙ ПОТОК (ВОРКЕР)
 */
void* worker_func_add(void* arg) {
    GlobalContext* gctx = static_cast<GlobalContext*>(arg);
    size_t PAGE_SIZE = sysconf(_SC_PAGESIZE); // Получаем размер страницы для выделения организации доступа к защищенной памяти
    // Выделяем изолированную страницу памяти для состояния шифра (S-блока)
    void* local_secure_state = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (local_secure_state == MAP_FAILED) return nullptr;
    
    volatile RC4_State* state = static_cast<volatile RC4_State*>(local_secure_state);
    while (keep_running) {
        size_t idx = gctx->file_idx.fetch_add(1, std::memory_order_relaxed);
        if (idx >= gctx->input_files.size()) {
            break;
        }
        FileInfo file = gctx->input_files[idx];

        // Узнаем размер исходного файла
        struct stat st;
        if (stat(file.real_path.c_str(), &st) != 0) {
            std::cerr << "[WARNING] Пропущен файл (ошибка доступа): " << file.real_path << "\n";
            continue;
        }

        // Защита от переполнения 32-битного заголовка (файлы > 4 ГБ)
        if (st.st_size > UINT32_MAX) {
            std::cerr << "[WARNING] Пропущен файл (превышен лимит 4 ГБ): " << file.real_path << "\n";
            continue;
        }

        uint32_t file_len = static_cast<uint32_t>(st.st_size);
        uint32_t name_len = static_cast<uint32_t>(file.archive_name.length());
        
        // Генерируем соль для файла
        unsigned char salt[16];
        generate_salt(salt);
        // --- КРИТИЧЕСКАЯ СЕКЦИЯ 1: Инициализация шифра ---
        gctx->key_access_mutex.lock(); 
        
        mprotect(global_secure_memory_pointer, SECURE_MEMORY_SIZE, PROT_READ); 
        mprotect(local_secure_state, PAGE_SIZE, PROT_READ | PROT_WRITE);       
        
        size_t actual_key_len = strlen((const char*)global_secure_memory_pointer);
        rc4_init(state, (const unsigned char*)global_secure_memory_pointer, actual_key_len, salt, 16);
        
        mprotect(local_secure_state, PAGE_SIZE, PROT_NONE);                    
        mprotect(global_secure_memory_pointer, SECURE_MEMORY_SIZE, PROT_NONE); 
        
        gctx->key_access_mutex.unlock();
        // --- КОНЕЦ КРИТИЧЕСКОЙ СЕКЦИИ 1 ---
        // --- КРИТИЧЕСКАЯ СЕКЦИЯ 2: Бронирование места в образе ---
        off_t data_offset = 0;
        gctx->write_mutex.lock(); // Блокируем запись в образ для других потоков
        
        // Смотрим, где сейчас конец файла-образа
        off_t current_eof = lseek(gctx->out_fd, 0, SEEK_END);
        
        // Собираем заголовок файла
        ContainerHeader header = {file_len, name_len, {0}};
        memcpy(header.salt, salt, 16);
        
        // Пишем Заголовок и Имя файла в конец образа
        write(gctx->out_fd, &header, sizeof(header));
        write(gctx->out_fd, file.archive_name.c_str(), name_len);
        
        // Вычисляем, куда именно этот поток будет писать зашифрованные данные
        data_offset = current_eof + sizeof(header) + name_len;
        
        // Резервируем место под данные на диске (чтобы потоки не перемешали байты)
        if (ftruncate(gctx->out_fd, data_offset + file_len) == -1) {
            std::cerr << "\n[CRITICAL ERROR] Не удалось выделить место на диске для " << file.archive_name << "\n";
            gctx->write_mutex.unlock();
            keep_running = 0; // Тормозим всю программу
            continue;
        }
        
        gctx->write_mutex.unlock(); // Отпускаем образ для других потоков
        // --- КОНЕЦ КРИТИЧЕСКОЙ СЕКЦИИ 2 ---


        // 3. Асинхронное чтение, шифрование и запись (БЕЗ мьютексов)
        int fd_in = open(file.real_path.c_str(), O_RDONLY);
        if (fd_in >= 0) {
            unsigned char buffer[BLOCK_SIZE];
            off_t write_cursor = data_offset; // Начинаем писать с забронированного места
            
            while (keep_running) {
                // Читаем блок из исходного файла
                ssize_t bytes = read(fd_in, buffer, BLOCK_SIZE);
                if (bytes <= 0) break; // Файл закончился

                // Открываем локальный S-блок, шифруем и сразу закрываем
                mprotect(local_secure_state, PAGE_SIZE, PROT_READ | PROT_WRITE);
                rc4_crypt(state, buffer, bytes);
                mprotect(local_secure_state, PAGE_SIZE, PROT_NONE);

                // Пишем зашифрованный блок в образ строго по своему смещению (write_cursor)
                pwrite(gctx->out_fd, buffer, bytes, write_cursor);
                write_cursor += bytes; // Сдвигаем курсор для следующего блока
            }
            close(fd_in);
            
            log_message(gctx, file.archive_name);
        }
    }
    mprotect(local_secure_state, PAGE_SIZE, PROT_READ | PROT_WRITE);
    memset(local_secure_state, 0, PAGE_SIZE); // Затираем пароли нулями
    munmap(local_secure_state, PAGE_SIZE);

    return nullptr;
}


/**
 * Формирует список файлов для архивации на основе переданных путей.
 * Разворачивает директории рекурсивно, вычисляя корректные относительные пути 
 * для записи в заголовок архива, сохраняя структуру вложенности.
 */
std::vector<FileInfo> build_archive_manifest(const std::vector<std::string>& raw_paths) {
    std::vector<FileInfo> manifest;
    
    for (const std::string& input_path : raw_paths) {
        // 1. Очищаем путь от случайного слэша на конце
        std::string clean_path = input_path;
        if (!clean_path.empty() && (clean_path.back() == '/' || clean_path.back() == '\\')) {
            clean_path.pop_back();
        }
        
        fs::path p(clean_path);
        std::error_code ec; // Объект для безопасного перехвата ошибок ФС
        
        // 2. Базовая проверка существования
        if (!fs::exists(p, ec)) {
            std::cerr << "[WARNING] Путь не существует или недоступен: " << input_path << "\n";
            continue;
        }

        if (fs::is_regular_file(p, ec)) {
            // Проверка прав на чтение (POSIX)
            if (access(p.c_str(), R_OK) != 0) {
                std::cerr << "[WARNING] Нет прав на чтение файла: " << input_path << "\n";
                continue;
            }
            
            std::string archive_name = "/" + p.relative_path().generic_string();
            manifest.push_back({archive_name, p.string()});
        } 
        else if (fs::is_directory(p, ec)) {
            // Запускаем безопасный итератор, который сам игнорирует запретные папки
            auto options = fs::directory_options::skip_permission_denied;
            
            for (const auto& entry : fs::recursive_directory_iterator(p, options)) {
                std::error_code entry_ec;
                
                // Пропускаем символические ссылки, сокеты, пайпы и устройства (/dev/*)
                if (fs::is_regular_file(entry, entry_ec)) {
                    
                    // Проверка прав на чтение конкретного вложенного файла
                    if (access(entry.path().c_str(), R_OK) != 0) {
                        std::cerr << "[WARNING] Нет прав на чтение файла: " << entry.path().string() << "\n";
                        continue;
                    }
                    
                    std::string archive_name = "/" + entry.path().relative_path().generic_string();
                    manifest.push_back({archive_name, entry.path().string()});
                }
            }
        } 
        else {
            // Сюда попадут сокеты, именованные каналы (FIFO) и блочные/символьные устройства
            std::cerr << "[WARNING] Игнорируется специальный или системный файл: " << input_path << "\n";
        }
    }
    
    return manifest;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, handle_sigint); // регистрация обработчика Ctrl + c
    
    // Регистрация расширенного обработчика ошибок сегментации 
    struct sigaction signal_action;
    signal_action.sa_flags = SA_SIGINFO; 
    sigemptyset(&signal_action.sa_mask);
    signal_action.sa_sigaction = handle_sigsegv;
    if (sigaction(SIGSEGV, &signal_action, NULL) == -1) {
        perror("Ошибка при регистрации обработчика SIGSEGV");
        cleanup_secure_memory();
        return 1;
    }
    std::string mode = "";
    std::string key_str = "";
    std::string image_file = "";
    std::string out_file = "";
    std::string target_file = "";
    std::vector<std::string> raw_input_files;

    struct option long_options[] = {
        {"add",   no_argument,       0, 'a'},
        {"list",  no_argument,       0, 'l'},
        {"get",   no_argument,       0, 'g'},
        {"key",   required_argument, 0, 'k'},
        {"image", required_argument, 0, 'i'},
        {"out",   required_argument, 0, 'o'},
        {0, 0, 0, 0}
    };
    int opt;
    int option_index = 0;
    
    // Парсинг флагов
    while ((opt = getopt_long_only(argc, argv, "", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'a': mode = "-add"; break;
            case 'l': mode = "-list"; break;
            case 'g': mode = "-get"; break;
            case 'k': key_str = optarg; break; // optarg - это встроенная переменная, содержащая значение аргумента
            case 'i': image_file = optarg; break;
            case 'o': out_file = optarg; break;
            case '?': 
                // getopt_long_only сама выведет ошибку, если флаг неизвестен или пропущен аргумент
                return 1;
        }
    }

    // Сбор свободных аргументов (позиционных), которые идут без флагов (file1.txt, dir/ и т.д.)
    // После работы getopt_long_only, индекс optind указывает на первый свободный аргумент
    for (int i = optind; i < argc; ++i) {
        raw_input_files.push_back(argv[i]);
    }

    // Валидация обязательных параметров
    bool valid = true;
    if (mode.empty() || image_file.empty()) valid = false;
    if (mode == "-add" && (key_str.empty() || raw_input_files.empty())) valid = false;
    if (mode == "-get" && (key_str.empty() || raw_input_files.empty() || out_file.empty())) valid = false;
    if (mode == "-list" && !key_str.empty()) valid = false; // Для list ключ не нужен

    if (!valid) {
        std::cerr << "Usage:\n"
                  << "  " << argv[0] << " -add -key <secret> -image <disk.img> <file1.txt> [file2.txt...] [dir/]\n"
                  << "  " << argv[0] << " -list -image <disk.img>\n"
                  << "  " << argv[0] << " -get -key <secret> -image <disk.img> -out <result_file> <file_name>\n";
        return 1;
    }
    // Выделение защищенной памяти
    global_secure_memory_pointer = mmap(NULL, SECURE_MEMORY_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (global_secure_memory_pointer == MAP_FAILED) {
        perror("Ошибка выделения защищенной памяти (mmap)");
        return 1;
    }
    if (!key_str.empty()) {
        size_t max_len = SECURE_MEMORY_SIZE - 1;
        
        if (key_str.length() > max_len) {
            std::cerr << "[WARNING] Введенный ключ слишком длинный (" << key_str.length() 
                      << " байт). Он будет обрезан до " << max_len << " байт для обеспечения безопасности памяти.\n";
        }
        
        size_t copy_len = std::min(key_str.length(), max_len);
        std::memcpy(global_secure_memory_pointer, key_str.c_str(), copy_len);
        ((char*)global_secure_memory_pointer)[copy_len] = '\0';
    }
    // Установка защиты "Полная блокировка" (ни чтения, ни записи)
    if (mprotect(global_secure_memory_pointer, SECURE_MEMORY_SIZE, PROT_NONE) == -1) {
        perror("Ошибка установки защиты памяти (mprotect PROT_NONE)");
        return 1;
    }

    // --- БЛОК СИМУЛЯЦИИ АТАКИ ---
#ifdef SIMULATE_ATTACK
    std::cout << "\n[ATTACK] Симуляция атаки: попытка несанкционированной записи в защищенную память...\n";
    *(volatile char*)global_secure_memory_pointer = 'X';
#endif
    // --- КОНЕЦ БЛОКА СИМУЛЯЦИИ АТАКИ ---
    // --- БЛОК СИМУЛЯЦИИ ОБЫЧНОГО SEGFAULT ---
    #ifdef SIMULATE_SEGFAULT
        std::cout << "\n[SEGFAULT] Симуляция обычной ошибки: разыменование нулевого указателя...\n";
        volatile char* bad_pointer = nullptr;
        *bad_pointer = 'X'; // Спровоцирует обычный SIGSEGV (адрес 0x0)
    #endif
    // --- КОНЕЦ БЛОКА СИМУЛЯЦИИ ОБЫЧНОГО SEGFAULT ---
    // --- МАРШРУТИЗАЦИЯ ПО РЕЖИМАМ ---
    if (mode == "-add") {
        
        std::vector<FileInfo> parsed_files = build_archive_manifest(raw_input_files);

        if (parsed_files.empty()) {
            std::cerr << "Нет файлов для добавления. Завершение.\n";
            cleanup_secure_memory();
            return 1;
        }

        // 2. Открываем образ контейнера (0600 - доступ ТОЛЬКО владельцу)
        int fd = open(image_file.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (fd < 0) {
            perror("Ошибка открытия образа");
            cleanup_secure_memory();
            return 1;
        }

        // 3. Блокировка файла от других процессов (File Lock)
        if (flock(fd, LOCK_EX | LOCK_NB) == -1) {
            std::cerr << "[ERROR] Файл образа '" << image_file << "' уже занят другой программой!\n";
            close(fd);
            cleanup_secure_memory();
            return 1;
        }

        // 4. Инициализация Глобального контекста и запуск воркеров
        GlobalContext gctx(fd, parsed_files);
        
        pthread_t workers[MAX_COUNT];
        for (int i = 0; i < MAX_COUNT; ++i) {
            pthread_create(&workers[i], nullptr, worker_func_add, &gctx); 
        }
        for (int i = 0; i < MAX_COUNT; ++i) {
            pthread_join(workers[i], nullptr);
        }
        
    } else if (mode == "-list") {
        std::cout << "Режим -list будет реализован на следующем шаге.\n";
    } else if (mode == "-get") {
        std::cout << "Режим -get будет реализован на следующем шаге.\n";
    }
    // Очистка при нормальном завершении программы
    cleanup_secure_memory();

    std::cout << "\n[OK] Secure batch copy finished. Check log.txt and stat.txt." << std::endl;
    return 0;
}
