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

#include "caesar.h"

const size_t BLOCK_SIZE = 4096;
const int MAX_COUNT = 4;
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

/**
 * ГЛОБАЛЬНЫЙ КОНТЕКСТ:
 * Общие данные для главных потоков.
 */
struct GlobalContext {
    std::vector<std::string> input_files;
    std::string out_dir;
    std::mutex key_access_mutex; // Мьютекс для синхронизации изменения прав доступа
    std::atomic<size_t> file_idx{0}; 
    std::mutex log_mutex;
    std::ofstream log_file;

    GlobalContext(const std::string& dir, const std::vector<std::string>& files) 
        : input_files(files), out_dir(dir) {
        log_file.open("log.txt", std::ios::app);
    }
    ~GlobalContext() {
        if (log_file.is_open()) log_file.close();
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
void* worker_func(void* arg) {
    GlobalContext* gctx = static_cast<GlobalContext*>(arg);

    while (keep_running) {
        size_t idx = gctx->file_idx.fetch_add(1, std::memory_order_relaxed);
        if (idx >= gctx->input_files.size()) {
            break;
        }
        std::string filepath = gctx->input_files[idx];
        std::string filename = filepath;
        size_t slash_pos = filepath.find_last_of("/\\");
        if (slash_pos != std::string::npos) {
            filename = filepath.substr(slash_pos + 1);
        }
        std::string out_filepath = gctx->out_dir + "/" + filename;

        std::ifstream infile(filepath, std::ios::binary);
        if (!infile) {
            std::cerr << "\n[ERROR] Файл не существует или недоступен: " << filepath << "\n";
            std::cerr << "Аварийное завершение программы.\n";
            cleanup_secure_memory(); // Очищаем память перед аварийным выходом
            exit(EXIT_FAILURE); 
        }
        std::ofstream outfile(out_filepath, std::ios::binary);

        if (infile && outfile) {
            // Создаем буффер (фиксируем длину сообщения)
            unsigned char buffer[BLOCK_SIZE];
            while (keep_running && infile) {
                // пытаемся прочитать блок в наш буффер
                infile.read(reinterpret_cast<char*>(buffer), BLOCK_SIZE);
                // смотрим сколько реально прочитали
                size_t read_bytes = infile.gcount();
                if (read_bytes > 0) {
                    
                    // --- КРИТИЧЕСКАЯ СЕКЦИЯ ШИФРОВАНИЯ ---
                    gctx->key_access_mutex.lock(); 

                    // 1. Открываем защищенную память только для чтения
                    if (mprotect(global_secure_memory_pointer, SECURE_MEMORY_SIZE, PROT_READ) == -1) {
                        perror("Ошибка mprotect (разрешение чтения)");
                        cleanup_secure_memory();
                        exit(EXIT_FAILURE);
                    }
                    
                    // 2. Передаем указатель в библиотеку
                    caesar(buffer, buffer, (int)read_bytes, (volatile char*)global_secure_memory_pointer);
                    
                    // 3. Закрываем доступ
                    if (mprotect(global_secure_memory_pointer, SECURE_MEMORY_SIZE, PROT_NONE) == -1) {
                        perror("Ошибка mprotect (запрет доступа)");
                        cleanup_secure_memory();
                        exit(EXIT_FAILURE);
                    }

                    gctx->key_access_mutex.unlock();
                    // --- КОНЕЦ КРИТИЧЕСКОЙ СЕКЦИИ ---

                    // пишем ровно столько байт, сколько было прочитано
                    outfile.write(reinterpret_cast<char*>(buffer), read_bytes);
                }
            }
        }

        if (keep_running) {
            log_message(gctx, filename);
        }
    }
    return nullptr;
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
    std::vector<std::string> input_files;

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
        input_files.push_back(argv[i]);
    }

    // Валидация обязательных параметров
    bool valid = true;
    if (mode.empty() || image_file.empty()) valid = false;
    if (mode == "-add" && (key_str.empty() || input_files.empty())) valid = false;
    if (mode == "-get" && (key_str.empty() || input_files.empty() || out_file.empty())) valid = false;
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
    GlobalContext gctx(image_file, input_files);


    int num_threads = MAX_COUNT;

        pthread_t workers[MAX_COUNT];
        for (int i = 0; i < num_threads; ++i) {
            pthread_create(&workers[i], nullptr, worker_func, &gctx);
        }
        for (int i = 0; i < num_threads; ++i) {
            pthread_join(workers[i], nullptr);
        }
    // Очистка при нормальном завершении программы
    cleanup_secure_memory();

    std::cout << "\n[OK] Secure batch copy finished. Check log.txt and stat.txt." << std::endl;
    return 0;
}
