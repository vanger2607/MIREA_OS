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
#include <x86intrin.h>

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

void print_stats(const std::string& mode, double total_time, unsigned long long total_ticks, size_t file_count) {
    double avg = (file_count > 0) ? total_time / file_count : 0.0;
    unsigned long long avg_ticks = (file_count > 0) ? total_ticks / file_count : 0;
    
    std::stringstream ss;
    ss << "\n=== Statistics (" << mode << ") ===\n"
       << "Files processed: " << file_count << "\n"
       << "Total time: " << total_time << " ms\n"
       << "Total ticks: " << total_ticks << "\n"
       << "Average time per file: " << avg << " ms\n"
       << "Average ticks per file: " << avg_ticks << "\n"
       << "===========================\n";

    std::cout << ss.str();
    std::ofstream stat_file("stat.txt", std::ios::app);
    if (stat_file.is_open()) {
        stat_file << ss.str();
    }
}

void print_auto_comparison(const std::string& mode, double total_time, unsigned long long total_ticks, 
                           const std::string& alt_mode, double alt_time, unsigned long long alt_ticks) {
    double parallel_time = (mode == "parallel") ? total_time : alt_time;
    double seq_time = (mode == "sequential") ? total_time : alt_time;
    
    unsigned long long parallel_ticks = (mode == "parallel") ? total_ticks : alt_ticks;
    unsigned long long seq_ticks = (mode == "sequential") ? total_ticks : alt_ticks;
    
    std::string time_comparison_result;
    if (parallel_time < seq_time) {
        time_comparison_result = "Parallel mode is faster by " + std::to_string(seq_time - parallel_time) + " ms.";
    } else {
        time_comparison_result = "Sequential mode is faster by " + std::to_string(parallel_time - seq_time) + " ms.";
    }

    std::string tick_comparison_result;
    if (parallel_ticks < seq_ticks) {
        tick_comparison_result = "Parallel mode took fewer ticks by " + std::to_string(seq_ticks - parallel_ticks) + " ticks.";
    } else {
        tick_comparison_result = "Sequential mode took fewer ticks by " + std::to_string(parallel_ticks - seq_ticks) + " ticks.";
    }

    std::stringstream ss;
    ss << "\n[Auto Mode Comparison Table]\n"
       << std::left << std::setw(15) << "Mode" 
       << std::setw(20) << "Total Time (ms)" 
       << std::setw(20) << "Total Ticks\n"
       << "------------------------------------------------------\n"
       << std::left << std::setw(15) << mode << std::setw(20) << total_time << total_ticks << "\n"
       << std::left << std::setw(15) << alt_mode << std::setw(20) << alt_time << alt_ticks << "\n"
       << "------------------------------------------------------\n"
       << time_comparison_result << "\n"
       << tick_comparison_result << "\n";
       
    std::cout << ss.str();
    
    std::ofstream stat_file("stat.txt", std::ios::app);
    if (stat_file.is_open()) {
        stat_file << ss.str();
    }
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

    std::string mode = "auto";
    int start_idx = 1;

    // Парсим режим
    if (argc > 1 && strncmp(argv[1], "--mode=", 7) == 0) {
        mode = argv[1] + 7;
        start_idx = 2;
        if (mode != "sequential" && mode != "parallel") {
            std::cerr << "Error: Invalid mode. Введите верное значение режима (--mode=sequential или --mode=parallel)\n";
            return 1;
        }
    }

    if (argc - start_idx < 3) {
        std::cerr << "Usage: " << argv[0] << " [--mode=sequential|parallel] <file1.txt> [file2.txt ...] <out_dir> <key_number>\n";
        return 1;
    }

    std::string out_dir = argv[argc - 2];
    mkdir(out_dir.c_str(), 0777);
    std::vector<std::string> input_files;

    for (int i = start_idx; i < argc - 2; ++i) {
        input_files.push_back(argv[i]);
    }

    // Выделение защищенной памяти
    global_secure_memory_pointer = mmap(NULL, SECURE_MEMORY_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (global_secure_memory_pointer == MAP_FAILED) {
        perror("Ошибка выделения защищенной памяти (mmap)");
        return 1;
    }

    // Запись распарсенного ключа напрямую в защищенную область
    *(volatile char*)global_secure_memory_pointer = (char)std::atoi(argv[argc - 1]);
    
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
    GlobalContext gctx(out_dir, input_files);

    bool is_auto = (mode == "auto");
    if (is_auto) {
        mode = (input_files.size() < 5) ? "sequential" : "parallel";
    }

    int num_threads = (mode == "parallel") ? MAX_COUNT : 1;

    // --- Запускаем таймер для основного прогона ---
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    unsigned long long start_ticks = __rdtsc();

    if (num_threads == 1) {
        worker_func(&gctx); // Без накладных расходов pthread
    } else {
        pthread_t workers[MAX_COUNT];
        for (int i = 0; i < num_threads; ++i) {
            pthread_create(&workers[i], nullptr, worker_func, &gctx);
        }
        for (int i = 0; i < num_threads; ++i) {
            pthread_join(workers[i], nullptr);
        }
    }

    // --- Останавливаем таймер и выводим статистику ---
    unsigned long long end_ticks = __rdtsc();
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double total_time = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1000000.0;
    unsigned long long total_ticks = end_ticks - start_ticks;
    print_stats(mode, total_time, total_ticks, input_files.size());

    // --- Блок для автоматического сравнения ---
    if (is_auto && keep_running) {
        gctx.file_idx = 0; // Сбрасываем очередь файлов
        std::string alt_mode = (mode == "parallel") ? "sequential" : "parallel";
        int alt_threads = (alt_mode == "parallel") ? MAX_COUNT : 1;

        struct timespec alt_start, alt_end;
        clock_gettime(CLOCK_MONOTONIC, &alt_start);
        unsigned long long alt_start_ticks = __rdtsc();

        if (alt_threads == 1) {
            worker_func(&gctx);
        } else {
            pthread_t workers[MAX_COUNT];
            for (int i = 0; i < alt_threads; ++i) {
                pthread_create(&workers[i], nullptr, worker_func, &gctx);
            }
            for (int i = 0; i < alt_threads; ++i) {
                pthread_join(workers[i], nullptr);
            }
        }
        unsigned long long alt_end_ticks = __rdtsc();
        clock_gettime(CLOCK_MONOTONIC, &alt_end);
        double alt_time = (alt_end.tv_sec - alt_start.tv_sec) * 1000.0 + (alt_end.tv_nsec - alt_start.tv_nsec) / 1000000.0;
        unsigned long long alt_ticks = alt_end_ticks - alt_start_ticks;

        print_auto_comparison(mode, total_time, total_ticks, alt_mode, alt_time, alt_ticks);
    }

    // Очистка при нормальном завершении программы
    cleanup_secure_memory();

    std::cout << "\n[OK] Secure batch copy finished. Check log.txt and stat.txt." << std::endl;
    return 0;
}
