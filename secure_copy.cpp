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

#include "readerwriterqueue.h" 
#include "caesar.h"

const size_t BLOCK_SIZE = 4096;
// Флаг для сигналов остается volatile sig_atomic_t
volatile sig_atomic_t keep_running = 1;

void handle_sigint(int sig) {
    (void)sig;
    keep_running = 0; 
}

struct DataBlock {
    unsigned char* ptr;
    size_t size;
};

/**
 * ГЛОБАЛЬНЫЙ КОНТЕКСТ:
 * Общие данные для 3-х главных потоков.
 */
struct GlobalContext {
    std::vector<std::string> input_files;
    std::string out_dir;
    char key;
    std::atomic<size_t> file_idx{0}; 
    std::mutex log_mutex;
    std::ofstream log_file;

    GlobalContext(char k, const std::string& dir, const std::vector<std::string>& files) 
        : input_files(files), out_dir(dir), key(k) {
        log_file.open("log.txt", std::ios::app);
    }
    ~GlobalContext() {
        if (log_file.is_open()) log_file.close();
    }
};

/**
 * СТРУКТУРА КОНТЕКСТА:
 * Мы упаковываем всё, что нужно потокам, в одну структуру.
 */
struct AppContext {
    moodycamel::ReaderWriterQueue<DataBlock> queue;
    std::atomic<bool> producer_finished;
    char key;
    std::string input_filename;
    std::string output_filename;

    // Конструктор для удобной инициализации
    AppContext(char k, const std::string& in, const std::string& out) 
        : queue(128), producer_finished(false), key(k), input_filename(in), output_filename(out) {}
};

/**
 * ПОТОК 1: PRODUCER
 */
void* producer_func(void* arg) {
    // Распаковываем контекст
    AppContext* ctx = static_cast<AppContext*>(arg);
    // Передаем ключ в библиотеку
    set_key(ctx->key);

    std::ifstream infile(ctx->input_filename, std::ios::binary);

    while (keep_running && infile) {
      // Создаем буффер (фиксируем длину сообщения)
        unsigned char* buffer = new (std::nothrow) unsigned char[BLOCK_SIZE];
        if (!buffer) break;
        // пытаемся прочитать блок в наш буффер
        infile.read(reinterpret_cast<char*>(buffer), BLOCK_SIZE);
        // смотрим сколько реально прочитали
        size_t read_bytes = infile.gcount();

        if (read_bytes > 0) {
            caesar(buffer, buffer, (int)read_bytes);
            ctx->queue.enqueue({buffer, read_bytes});
        } else {
            delete[] buffer;
            if (infile.eof()) break;
        }
    }
   // Сообщаем второму потоку, что новых данных больше не будет 
    ctx->producer_finished.store(true, std::memory_order_release);
    return nullptr;
}

/**
 * ПОТОК 2: CONSUMER
 */
void* consumer_func(void* arg) {
    AppContext* ctx = static_cast<AppContext*>(arg);
    std::ofstream outfile(ctx->output_filename, std::ios::binary);

    while (true) {
        DataBlock block;
        if (ctx->queue.try_dequeue(block)) {
            outfile.write(reinterpret_cast<char*>(block.ptr), block.size);
            // пишем ровно столько байт, сколько было прочитано
            delete[] block.ptr;
            // освобождаем память выделенную первым потоком
        } else { // Если нет данных, то проверяем не закончил ли первый поток передачу
            if (ctx->producer_finished.load(std::memory_order_acquire)) {
                break;
            }
            // Очередь пуста, делать пока нечего, поэтому говорим процессору, что бездельничаем, другие могут работать
            sched_yield();
        }
    }
    return nullptr;
}

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

        // Создаем объект контекста
        AppContext ctx(gctx->key, filepath, out_filepath);

        pthread_t t1, t2;

        // Передаем АДРЕС структуры ctx в оба потока и создаём их
        pthread_create(&t1, nullptr, producer_func, &ctx);
        pthread_create(&t2, nullptr, consumer_func, &ctx);
        
        // Ждем окончания потоков, чтобы убить зомби
        pthread_join(t1, nullptr);
        pthread_join(t2, nullptr);

        if (keep_running) {
            log_message(gctx, filename);
        }
    }
    return nullptr;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <file1.txt> [file2.txt ...] <out_dir> <key_number>\n";
        return 1;
    }

    signal(SIGINT, handle_sigint); // регистрация обработчика Ctrl + c

    char key = (char)std::atoi(argv[argc - 1]);
    std::string out_dir = argv[argc - 2];
    mkdir(out_dir.c_str(), 0777);
    std::vector<std::string> input_files;
    for (int i = 1; i < argc - 2; ++i) {
        input_files.push_back(argv[i]);
    }

    GlobalContext gctx(key, out_dir, input_files);

    const int NUM_THREADS = 3;
    pthread_t workers[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; ++i) {
        pthread_create(&workers[i], nullptr, worker_func, &gctx);
    }

    for (int i = 0; i < NUM_THREADS; ++i) {
        pthread_join(workers[i], nullptr);
    }

    std::cout << "\n[OK] Secure batch copy finished. Check log.txt." << std::endl;
    return 0;
}
