#include <iostream>
#include <fstream>
#include <pthread.h>
#include <csignal>
#include <unistd.h>
#include <sched.h>
#include <cstdlib>
#include <atomic>

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
 * СТРУКТУРА КОНТЕКСТА:
 * Мы упаковываем всё, что нужно потокам, в одну структуру.
 */
struct AppContext {
    moodycamel::ReaderWriterQueue<DataBlock> queue;
    std::atomic<bool> producer_finished;
    char key;
    const char* output_filename;

    // Конструктор для удобной инициализации
    AppContext(char k, const char* out) 
        : queue(128), producer_finished(false), key(k), output_filename(out) {}
};

/**
 * ПОТОК 1: PRODUCER
 */
void* producer_func(void* arg) {
    // Распаковываем контекст
    AppContext* ctx = static_cast<AppContext*>(arg);
    
    // Передаем ключ в библиотеку
    set_key(ctx->key);

    while (keep_running) {
      // Создаем буффер (фиксируем длину сообщения)
        unsigned char* buffer = new (std::nothrow) unsigned char[BLOCK_SIZE];
        if (!buffer) break;
        // пытаемся прочитать блок в наш буффер
        std::cin.read(reinterpret_cast<char*>(buffer), BLOCK_SIZE);
        // смотрим сколько реально прочитали
        size_t read_bytes = std::cin.gcount();

        if (read_bytes > 0) {
            caesar(buffer, buffer, (int)read_bytes);
            ctx->queue.enqueue({buffer, read_bytes});
        } else {
            delete[] buffer;
            if (std::cin.eof()) break;
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
            outfile.write(reinterpret_cast<char*>(block.ptr), block.size); // пишем ровно столько байт, сколько было прочитано
            delete[] block.ptr; // освобождаем память выделенную первым потоком
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

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <output_file> <key_number>" << std::endl;
        return 1;
    }

    signal(SIGINT, handle_sigint); // регистрация обработчика Ctrl + c

    // Создаем объект контекста
    char key = (char)std::atoi(argv[2]);
    AppContext ctx(key, argv[1]);

    pthread_t t1, t2;

    // Передаем АДРЕС структуры ctx в оба потока и создаём их
    pthread_create(&t1, nullptr, producer_func, &ctx);
    pthread_create(&t2, nullptr, consumer_func, &ctx);
    // Ждем окончания потоков, чтобы убить зомби
    pthread_join(t1, nullptr);
    pthread_join(t2, nullptr);

    std::cout << "\n[OK] Secure copy finished." << std::endl;
    return 0;
}

