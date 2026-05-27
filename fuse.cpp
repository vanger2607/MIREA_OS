#define FUSE_USE_VERSION 31

#include <fuse.h>
#include <iostream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cstring>
#include <sys/mman.h>

#include "secure_types.h"
#include "rc4.h"

const size_t SECURE_MEMORY_SIZE = 257;

// Глобальный контекст, который мы передадим демону FUSE
struct MountContext {
    std::string image_path;
    std::unordered_map<std::string, VirtualFile> vfs; // Словарь всех файлов
    void* secure_key_ptr = nullptr;
    size_t key_len = 0;
};

// Функция-помощник для получения нашего контекста внутри коллбэков FUSE
MountContext* get_context() {
    return static_cast<MountContext*>(fuse_get_context()->private_data);
}

// ---------------------------------------------------------
// 1. ПОСТРОЕНИЕ ВИРТУАЛЬНОЙ ФАЙЛОВОЙ СИСТЕМЫ ПРИ СТАРТЕ
// ---------------------------------------------------------
bool build_virtual_fs(MountContext& ctx) {
    int fd = open(ctx.image_path.c_str(), O_RDONLY);
    if (fd < 0) {
        perror("[ERROR] Не удалось открыть образ диска");
        return false;
    }

    struct stat st;
    fstat(fd, &st);
    off_t file_size = st.st_size;
    off_t current_offset = 0;

    std::cout << "[INFO] Построение VFS в оперативной памяти...\n";

    while (current_offset + (off_t)sizeof(ContainerHeader) <= file_size) {
        ContainerHeader header;
        ssize_t bytes = read(fd, &header, sizeof(ContainerHeader));
        if (bytes != sizeof(ContainerHeader)) break;

        if (header.name_length == 0 || header.name_length > Config::MAX_PATH_LEN) break;

        current_offset += sizeof(ContainerHeader);

        std::string filename(header.name_length, '\0');
        read(fd, &filename[0], header.name_length);
        current_offset += header.name_length;

        // Сохраняем физическое смещение зашифрованных данных файла
        VirtualFile vfile;
        vfile.size = header.file_length;
        std::memcpy(vfile.salt, header.salt, 16);
        vfile.data_offset = current_offset; 

        ctx.vfs[filename] = vfile;

        current_offset += header.file_length;
        lseek(fd, current_offset, SEEK_SET);
    }

    close(fd);
    std::cout << "[OK] VFS построена. Индексировано файлов: " << ctx.vfs.size() << "\n";
    return true;
}

// ---------------------------------------------------------
// 2. FUSE: ПОЛУЧЕНИЕ АТРИБУТОВ ФАЙЛА/ПАПКИ (getattr)
// ---------------------------------------------------------
static int fs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    (void) fi;
    MountContext* ctx = get_context();
    memset(stbuf, 0, sizeof(struct stat));
    std::string spath(path);

    // 1. Запрос на корень архива
    if (spath == "/") {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        return 0;
    }

    // 2. Запрос на конкретный файл (точное совпадение в VFS)
    auto it = ctx->vfs.find(spath);
    if (it != ctx->vfs.end()) {
        stbuf->st_mode = S_IFREG | 0444; // Read-only file
        stbuf->st_nlink = 1;
        stbuf->st_size = it->second.size; // Выдаем реальный размер из памяти
        return 0;
    }

    // 3. А может это виртуальная директория? (например, запрашивают "/level1")
    // Проверяем, есть ли в VFS файлы, путь которых начинается с "/level1/"
    std::string dir_prefix = spath + "/";
    for (const auto& pair : ctx->vfs) {
        if (pair.first.find(dir_prefix) == 0) {
            stbuf->st_mode = S_IFDIR | 0755;
            stbuf->st_nlink = 2;
            return 0;
        }
    }

    return -ENOENT; // Такого пути нет
}

// ---------------------------------------------------------
// 3. FUSE: ЧТЕНИЕ СОДЕРЖИМОГО ДИРЕКТОРИИ (readdir)
// ---------------------------------------------------------
static int fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
    (void) offset; (void) fi; (void) flags;
    MountContext* ctx = get_context();
    std::string req_path(path);
    if (req_path != "/") req_path += "/";

    filler(buf, ".", NULL, 0, (fuse_fill_dir_flags)0);
    filler(buf, "..", NULL, 0, (fuse_fill_dir_flags)0);

    std::unordered_set<std::string> listed_entries;

    // Бежим по всем файлам и ищем те, что лежат в запрошенной папке
    for (const auto& pair : ctx->vfs) {
        const std::string& filepath = pair.first;
        
        if (filepath.find(req_path) == 0) {
            // Отрезаем базовый путь. Для "/a/b/c.txt" при req_path "/a/" получим "b/c.txt"
            std::string sub = filepath.substr(req_path.length());
            
            size_t slash_pos = sub.find('/');
            std::string entry_name;
            
            if (slash_pos == std::string::npos) {
                entry_name = sub; // Это конечный файл ("c.txt")
            } else {
                entry_name = sub.substr(0, slash_pos); // Это подпапка ("b")
            }

            // Добавляем в вывод, если еще не добавили (чтобы не дублировать папки)
            if (listed_entries.find(entry_name) == listed_entries.end()) {
                listed_entries.insert(entry_name);
                filler(buf, entry_name.c_str(), NULL, 0, (fuse_fill_dir_flags)0);
            }
        }
    }
    return 0;
}

// ---------------------------------------------------------
// 4. FUSE: ЧТЕНИЕ И РАСШИФРОВКА ДАННЫХ НА ЛЕТУ (read)
// ---------------------------------------------------------
static int fs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    (void) fi;
    MountContext* ctx = get_context();
    std::string spath(path);

    // 1. Ищем файл в нашей VFS
    auto it = ctx->vfs.find(spath);
    if (it == ctx->vfs.end()) return -ENOENT;

    VirtualFile& vfile = it->second;

    // 2. Проверяем границы чтения
    if (offset >= vfile.size) return 0; // Достигнут конец файла
    if (offset + size > vfile.size) size = vfile.size - offset; // Читаем только остаток

    // 3. Открываем физический образ диска
    int fd = open(ctx->image_path.c_str(), O_RDONLY);
    if (fd < 0) return -EIO;

    // 4. Выделяем страницу памяти под локальный S-блок RC4
    size_t PAGE_SIZE = sysconf(_SC_PAGESIZE);
    void* local_secure_state = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (local_secure_state == MAP_FAILED) { close(fd); return -ENOMEM; }
    volatile RC4_State* state = static_cast<volatile RC4_State*>(local_secure_state);

    // 5. ИНИЦИАЛИЗАЦИЯ RC4
    // Разрешаем потоку прочитать мастер-ключ
    mprotect(ctx->secure_key_ptr, SECURE_MEMORY_SIZE, PROT_READ);
    rc4_init(state, (const unsigned char*)ctx->secure_key_ptr, ctx->key_len, vfile.salt, 16);
    // Мгновенно блокируем ключ обратно
    mprotect(ctx->secure_key_ptr, SECURE_MEMORY_SIZE, PROT_NONE);

    // 6. ХОЛОСТАЯ ПРОКРУТКА ШИФРА
    // Так как нас просят прочитать данные со смещением 'offset', мы обязаны 
    // "промотать" алгоритм RC4 на 'offset' байт вперед, генерируя мусор.
    unsigned char dummy = 0;
    for (off_t i = 0; i < offset; ++i) {
        dummy = 0; 
        rc4_crypt(state, &dummy, 1);
    }

    // 7. Чтение и  расшифровка запрошенного куска
    lseek(fd, vfile.data_offset + offset, SEEK_SET);
    ssize_t bytes_read = read(fd, buf, size);
    
    if (bytes_read > 0) {
        rc4_crypt(state, (unsigned char*)buf, bytes_read);
    }

    // 8. Заметание следов
    memset(local_secure_state, 0, PAGE_SIZE);
    munmap(local_secure_state, PAGE_SIZE);
    close(fd);

    return bytes_read;
}

// ---------------------------------------------------------
// связывание написанных функций с FUSE
// ---------------------------------------------------------
static struct fuse_operations fs_ops = {
    .getattr = fs_getattr,
    .read    = fs_read,
    .readdir = fs_readdir,
};

// ---------------------------------------------------------
// Точка входа
// ---------------------------------------------------------
int main(int argc, char *argv[]) {
    MountContext ctx;
    const char* key_arg = nullptr;
    std::string mountpoint;

    // парсим  аргументы (-key, -image)
    std::vector<char*> fuse_args;
    fuse_args.push_back(argv[0]); // Имя программы

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-key" && i + 1 < argc) {
            key_arg = argv[++i];
        } else if (arg == "-image" && i + 1 < argc) {
            ctx.image_path = argv[++i];
        } else if (arg == "-f" || arg == "-d") { // Флаги демона
            fuse_args.push_back(argv[i]);
        } else {
            // Всё остальное отдаем FUSE
            mountpoint = argv[i];
            fuse_args.push_back(argv[i]);
        }
    }

    if (!key_arg || ctx.image_path.empty() || mountpoint.empty()) {
        std::cerr << "Usage: " << argv[0] << " -key <secret> -image <disk.img> <mountpoint> [-f]\n";
        return 1;
    }

    // --- Выделение памяти для ключа ---
    ctx.secure_key_ptr = mmap(NULL, SECURE_MEMORY_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ctx.secure_key_ptr == MAP_FAILED) return 1;

    ctx.key_len = strnlen(key_arg, SECURE_MEMORY_SIZE - 1);
    std::memcpy(ctx.secure_key_ptr, key_arg, ctx.key_len);
    ((char*)ctx.secure_key_ptr)[ctx.key_len] = '\0';
    
    // Блокируем доступ к ключу до востребования в fs_read
    mprotect(ctx.secure_key_ptr, SECURE_MEMORY_SIZE, PROT_NONE);

    // Затираем буфер аргументов
    volatile char* p = const_cast<volatile char*>(key_arg);
    for (size_t i = 0; i < ctx.key_len; ++i) p[i] = '\0';

    // --- Строим VFS ---
    if (!build_virtual_fs(ctx)) {
        return 1;
    }

    // --- Запуск FUSE ---
    std::cout << "[INFO] Монтирование образа в: " << mountpoint << "\n";
    std::cout << "[INFO] Для размонтирования используйте команду: fusermount -u " << mountpoint << "\n";
    
    // fuse_main сам берет контроль над процессом и уводит его в фон (если нет флага -f)
    int ret = fuse_main(fuse_args.size(), fuse_args.data(), &fs_ops, &ctx);

    return ret;
}