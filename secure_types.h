#pragma once

#include <cstdint>

// Константы проекта (теперь доступны везде)
namespace Config {
    constexpr uint64_t MAX_FILE_SIZE = UINT32_MAX;
    constexpr uint32_t MAX_PATH_LEN = 4096;
}

// Заголовок файла в образе (Строго 24 байта)
#pragma pack(push, 1)
struct ContainerHeader {
    uint32_t file_length;
    uint32_t name_length;
    unsigned char salt[16];
};
#pragma pack(pop)
// Виртуальный узел (Virtual File System) для демона FUSE
struct VirtualFile {
    uint32_t size;              // Размер расшифрованного файла
    unsigned char salt[16];     // Индивидуальная соль файла
    off_t data_offset;          // Физическое смещение зашифрованных данных внутри disk.img
};