#ifndef CRC32_H
#define CRC32_H

#include <cstddef>
#include <cstdint>

uint32_t calculateCRC32(const char* data, size_t length);

#endif  // CRC32_H