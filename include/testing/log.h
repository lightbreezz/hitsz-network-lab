#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#include <stdio.h>

#define RESET "\e[0m"  //!< Reset colored output to default terminal color
#define RED "\e[0;31m"
#define YELLOW "\e[0;33m"
#define BLUE "\e[0;34m"
#define GREEN "\e[0;32m"

#define PRINT_ERROR(fmt, ...)                       \
    do {                                      \
        printf(RED fmt RESET, ##__VA_ARGS__); \
    } while (0)

#define PRINT_WARN(fmt, ...)                           \
    do {                                         \
        printf(YELLOW fmt RESET, ##__VA_ARGS__); \
    } while (0)

#define PRINT_INFO(fmt, ...)                         \
    do {                                       \
        printf(BLUE fmt RESET, ##__VA_ARGS__); \
    } while (0)

#define PRINT_PASS(fmt, ...)                          \
    do {                                        \
        printf(GREEN fmt RESET, ##__VA_ARGS__); \
    } while (0)

#endif