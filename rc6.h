#ifndef RC6_H
#define RC6_H

#include <stdint.h>

#define ROUNDS      20      // Количество раундов
#define KEY_LENGTH  256     // Длина ключа
#define W           32      // Длина машинного слова в битах

// n = 128 бит - длина блока (32+32+32+32)

// Контекст RC6
typedef struct rc6_ctx
{
    uint8_t r;      // Число раундов, по умолчанию 20
    uint32_t *S;    // 32-битные раундовые ключи
} rc6_ctx_t;

// Создание нового контекста RC6
rc6_ctx_t* ak_rc6_ctx_create_new();

// Удаление контекста RC6
void ak_rc6_ctx_free(rc6_ctx_t *ctx);

// Алгоритм развёртки ключа
void ak_rc6_ctx_key_schedule(rc6_ctx_t *ctx, void *key);

// Алгоритм зашифрования
void ak_rc6_ctx_encrypt(rc6_ctx_t *ctx, void *block);

// Алгоритм расшифрования
void ak_rc6_ctx_decrypt(rc6_ctx_t *ctx, void *block);

#endif // RC6_H

