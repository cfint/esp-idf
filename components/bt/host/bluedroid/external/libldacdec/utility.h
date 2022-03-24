#pragma once

#include <stdint.h>
#include <math.h>

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#ifndef int32
typedef int32_t int32;
#endif

#ifndef int64
typedef int64_t int64;
#endif

int Max(int a, int b);
int Min(int a, int b);
uint32_t BitReverse32(uint32_t value, int bitCount);
int32_t SignExtend32(int32_t value, int bits);
int16_t Clamp16(int value);
int Round(float x);

