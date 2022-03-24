#pragma once

typedef struct {
	int Bits;
	int Size;
	float Scale;
	float ImdctPrevious[MAX_FRAME_SAMPLES];
	float* Window;
	float* SinTable;
	float* CosTable;
} Mdct;

void InitMdct();
void RunImdct(Mdct* mdct, float* input, float* output);

