#include <math.h>
#include <stdint.h>

#include "ldacdec.h"
#include "utility.h"


#define DEF_MDCTWINDOW(i) float* MdctWindow_##i;
#define DEF_IMDCTWINDOW(i) float ImdctWindow_##i[1<<i];
#define DEF_SHUFFLETABLE(i) int ShuffleTable_##i[1<<i];

#define DEF_GET_WINDOW_FUNC(table, type) inline type* Get##table(int i) {	\
	switch(i) {																\
		case 7: return table##_7;											\
		case 8: return table##_8;											\
		default:															\
			break;															\
	}																		\
	return NULL;															\
}

#define DEF_SINTABLE(i) float SinTable_##i[1<<i]
#define DEF_COSTABLE(i) float CosTable_##i[1<<i]

#define DEF_GET_TABLE_FUNC(table) inline float* Get##table(int i) {		\
	switch(i) {															\
		case 0: return table##_0;										\
		case 1: return table##_1;										\
		case 2: return table##_2;										\
		case 3: return table##_3;										\
		case 4: return table##_4;										\
		case 5: return table##_5;										\
		case 6: return table##_6;										\
		case 7: return table##_7;										\
		case 8: return table##_8;										\
		default:														\
			break;														\
	}																	\
	return NULL;														\
}

DEF_MDCTWINDOW(7);
DEF_MDCTWINDOW(8);
DEF_IMDCTWINDOW(7);
DEF_IMDCTWINDOW(8);
DEF_SHUFFLETABLE(7);
DEF_SHUFFLETABLE(8);

DEF_SINTABLE(0);
DEF_SINTABLE(1);
DEF_SINTABLE(2);
DEF_SINTABLE(3);
DEF_SINTABLE(4);
DEF_SINTABLE(5);
DEF_SINTABLE(6);
DEF_SINTABLE(7);
DEF_SINTABLE(8);

DEF_COSTABLE(0);
DEF_COSTABLE(1);
DEF_COSTABLE(2);
DEF_COSTABLE(3);
DEF_COSTABLE(4);
DEF_COSTABLE(5);
DEF_COSTABLE(6);
DEF_COSTABLE(7);
DEF_COSTABLE(8);

DEF_GET_WINDOW_FUNC(MdctWindow, float);
DEF_GET_WINDOW_FUNC(ImdctWindow, float);
DEF_GET_WINDOW_FUNC(ShuffleTable, int);

DEF_GET_TABLE_FUNC(SinTable);
DEF_GET_TABLE_FUNC(CosTable);


static void GenerateTrigTables(int sizeBits)
{
	const int size = 1 << sizeBits;
	float* sinTab = GetSinTable(sizeBits);
	float* cosTab = GetCosTable(sizeBits);

	for (int i = 0; i < size; i++)
	{
		const float value = M_PI * (4 * i + 1) / (4 * size);
		sinTab[i] = sin(value);
		cosTab[i] = cos(value);
	}
}

static void GenerateShuffleTable(int sizeBits)
{
	const int size = 1 << sizeBits;
	int* table = GetShuffleTable(sizeBits);

	for (int i = 0; i < size; i++)
	{
		table[i] = BitReverse32(i ^ (i / 2), sizeBits);
	}
}

static void GenerateMdctWindow(int frameSizePower)
{
	const int frameSize = 1 << frameSizePower;
	float* mdct = GetMdctWindow(frameSizePower);

	for (int i = 0; i < frameSize; i++)
	{
		mdct[i] = (sin(((i + 0.5) / frameSize - 0.5) * M_PI) + 1.0) * 0.5;
	}
}

static void GenerateImdctWindow(int frameSizePower)
{
	const int frameSize = 1 << frameSizePower;
	float* imdct = GetImdctWindow(frameSizePower);
	float* mdct = GetMdctWindow(frameSizePower);

	for (int i = 0; i < frameSize; i++)
	{
		imdct[i] = mdct[i] / (mdct[frameSize - 1 - i] * mdct[frameSize - 1 - i] + mdct[i] * mdct[i]);
	}
}

void InitMdct()
{
	for (int i = 0; i < 9; i++)
	{
		GenerateTrigTables(i);
	}		

	GenerateShuffleTable(7);
	GenerateShuffleTable(8);

	MdctWindow_7 = malloc(sizeof(float) * (1<<7));
	MdctWindow_8 = malloc(sizeof(float) * (1<<8));
	GenerateMdctWindow(7);
	GenerateMdctWindow(8);

	GenerateImdctWindow(7);
	GenerateImdctWindow(8);

	free(MdctWindow_7);
	free(MdctWindow_8);
}


static void Dct4(Mdct* mdct, float* input, float* output);

void RunImdct(Mdct* mdct, float* input, float* output)
{
	const int size = 1 << mdct->Bits;
	const int half = size / 2;
	float dctOut[MAX_FRAME_SAMPLES] = { 0.f };
	const float* window = GetImdctWindow(mdct->Bits);
	float* previous = mdct->ImdctPrevious;

    Dct4(mdct, input, dctOut);
	
    for (int i = 0; i < half; i++)
	{
		output[i] = window[i] * dctOut[i + half] + previous[i];
		output[i + half] = window[i + half] * -dctOut[size - 1 - i] - previous[i + half];
		previous[i] = window[size - 1 - i] * -dctOut[half - i - 1];
		previous[i + half] = window[half - i - 1] * dctOut[i];
    }
}


static void Dct4(Mdct* mdct, float* input, float* output)
{
	int MdctBits = mdct->Bits;
	int MdctSize = 1 << MdctBits;
	const int* shuffleTable = GetShuffleTable(MdctBits);
	const float* sinTable = GetSinTable(MdctBits);
	const float* cosTable = GetCosTable(MdctBits);
	float dctTemp[MAX_FRAME_SAMPLES];

	int size = MdctSize;
	int lastIndex = size - 1;
	int halfSize = size / 2;

	for (int i = 0; i < halfSize; i++)
	{
		int i2 = i * 2;
		float a = input[i2];
		float b = input[lastIndex - i2];
		float sin = sinTable[i];
		float cos = cosTable[i];
		dctTemp[i2] = a * cos + b * sin;
		dctTemp[i2 + 1] = a * sin - b * cos;
	}
	int stageCount = MdctBits - 1;

	for (int stage = 0; stage < stageCount; stage++)
	{
		int blockCount = 1 << stage;
		int blockSizeBits = stageCount - stage;
		int blockHalfSizeBits = blockSizeBits - 1;
		int blockSize = 1 << blockSizeBits;
		int blockHalfSize = 1 << blockHalfSizeBits;
		sinTable = GetSinTable(blockHalfSizeBits);
		cosTable = GetCosTable(blockHalfSizeBits);

		for (int block = 0; block < blockCount; block++)
		{
			for (int i = 0; i < blockHalfSize; i++)
			{
				int frontPos = (block * blockSize + i) * 2;
				int backPos = frontPos + blockSize;
				float a = dctTemp[frontPos] - dctTemp[backPos];
				float b = dctTemp[frontPos + 1] - dctTemp[backPos + 1];
				float sin = sinTable[i];
				float cos = cosTable[i];
				dctTemp[frontPos] += dctTemp[backPos];
				dctTemp[frontPos + 1] += dctTemp[backPos + 1];
				dctTemp[backPos] = a * cos + b * sin;
				dctTemp[backPos + 1] = a * sin - b * cos;
			}
		}
	}

	for (int i = 0; i < MdctSize; i++)
	{
		output[i] = dctTemp[shuffleTable[i]];
	}
}
