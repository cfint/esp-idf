#include <math.h>
#include <stdint.h>

#include "ldacdec.h"
#include "utility.h"

float MdctWindow[3][256];
float ImdctWindow[3][256];
float SinTables[9][256];
float CosTables[9][256];
int ShuffleTables[9][256];

static void GenerateTrigTables(int sizeBits)
{
	const int size = 1 << sizeBits;
	float* sinTab = SinTables[sizeBits];
	float* cosTab = CosTables[sizeBits];

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
	int* table = ShuffleTables[sizeBits];

	for (int i = 0; i < size; i++)
	{
		table[i] = BitReverse32(i ^ (i / 2), sizeBits);
	}
}

static void GenerateMdctWindow(int frameSizePower)
{
	const int frameSize = 1 << frameSizePower;
	float* mdct = MdctWindow[frameSizePower - 6];

	for (int i = 0; i < frameSize; i++)
	{
		mdct[i] = (sin(((i + 0.5) / frameSize - 0.5) * M_PI) + 1.0) * 0.5;
	}
}

static void GenerateImdctWindow(int frameSizePower)
{
	const int frameSize = 1 << frameSizePower;
	float* imdct = ImdctWindow[frameSizePower - 6];
	float* mdct = MdctWindow[frameSizePower - 6];

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
		GenerateShuffleTable(i);
	}		
    GenerateMdctWindow(7);
    GenerateImdctWindow(7);

    GenerateMdctWindow(8);
	GenerateImdctWindow(8);
}


static void Dct4(Mdct* mdct, float* input, float* output);

void RunImdct(Mdct* mdct, float* input, float* output)
{
	const int size = 1 << mdct->Bits;
	const int half = size / 2;
	float dctOut[MAX_FRAME_SAMPLES] = { 0.f };
	const float* window = ImdctWindow[mdct->Bits - 6];
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
	const int* shuffleTable = ShuffleTables[MdctBits];
	const float* sinTable = SinTables[MdctBits];
	const float* cosTable = CosTables[MdctBits];
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
		sinTable = SinTables[blockHalfSizeBits];
		cosTable = CosTables[blockHalfSizeBits];

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
