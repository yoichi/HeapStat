/*
	allocate various size of memories and fill them
*/
#include <intrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
	size_t blockSize[] = {256, 512, 1024, 2048, 4096, 8192, 16384};
	for (int i = 0; i < _countof(blockSize); i++)
	{
		for (int j = 0; j < 0x100; j++)
		{
			size_t length = blockSize[i] - 0x20 - (j >> 4);
			void *ptr = malloc(length);
			memset(ptr, 0xc0 | i, length);
			printf("ptr=%p,i=0x%02x\n", ptr, i);
		}
	}

	__debugbreak();

	return 0;
}