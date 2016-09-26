
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cyclone_crypto/des.h"
#include "cyclone_crypto/des3.h"

void dump(const char *msg, const uint8_t *d, int sz)
{
	printf("%s ==> ", msg);
	for (int i = 0; i < sz; ++i)
		printf("%02x ", d[i]);
	printf("\n");
}

int main()
{
	// chiave condivisa tra PCB (lettore schede) e PICC (TSC)
	uint8_t key[16];
	key[0] = 0x49;
	key[1] = 0x45;
	key[2] = 0x4D;
	key[3] = 0x4B;
	key[4] = 0x41;
	key[5] = 0x45;
	key[6] = 0x52;
	key[7] = 0x42;
	key[8] = 0x21;
	key[9] = 0x4E;
	key[10] = 0x41;
	key[11] = 0x43;
	key[12] = 0x55;
	key[13] = 0x4F;
	key[14] = 0x59;
	key[15] = 0x46;


	// PICC --> invento un PCB_B casuale
	uint8_t PICC_B[8];
	PICC_B[0] = 0x51;
	PICC_B[1] = 0xE7;
	PICC_B[2] = 0x64;
	PICC_B[3] = 0x60;
	PICC_B[4] = 0x26;
	PICC_B[5] = 0x78;
	PICC_B[6] = 0xDF;
	PICC_B[7] = 0x2B;
	dump("PICC_B", PICC_B, 8);

	// PICC crypto B e lo trasmetto al PCB
	uint8_t ek_rndB[8];
	{
		Des3Context picc;
		des3Init(&picc, key, 16);
		des3EncryptBlock(&picc, PICC_B, ek_rndB);
		dump("ek(PCD_B)", ek_rndB, 8);
	}

	// PCB decritto B
	uint8_t PCB_B[8];
	{
		Des3Context pcd;
		des3Init(&pcd, key, 16);
		des3DecryptBlock(&pcd, ek_rndB, PCB_B);
		dump("PCB_B", PCB_B, 8);
	}

	// PCB --> invento un PCB_A casuale
	uint8_t PCB_A[8];
	PCB_A[0] = 0xA8;
	PCB_A[1] = 0xAF;
	PCB_A[2] = 0x3B;
	PCB_A[3] = 0x25;
	PCB_A[4] = 0x6C;
	PCB_A[5] = 0x75;
	PCB_A[6] = 0xED;
	PCB_A[7] = 0x40;


	// trasmetto enk(A|Bp)
	uint8_t ek_rndA_Bp[16];
	{
		// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
		uint8_t PCB_A_Bp[16];
		memcpy(PCB_A_Bp, PCB_A, 8);
		for (int i = 0; i < 7; ++i)
			PCB_A_Bp[i+8] = PICC_B[i+1];
		PCB_A_Bp[15] = PICC_B[0];
		dump("PCB_A_Bp", PCB_A_Bp, 16);

		uint8_t bb[8];
		Des3Context pcd;
		des3Init(&pcd, key, 16);
		for (int i = 0; i < 8; ++i)
			PCB_A_Bp[i] ^= ek_rndB[i];
		des3EncryptBlock(&pcd, PCB_A_Bp, bb);
		memcpy(ek_rndA_Bp, bb, 8);

		for (int i = 0; i < 8; ++i)
			PCB_A_Bp[i+8] ^= bb[i];
		des3EncryptBlock(&pcd, PCB_A_Bp+8, bb);
		memcpy(ek_rndA_Bp + 8, bb, 8);
		dump("enk(PCB_A_Bp)", ek_rndA_Bp, 16);
	}

	// lato PICC decritto ek_rndA_Bp
	{
		uint8_t A[8];
		uint8_t Bp[8];
		Des3Context picc;
		des3Init(&picc, key, 16);
		des3DecryptBlock(&picc, ek_rndA_Bp, A);
		for (int i = 0; i < 8; ++i)
			A[i] ^= ek_rndB[i];
		dump("PCB_A", A, 8);
		des3DecryptBlock(&picc, ek_rndA_Bp+8, Bp);
		for (int i = 0; i < 8; ++i)
			Bp[i] ^= ek_rndA_Bp[i];
		dump("Bp", Bp, 8);

		// ruoto Bp ==> ottengo B
		uint8_t B[8];
		for (int i = 0; i < 7; ++i)
			B[i+1] = Bp[i];
		B[0] = Bp[7];
		dump("B", B, 8);

		// se B va bene significa che A e' stato ricevuto dal PCB
		if (memcmp(B, PICC_B, 8) == 0)
		{
			printf("Test OK\n");
			printf("ACK\n");
		}
		else
			printf("NACK\n");

		// PICC --> ho generato A e ho ottenuto B
		// PCB  --> ho ottenuto A e ho generato B
	}
	return 0;
}
