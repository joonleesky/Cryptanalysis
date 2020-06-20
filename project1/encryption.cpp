#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

#pragma warning (disable : 4996)

char **plainText = (char**)malloc(sizeof(char*) * 4);
char **cipherText = (char**)malloc(sizeof(char*) * 4);

int key[8]; //find 8 sub keys
int modulo = 65536;

unsigned int **p_block = (unsigned int**)malloc(sizeof(unsigned int*) * 4); // PlainText Blocks
unsigned int **c_block = (unsigned int**)malloc(sizeof(unsigned int*) * 4); // CipherText Blocks
unsigned int **e_block = (unsigned int**)malloc(sizeof(unsigned int*) * 4); // Encrypted Blocks
unsigned int **temp_e_block = (unsigned int**)malloc(sizeof(unsigned int*) * 4); // Encrypted Blocks to Save temporay values


unsigned int ***LookUpTable = (unsigned int ***)malloc(sizeof(unsigned int **) * 4);

void Initialize(){
	plainText[0] = "0x6018 E590 FDA5 84A9";
	plainText[1] = "0x0A81 ECF1 281E DA5A";
	plainText[2] = "0x2E70 91D3 0AF3 45A0";
	plainText[3] = "0xF778 A320 1457 4AB1";

	cipherText[0] = "0x3AC5 37CD 9CD1 724E";
	cipherText[1] = "0x192C 94BE C3CA 69ED";
	cipherText[2] = "0x0B2D A334 CD6F D8F7";
	cipherText[3] = "0x7BA5 5825 5367 2DF6";

	for (int i = 0; i < 4; i++){
		p_block[i] = (unsigned int*)malloc(sizeof(unsigned int) * 4);
		c_block[i] = (unsigned int*)malloc(sizeof(unsigned int) * 4);
		e_block[i] = (unsigned int*)malloc(sizeof(unsigned int) * 4);
		temp_e_block[i] = (unsigned int*)malloc(sizeof(unsigned int) * 4);
	}

	printf("1.Intialization Done\n"); 
}

//In order to utilize bit-wise operation,convert hexadecimal Text to decimal 
void HexToDec(){
	for (int n = 0; n < 4; n++){
		char *p_ptr = plainText[n];
		char *c_ptr = cipherText[n];

		for (int b = 0; b < 4; b++){
			p_block[n][b] = strtoul(p_ptr, &p_ptr, 16);
			c_block[n][b] = strtoul(c_ptr, &c_ptr, 16);
		}
	}
	printf("2.Convert Hex to Dec Done\n\n");
}

void BreakBlock_1(int s_key1, int s_key4){
	printf("3.Block1 Breaking Start\n");
	clock_t begin = clock();
	int key_num = 0;
	int cnt = 0;
	for (int key1 = s_key1; key1 < modulo; key1++){
		for (int key4 = s_key4; key4 < modulo; key4++){
			//printf("[%d %d %d]\n",cnt, key1, key4);
			int success_num = 0;
			for (int n = 0; n < 4; n++){
				temp_e_block[n][0] = ((p_block[n][0] * key1) % modulo);
				e_block[n][0] = ((temp_e_block[n][0]+modulo) ^ key4) - modulo; //add modulo to perform secure XOR
				if (e_block[n][0] == c_block[n][0])
					success_num += 1;
			}
			if (success_num == 4){
				key[0] = key1;
				key[3] = key4;

				printf("  key1: %d, key4: %d\n", key[0], key[3]);
				clock_t end = clock();
				printf("  time spent:%f\n", (double)(end - begin) / CLOCKS_PER_SEC);
				printf("  Block1 Breaking Finished\n\n");
				return;
			}
		}
	}
}

void BreakBlock_4(int s_key5, int s_key8){
	printf("4.Block4 Breaking Start\n");
	clock_t begin = clock();
	int key_num = 0;

	for (int key5 = s_key5; key5 < modulo; key5++){
		for (int key8 = s_key8; key8 < modulo; key8++){
			int success_num = 0;
			for (int n = 0; n < 4; n++){
				temp_e_block[n][3] = ((p_block[n][3] * key5) % modulo); 
				e_block[n][3] = ((temp_e_block[n][3] + modulo) ^ key8) - modulo; //add modulo to perform secure XOR
				if (e_block[n][3] == c_block[n][3])
					success_num += 1;
			}
			if (success_num == 4){
				key[4] = key5;
				key[7] = key8;
				
				printf("  key5: %d, key8: %d\n", key[4], key[7]);
				clock_t end = clock();
				printf("  time spent:%f\n", (double)(end - begin) / CLOCKS_PER_SEC);
				printf("  Block1 Breaking Finished\n\n");
				return;
			}
		}
	}
}

void BreakBlock_2_3(int s_key2, int s_key6){
	printf("5.Block2&3 Breaking Start\n");
	clock_t begin = clock();

	for (int key2 = s_key2; key2 < modulo; key2++){
		for (int key6 = s_key6; key6 < modulo; key6++){
			int key3 = key2 >> 2;
			int key7 = key6 >> 2;

			int success_num = 0;
			for (int n = 0; n < 4; n++){
				e_block[n][1] = (p_block[n][1] + key2) % modulo;
				e_block[n][2] = (p_block[n][2] + key6) % modulo;

				temp_e_block[n][1] = ((temp_e_block[n][0] + modulo) ^ e_block[n][2]) - modulo;
				temp_e_block[n][2] = ((temp_e_block[n][3] + modulo) ^ e_block[n][1]) - modulo;
				
				temp_e_block[n][1] = (temp_e_block[n][1] * key3) % modulo;
				temp_e_block[n][2] = (temp_e_block[n][1] + temp_e_block[n][2]) % modulo;

				temp_e_block[n][2] = (temp_e_block[n][2] * key7) % modulo;
				temp_e_block[n][1] = (temp_e_block[n][1] + temp_e_block[n][2]) % modulo;

				e_block[n][1] = ((e_block[n][1] + modulo) ^ temp_e_block[n][1]) - modulo;
				e_block[n][2] = ((e_block[n][2] + modulo) ^ temp_e_block[n][2]) - modulo;
				if ((e_block[n][1] == c_block[n][1]) & (e_block[n][2] == c_block[n][2]))
					success_num += 1;
			}
			if (success_num == 4){
				key[1] = key2;
				key[2] = key3;
				key[5] = key6;
				key[6] = key7;
				printf("  key2:%d, key3:%d key6:%d key7:%d \n", key[1], key[2], key[5], key[6]);
				clock_t end = clock();
				printf("  time spent:%f\n", (double)(end - begin) / CLOCKS_PER_SEC);
				printf("  Block2&3 Breaking Finished\n\n");
				return;
				}
			}
	}
}

void show_key(){
	printf("\n-------------------Show Key-------------------\n");
	printf("key1  key2  key3  key4  key5  key6  key7  key8\n");
	for (int i = 0; i < 8; i++)
		printf("%-6d", key[i]);
}

int main(void){
	printf("----- Start Breaking -----\n\n");

	Initialize();
	HexToDec();
	
	BreakBlock_1(0,0); //key1:41713, key4: 40029
	BreakBlock_4(0,0); //key5:52977, key8: 37719
	BreakBlock_2_3(0,0); //key2:35347, key3:8836, key6:34926, key7:8731
	
	show_key();
	getchar();
	getchar();
	system("pause");
	return 0;
}