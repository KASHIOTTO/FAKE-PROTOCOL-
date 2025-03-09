#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <sys/mman.h>
#include <math.h>
#include <sys/stat.h>
#include <errno.h>

//Packet Code:

void print_packet(unsigned char packet[])
{
	/*
	Array Number: 7
	Fragment Number: 3
	Length: 3
	Encrypted: 0
	Endianness: 0
	Last: 1
	Data: 845fed ffff668f 5888192
	*/

	unsigned int arrNumb = packet[0] >> 2;
	unsigned int fragNumb = ((packet[0] & 0x03) << 3) | ((packet[1] >> 5) & 0x07); 
	unsigned int leng = ((packet[1] & 0x1F) << 5) | ((packet[2] >> 3) & 0x1F);
	unsigned int encrypt = (packet[2] >> 2) & 0x01;
	unsigned int endian = (packet[2] >> 1) & 0x01;
	unsigned int last = (packet[2]) & 0x01;

	printf("Array Number: %u\n", arrNumb);
	printf("Fragment Number: %x\n", fragNumb);
	printf("Length: %x\n", leng);
	printf("Encrypted: %x\n", encrypt);
	printf("Endianness: %x\n", endian);
	printf("Last: %x\n", last);
	printf("Data:");
	int payStarts = 3;
	for(unsigned int i = 0; i<leng; i++){//unint
		unsigned int pay;
		if(endian == 0){
			pay = (packet[payStarts] << 24) | (packet[payStarts+1] << 16) | (packet[payStarts+2] << 8) | (packet[payStarts+3]);
		}
		else{
			pay = (packet[payStarts]) | (packet[payStarts+1] << 8) | (packet[payStarts+2] << 16) | (packet[payStarts+3] << 24);
		}
		payStarts += 4;

		printf(" %x", pay);
	}
	printf("\n");
}

unsigned char* build_packets(int data[], int data_length, int max_fragment_size, int endianness, int array_number)
{
	//datlength = 2, maxfrag = 8, end = 1, arrnum = 4
	//2 * 4 > 8 ? -> no
	//end 1/ reverse data
	// (1)78 56 34 12 (2)01 ef cd ab
	int dpf = max_fragment_size / 4;
	int N = (data_length + dpf - 1) / dpf;

	int space = 0;
	int rem = data_length;
	for(int i = 0; i<N; i++){
		int words;
		if(rem > dpf){
			words = dpf;
		}
		else{
			words = rem;
		}
		space += 3 + (words * 4);
		rem -= words;
	}
	unsigned char *pack = malloc(space);
	unsigned char *p = pack;

	int index = 0;
	for(int n = 0; n<N; n++){
		int words;
		if(data_length - index >= dpf){
			words = dpf;
		}
		else{
			words = data_length - index;
		}
		
		int leng = words;
		int last = (n == N - 1) ? 1 : 0;

		unsigned char head0 = ((array_number & 0x3F) << 2) | ((n >> 3) & 0x03);
		unsigned char head1 = ((n & 0x07) << 5) | ((leng >> 5) & 0x1F);
		unsigned char head2 = ((leng & 0x1F) << 3) | (0 << 2) | ((endianness & 0x01) << 1) | (last & 0x01);
		*(p++) = head0;
		*(p++) = head1;
		*(p++) = head2;

		for(int i = 0; i<words; i++){
			int val = data[index++];
			if(endianness == 0){ //get end first
				*(p++) = (val >> 24) & 0xFF;
				*(p++) = (val >> 16) & 0xFF;
				*(p++) = (val >> 8) & 0xFF;
				*(p++) = (val) & 0xFF;
			}
			else{//get begin first
				*(p++) = (val) & 0xFF;
				*(p++) = (val >> 8) & 0xFF;
				*(p++) = (val >> 16) & 0xFF;
				*(p++) = (val >> 24) & 0xFF;
			}
		}
	}
	return pack;
}

int** create_arrays(unsigned char packets[], int array_count, int *array_lengths){
    typedef struct{
        int seen;// 0 - 1 - 2
        int leng;
    }Fragment;

    //keep track frags 
	//two scan 2nd pay
	Fragment *frags = calloc(array_count * 32, sizeof(Fragment)); //free
	int *N = calloc(array_count, sizeof(int));//free
	int *complete = calloc(array_count, sizeof(int));//free
	int *highest = malloc(array_count * sizeof(int));
	for(int i = 0; i < array_count; i++){
        array_lengths[i] = 0;
        highest[i] = -1;
    }
	
	int count_arrays = 0;
    unsigned char *p = packets;
    while(count_arrays < array_count){
        unsigned char head0 = p[0];
        unsigned char head1 = p[1];
        unsigned char head2 = p[2];
        p += 3;

        unsigned char arrNumb = (head0 >> 2) & 0x3F;
        unsigned char fragNumb = ((head0 & 0x03) << 3) | ((head1 >> 5) & 0x07);
		unsigned int length = ((head1 & 0x1F) << 5) | ((head2 >> 3) & 0x1F);
		unsigned char last = head2 & 0x01;
		if(arrNumb < array_count){
            int index = arrNumb * 32 + fragNumb;
			if(!frags[index].seen){
                frags[index].seen = 1;
                frags[index].leng = length;
                N[arrNumb]++;
                array_lengths[arrNumb] += length;
            }
			if(last == 1 && highest[arrNumb] == -1){
                highest[arrNumb] = fragNumb;
            }
			if(!complete[arrNumb] && highest[arrNumb] >= 0){
                int fragreq = highest[arrNumb] + 1;
                if(N[arrNumb] == fragreq){
                    complete[arrNumb] = 1;
                    count_arrays += 1;
                }
            }
        }
		p += (length * 4); //skip **on 2
    }
	int *fragStarts = calloc(array_count * 32, sizeof(int));

    for(int i = 0; i < array_count; i++){
        int maxFrag = highest[i];
		int gap = 0;
        for(int j = 0; j <= maxFrag; j++){ 
            fragStarts[i * 32 + j] = gap;
			if(frags[i * 32 + j].seen){
                gap += frags[i * 32 + j].leng;
            }
        }
    }

    int **return_value = malloc(array_count * sizeof(int*));
    for(int i = 0; i < array_count; i++){
        return_value[i] = malloc(array_lengths[i] * sizeof(int));
    }
	memset(N, 0, array_count * sizeof(int));
    memset(complete, 0, array_count * sizeof(int));
    
	count_arrays = 0;
    p = packets;//pass 2
	while(count_arrays < array_count){
        unsigned char head0 = p[0];
        unsigned char head1 = p[1];
        unsigned char head2 = p[2];
        p += 3;

        unsigned char arrNumb = (head0 >> 2) & 0x3F;
        unsigned char fragNumb = ((head0 & 0x03) << 3) | ((head1 >> 5) & 0x07);
        unsigned int length = ((head1 & 0x1F) << 5) | ((head2 >> 3) & 0x1F);
		//unsigned char encrypt = (head2 >> 2) & 0x01;  **UNUSED WARNING
        unsigned char endian  = (head2 >> 1) & 0x01;
        unsigned char last    = head2 & 0x01;

        if(arrNumb < array_count){
            int index = arrNumb * 32 + fragNumb;
			//pass 2 pay
            if(frags[index].seen == 1){
                int payStart = fragStarts[index];
                for(unsigned int w = 0; w < length; w++){//unint 
                    unsigned char *b = p + (w * 4);
                    int value;
                    if(endian == 1){
                        value =  (b[0]) | ((b[1] << 8 ) & 0x0000FF00) | ((b[2] << 16) & 0x00FF0000) | ((b[3] << 24) & 0xFF000000);
                    }
					else{
                        value =  (b[3]) | ((b[2] << 8 ) & 0x0000FF00) | ((b[1] << 16) & 0x00FF0000) | ((b[0] << 24) & 0xFF000000);
                    }
                    return_value[arrNumb][payStart + w] = value;
                }
				frags[index].seen = 2;
                N[arrNumb]++;

				if(last == 1 && highest[arrNumb] < 0){
                    highest[arrNumb] = fragNumb;
                }
				if(!complete[arrNumb] && highest[arrNumb] >= 0){
                    int fragreq = highest[arrNumb] + 1;
                    if(N[arrNumb] == fragreq){
                        complete[arrNumb] = 1;
                        count_arrays++;
                    }
                }
            }
        }
        p += (length * 4);

        if(count_arrays >= array_count){
            break;
        }
    }
	free(frags);
    free(N);
    free(highest);
    free(complete);
    free(fragStarts);
    return return_value;
}


//Encryption Code:

#define EXPANDED_KEYS_LENGTH 32

typedef uint64_t sbu_key_t;
typedef uint32_t block_t;
typedef block_t(*permute_func_t)(block_t);

block_t table[] = { 
    0x6a09e667, 0xbb67ae84, 0x3c6ef372, 0xa54ff539, 0x510e527f, 0x9b05688b, 0x1f83d9ab, 0x5be0cd18, 
    0xcbbb9d5c, 0x629a2929, 0x91590159, 0x152fecd8, 0x67332667, 0x8eb44a86, 0xdb0c2e0c, 0x47b5481d, 
    0xae5f9156, 0xcf6c85d2, 0x2f73477d, 0x6d1826ca, 0x8b43d456, 0xe360b595, 0x1c456002, 0x6f196330, 
    0xd94ebeb0, 0x0cc4a611, 0x261dc1f2, 0x5815a7bd, 0x70b7ed67, 0xa1513c68, 0x44f93635, 0x720dcdfd, 
    0xb467369d, 0xca320b75, 0x34e0d42e, 0x49c7d9bd, 0x87abb9f1, 0xc463a2fb, 0xec3fc3f2, 0x27277f6c, 
    0x610bebf2, 0x7420b49e, 0xd1fd8a32, 0xe4773593, 0x092197f5, 0x1b530c95, 0x869d6342, 0xeee52e4e, 
    0x11076689, 0x21fba37b, 0x43ab9fb5, 0x75a9f91c, 0x86305019, 0xd7cd8173, 0x07fe00ff, 0x379f513f, 
    0x66b651a8, 0x764ab842, 0xa4b06be0, 0xc3578c14, 0xd2962a52, 0x1e039f40, 0x857b7bed, 0xa29bf2de
};

// ----------------- Bitwise Functions ----------------- //

uint8_t rotl(uint8_t x, uint8_t shamt)
{/*8-bit bitwise rotate left `rotl(x, shamt)`
    - Shifts 8-bits `x` left by `shamt` and wrap the bits that "fall off" the left end back around to the right. 
    - For example, 8-bit rotate `0b10110010` left by `3` is `0b10010101`*/
	shamt = shamt & 7;
	return (uint8_t)((x << shamt) | (x >> (8 - shamt)));
}

uint8_t rotr(uint8_t x, uint8_t shamt)
{
	/*8-bit bitwise rotate left `rotl(x, shamt)`
    - Shifts 8-bits `x` left by `shamt` and wrap the bits that "fall off" the left end back around to the right. 
    - For example, 8-bit rotate `0b10110010` left by `3` is `0b10010101`*/
	shamt = shamt & 7;
	return (uint8_t)((x >> shamt) | (x << (8 - shamt)));
}

block_t reverse(block_t x)
{//blco=4byte
	/*x=100011/ 010001/ 001000/ 000100/ 000010/ 000001/ 000000 
	rev=000000/ 000001/ 000011/ 000110/ 001100/ 011000/ 110001*/ 
	block_t revblock = 0;
	for(int i = 0; i<32; i++){
		revblock <<= 1;
		revblock = revblock | (x & 1);
		x >>= 1;
	}
	return revblock;
}

block_t shuffle4(block_t x)
{
	uint32_t thalf = (x >> 16) & 0xFFFF;
	uint32_t bhalf = x & 0xFFFF;
	uint32_t result = 0;
	for(int i = 0; i<4; i++){
		uint32_t tshift = (thalf >> (12 - 4 * i)) & 0xF;
		result = (result << 4) | tshift;
		uint32_t bshift = (bhalf >> (12 - 4 * i)) & 0xF;
		result = (result << 4) | bshift;
	}
	return result;
	
    
}

block_t unshuffle4(block_t x)
{/*V32-bit un-interleave every four bits `unshuffle4(x)`
    - Inverse operation of `shuffle4`.
    - More precisely, let `x` be the concatenated `aebfcgdh` where letter `a` to `h` represents a hexadecimal value. The result of `unshuffle4` is `abcdefgh`
    - For example, `unshuffle4(0x73625140) = 0x76543210`*/
	uint32_t tresult = 0;
	uint32_t bresult = 0;
	for(int i = 0; i<8; i++){
		uint32_t chunk = (x >> (28 - 4 * i)) & 0xF;
		if(i % 2 == 0){
			tresult = (tresult << 4) | chunk; 
		}
		else{
			bresult = (bresult << 4) | chunk;
		}
	}

	uint32_t result = ((tresult & 0xFFFF) << 16) | (bresult & 0xFFFF);
	return result;
}

block_t shuffle1(block_t x)
{
	uint32_t t = (x >> 16) & 0xFFFF;
	uint32_t b = (x & 0xFFFF);
	uint32_t result = 0;
	for(int i = 15; i>=0; i--){
		uint32_t tbit = (t >> i) & 1;
		result = (result << 1) | tbit;
		uint32_t bbit = (b >> i) & 1;
		result = (result << 1) | bbit;
	}
	return result;
}

block_t unshuffle1(block_t x)
{
	uint32_t t = 0;
	uint32_t b = 0;
	
	uint32_t temp = x;
	for(int i = 0; i<16; i++){
		t <<= 1;
		t = (t) | ((temp >> 31) & 1);
		temp <<= 1;

		b <<=1;
		b = (b) | ((temp >> 31) & 1);
		temp <<= 1;
	}
	block_t result = (t << 16) | (b & 0xFFFF);
	return result;


}

uint8_t nth_byte(block_t x, uint8_t n)
{
	n &= 3;
	return (uint8_t)((x >> (8 * n)) & 0xFF);
}

// ----------------- Encryption Functions ----------------- //

void sbu_expand_keys(sbu_key_t key, block_t *expanded_keys)
{/***Step 1**
	```
	// Load the key to key schedule 
	S[0] := K[31:0]
	S[1] := K[63:32]
	```
	**Step 2**
	```
	// Generate key schedule, iterating forward
	for i in 2,..., 32:
		S[i] = T[ (S[i - 1] XOR S[i - 2]) % 32 ] XOR S[i - 1]
	```
	**Step 3**
	```
	// Generate key schedule, iterating backward
	for i in 29,..., 0:
		S[i] = T[ (S[i + 1] XOR ^ S[i + 2]) % 32 ] XOR S[i]
	```
	**/

	expanded_keys[0] = (uint32_t)((key >> 32) & 0xFFFFFFFF);
	expanded_keys[1] = (uint32_t)(key & 0xFFFFFFFF);
	
	
	for(int i = 2; i<32; i++){
		uint32_t s = (expanded_keys[i-1] ^ expanded_keys[i-2]) % 32;
		expanded_keys[i] = table[s] ^ expanded_keys[i-1];
	}

	for(int i = 29; i>=0; i--){
		uint32_t s = (expanded_keys[i+1] ^ expanded_keys[i+2]) % 32;
		expanded_keys[i] = table[s] ^ expanded_keys[i];
	}

}


//************************* 
/*```
rot_table := [ 2, 3, 5, 7 ]

byte(B, i)
    idx = i mod 4
    ret B[8*(idx + 1)-1 : 8*idx]

scramble_op(B, i, keyA, keyB)
    B1 = byte(B, i) XOR ( byte(B, i-1) AND byte(B, i-2) ) XOR ( ~byte(B, i-1) AND byte(B, i-3) ) XOR byte(keyA, i) XOR byte(keyB, i)
    return rotl( B1, rot_table[i] )

mash_op(B, i, S)
    key = S[ byte(B, i-1) mod 32 ]
    ret byte(B, i) XOR byte(key, i)

scramble(B, S, j, op)
    keyA := S[j]
    keyB := S[31 - j]
    B := op(B)
    B[8:0]   := scramble_op(B, 0, keyA, keyB)
    B[16:8]  := scramble_op(B, 1, keyA, keyB)
    B[24:16] := scramble_op(B, 2, keyA, keyB)
    B[32:24] := scramble_op(B, 3, keyA, keyB)
    ret B

mash(B, S)
    B[7:0]   := mash_op(B, 0, S)
    B[15:8]  := mash_op(B, 1, S)
    B[23:16] := mash_op(B, 2, S)
    B[31:24] := mash_op(B, 3, S)
    ret B
```
*****************************************************
**********************************************
r_rot_table := [ 7, 5, 3, 2 ]

byte(B, i)
    idx = i mod 4
    ret B[8*(idx + 1)-1 : 8*idx]

r_scramble_op(B, i, keyA, keyB)
    B1 = rotr(B, r_rot_table[i])
    ret byte(B1, i) XOR ( byte(B1, i-1) AND byte(B1, i-2) ) XOR ( ~byte(B1, i-1) AND byte(B1, i-3) ) XOR byte(keyA, i) ^ byte(keyB, i)

r_scramble(B, S, j, op)
    keyA := S[j]
    keyB := S[31 - j]
    B[32:24] := r_scramble_op(B, 3, keyA, keyB)
    B[24:16] := r_scramble_op(B, 2, keyA, keyB)
    B[16:8]  := r_scramble_op(B, 1, keyA, keyB)
    B[8:0]   := r_scramble_op(B, 0, keyA, keyB)
    B := op(B)
    ret B

r_mash(B, S)
    B[32:24] := mash_op(B, 3, S)
    B[24:16] := mash_op(B, 2, S)
    B[16:8]  := mash_op(B, 1, S)
    B[8:0]   := mash_op(B, 0, S)
    ret B
```*/


static const uint8_t rot_table[4]  = { 2, 3, 5, 7 };
static const uint8_t r_rot_table[4] = { 7, 5, 3, 2 };

static uint8_t scramble_op(uint32_t B, int i, uint32_t keyA, uint32_t keyB){
	uint8_t b0 = nth_byte(B, (i & 3));
	uint8_t b1 = nth_byte(B, ((i - 1) & 3));
	uint8_t b2 = nth_byte(B, ((i - 2) & 3));
	uint8_t b3 = nth_byte(B, ((i - 3) & 3));
	uint8_t ka = nth_byte(keyA, (i & 3));
	uint8_t kb = nth_byte(keyB, (i & 3));
	uint8_t b = (uint8_t)(b0 ^ (b1 & b2) ^ ((~b1) & b3) ^ ka ^ kb);
	b = rotl(b, rot_table[i & 3]);
	
	return b;
}
static uint8_t r_scramble_op(uint32_t B, int i, uint32_t keyA, uint32_t keyB){
	uint8_t finalByte = nth_byte(B, (i & 3));
	uint8_t temp = rotr(finalByte, r_rot_table[i & 3]);
	uint8_t b1 = nth_byte(B, ((i - 1) & 3));
	uint8_t b2 = nth_byte(B, ((i - 2) & 3));
	uint8_t b3 = nth_byte(B, ((i - 3) & 3));
	uint8_t ka = nth_byte(keyA, (i & 3));
	uint8_t kb = nth_byte(keyB, ((i & 3)));
	uint8_t b = (uint8_t)(temp ^ (b1 & b2) ^ ((~b1) & b3) ^ ka ^ kb);

	return b;
}
block_t scramble(block_t x, block_t *keys, uint32_t round, permute_func_t op)
{
	x = op(x);
	uint32_t keyA = keys[round];
	uint32_t keyB = keys[31 - round];

	uint8_t b0 = scramble_op(x, 0, keyA, keyB);
	uint8_t b1 = scramble_op(x, 1, keyA, keyB);
	uint8_t b2 = scramble_op(x, 2, keyA, keyB);
	uint8_t b3 = scramble_op(x, 3, keyA, keyB);
	block_t result = 0;
	result = ((block_t)b0) | ((block_t)b1 << 8) | ((block_t)b2 << 16) | ((block_t)b3 << 24); 
	
	return result;
}

static uint8_t mash_op(uint32_t B, int i, const uint32_t *S){
	uint8_t b1 = nth_byte(B, (i - 1) & 3);
	uint32_t key = S[b1 % 32];
	uint8_t b0 = nth_byte(B, (i & 3));
	uint8_t k = nth_byte(key, (i & 3));

	return (uint8_t)(b0 ^ k);
}
block_t mash(block_t x, block_t *keys)
{
	uint8_t m0 = mash_op(x, 0, keys);
	uint8_t m1 = mash_op(x, 1, keys);
	uint8_t m2 = mash_op(x, 2, keys);
	uint8_t m3 = mash_op(x, 3, keys);
	block_t result = 0;
	result = ((block_t)m0) | ((block_t)m1 << 8) | ((block_t)m2 << 16) | ((block_t)m3 << 24); 
	
	return result;
}

block_t sbu_encrypt_block(block_t plain_text, block_t *expanded_keys)
{
	block_t r1 = scramble(plain_text,expanded_keys,0,reverse);
    block_t r2 = scramble(r1,expanded_keys,1,shuffle1);
    block_t r3 = scramble(r2,expanded_keys,2,shuffle4);
    block_t r4 = scramble(r3,expanded_keys,3,reverse);
    block_t r5 = mash(r4,expanded_keys);
    block_t r6 = scramble(r5,expanded_keys,4,reverse);
    block_t r7 = scramble(r6,expanded_keys,5,shuffle1);
    block_t r8 = scramble(r7,expanded_keys,6,shuffle4);
    block_t r9 = scramble(r8,expanded_keys,7,reverse);
    block_t r10 = mash(r9,expanded_keys);
    block_t r11 = scramble(r10,expanded_keys,8,reverse);
    block_t r12 = scramble(r11,expanded_keys,9,shuffle1);
    block_t r13 = scramble(r12,expanded_keys,10,shuffle4);
    block_t r14 = scramble(r13,expanded_keys,11,reverse);
    block_t r15 = mash(r14,expanded_keys);
    block_t r16 = scramble(r15,expanded_keys,12,reverse);
    block_t r17 = scramble(r16,expanded_keys,13,shuffle1);
    block_t r18 = scramble(r17,expanded_keys,14,shuffle4);
    block_t r19 = scramble(r18,expanded_keys,15,reverse);
    return r19;
}

block_t r_scramble(block_t x, block_t *keys, uint32_t round, permute_func_t op)
{
	uint32_t keyA = keys[round];
	uint32_t keyB = keys[31 - round];
	uint8_t b3 = r_scramble_op(x, 3, keyA, keyB);
	uint8_t b2 = r_scramble_op(x, 2, keyA, keyB);
	uint8_t b1 = r_scramble_op(x, 1, keyA, keyB);
	uint8_t b0 = r_scramble_op(x, 0, keyA, keyB);
	block_t result = 0;
	result = ((block_t)b0) | ((block_t)b1 << 8) | ((block_t)b2 << 16) | ((block_t)b3 << 24); 
	result = op(result);

	return result;
}

block_t r_mash(block_t x, block_t *keys)
{
	uint8_t m3 = mash_op(x, 3, keys);
	uint8_t m2 = mash_op(x, 2, keys);
	uint8_t m1 = mash_op(x, 1, keys);
	uint8_t m0 = mash_op(x, 0, keys);
	block_t result = 0;
	result = ((block_t)m0) | ((block_t)m1 << 8) | ((block_t)m2 << 16) | ((block_t)m3 << 24); 
	
	return result;
}

block_t sbu_decrypt_block(block_t cipher_text, block_t *expanded_keys)
{
	block_t r1 = r_scramble(cipher_text,expanded_keys,15,reverse);
    block_t r2 = r_scramble(r1,expanded_keys,14,unshuffle4);
    block_t r3 = r_scramble(r2,expanded_keys,13,unshuffle1);
    block_t r4 = r_scramble(r3,expanded_keys,12,reverse);
    block_t r5 = r_mash(r4,expanded_keys);
    block_t r6 = r_scramble(r5,expanded_keys,11,reverse);
    block_t r7 = r_scramble(r6,expanded_keys,10,unshuffle4);
    block_t r8 = r_scramble(r7,expanded_keys,9,unshuffle1);
    block_t r9 = r_scramble(r8,expanded_keys,8,reverse);
    block_t r10 = r_mash(r9,expanded_keys);
    block_t r11 = r_scramble(r10,expanded_keys,7,reverse);
    block_t r12 = r_scramble(r11,expanded_keys,6,unshuffle4);
    block_t r13 = r_scramble(r12,expanded_keys,5,unshuffle1);
    block_t r14 = r_scramble(r13,expanded_keys,4,reverse);
    block_t r15 = r_mash(r14,expanded_keys);
    block_t r16 = r_scramble(r15,expanded_keys,3,reverse);
    block_t r17 = r_scramble(r16,expanded_keys,2,unshuffle4);
    block_t r18 = r_scramble(r17,expanded_keys,1,unshuffle1);
    block_t r19 = r_scramble(r18,expanded_keys,0,reverse);

    return r19;
}

void sbu_encrypt(uint8_t *plaintext_input, block_t *encrypted_output, size_t pt_len, uint32_t *expanded_keys)
{/*- `sbu_encrypt` encrypts the bytes in the buffer `plaintext_input` using the `expanded_keys` which was written by `sbu_expand_keys`.
	If the length of the `plain_text`, here `pt_len`, is not a multiple of four, then it is padded with `0` until it is. The encrypted output is written
	to the appropriately sized `encrypted_output`.
    - To create a block for encryption from `plaintext_input`, every four consecutive bytes of `plaintext_input` is concatenated together where the bytes
    that occur earlier in the buffer have a lower address in the block (little endian). For example, the bytes `[0xAA, 0xBB, 0xCC, 0xDD]` would become the block `0xDDCCBBAA`.
	*/
	// 10 11 13 14 15; 2 1 3 2 1
	size_t blocks = (pt_len + 3) / 4;
	for(unsigned int i = 0; i<blocks; i++){
		//4*8 32
		uint32_t block = 0;
		for(int byte = 0; byte<4; byte++){
			size_t k = i * 4 + byte;
			uint8_t read = 0;
			if(k < pt_len){
				read = plaintext_input[k];
			}
			block = block | ((uint32_t)read << (8 * byte));
		}
		uint32_t encryptedBlock = sbu_encrypt_block(block, expanded_keys);
		encrypted_output[i] = encryptedBlock;
	}
}

void sbu_decrypt(block_t *encrypted_input, char *plaintext_output, size_t pt_len, uint32_t *expanded_keys)
{/*`sbu_decrypt` decrypts the bytes in the buffer `encrypted_input` using the `expanded_keys` which was written by `sbu_expand_keys`. The decrypted byte buffer
may be larger than the `pt_len`, the expected length of the plaintext. If this happens, truncate the remaining bytes. 
    - To decompose the block from the decryption, store the lower bytes in lower addresses (little-endian). In other words, the block `0xDDCCBBAA` would decompose to 
    `[0xAA, 0xBB, 0xCC, 0xDD]`
	
	*/
	size_t blocks = (pt_len + 3) / 4;
	for(size_t i = 0; i<blocks; i++){
		//4*8 32
		uint32_t block = sbu_decrypt_block(encrypted_input[i], expanded_keys);
		for(int byte = 0; byte<4; byte++){
			size_t k = i * 4 + byte;

			if(k < pt_len){//truncat **
				plaintext_output[k] = (uint8_t)((block >> (8 * byte)) & 0xFF);
			}
		}
	}
}

// ----------------- Utility Functions ----------------- //