//cerebr4l_codes @2023
//this is meant solely for my personal education

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>

#define PNG_SIG_CAP 8
#define PNG_DAT_CAP (64*1024)

const uint8_t png_sig[] = {137, 80, 78, 71, 13, 10, 26, 10};
bool quit = false;

// Ideally, I'd like to use this struct as a primitive obect to handle the chuncks better
struct Chunk{
	uint32_t length;
	uint32_t type;
	uint32_t crc;
	uint8_t data[PNG_DAT_CAP];  //chunk.length determines data size(max:2^31)
};

void read_bytes(FILE *file, void *buf, size_t buf_cap)
{
	size_t n = fread(buf, buf_cap, 1, file);
	if(n!=1){
		if(ferror(file)){
			fprintf(stderr, "ERROR: could not read %zu bytes from file: %s\n", 
				buf_cap, strerror(errno));
			exit(1);
		} else if(feof(file)){
				fprintf(stderr, "ERROR: could not read %zu  bytes from file: reached end of file (EOF)\n", buf_cap);
				exit(1);
		} else{
				quit = true;
				//assert(0 && "unreachable");
		}
	}
}

void print_bytes(uint8_t *buf, size_t buf_cap)
{
	for(size_t i=0; i<buf_cap; ++i){
		printf("%u ", buf[i]);
	}
	printf("\n");
}

// Need to reverse the bytes due to png format being *big endian*
void flip_bytes(void *buf_, size_t buf_cap)
{
	uint8_t *buf = buf_;
	for(size_t i = 0; i < buf_cap/2; ++i){
		uint8_t t = buf[i];
		buf[i] = buf[buf_cap - i - 1];
		buf[buf_cap - i - 1] = t;
	}
}

// In case we aren't interested in a series of bytes/chunks
void skip_bytes(void *buf_, size_t size)
{
	//TODO: finish this function to skip through chunks.

	if(fseek(buf_, size, SEEK_CUR) < 0) {
		fprintf(stderr, "ERROR: could not skip bytes: %s\n", strerror(errno));
		exit(1);
	}
}




int main(int argc, char **argv)
{
	(void) argc;

	//assert that there was an arg provided; the arg array provides a null terminator, 
	//allowing us to step through args until reaching NULL
	assert(*argv != NULL);

	//take 1st arg provided, then increment the arg count
	char *program = *argv++;

	if(*argv == NULL){
		fprintf(stderr, "Usage: %s <input.png>\n", program);
		fprintf(stderr, "ERROR: no input file provided\n");
		exit(1);
	}

	//take next arg as in_filepath
	char *in_filepath = *argv++;
	
	FILE *input_file = fopen(in_filepath, "rb");
	if (input_file == NULL){
		fprintf(stderr, "READ_ERROR: could not open file %s: %s\n", 
				in_filepath, strerror(errno));
		exit(1);

	}
	printf("Provided file: %s\n", in_filepath);

	if(*argv++!=NULL){
		//take next arg as out_filepath
		char *out_filepath = *argv++;
		
		FILE *output_file = fopen(out_filepath, "wb");
		if (output_file == NULL){
			fprintf(stderr, "WRITE_ERROR: could not open file %s: %s\n", 
					out_filepath, strerror(errno));
			exit(1);
		}
		printf("Destination file: %s\n", out_filepath);
	}

	//png signature; first 8 bytes of file ALWAYS contains
	//the following decimal values: 137 80 78 71 13 10 26 10
	
	//capture first 8 bytes and store as array?
	uint8_t sig[PNG_SIG_CAP];
	read_bytes(input_file, sig, PNG_SIG_CAP);
	printf("PNG Sig Bytes: ");
	print_bytes(sig, PNG_SIG_CAP);
	//printf("PNG Signature: %.*s\n", PNG_SIG_CAP, sig); 


	if(memcmp(sig, png_sig, PNG_SIG_CAP)!=0){
		fprintf(stderr, "ERROR: %s does not appear to be a valid PNG image\n", in_filepath);
		exit(1);
	} 

  while(!quit){
		uint32_t chunk_len;
		read_bytes(input_file, &chunk_len, sizeof(chunk_len));
		flip_bytes(&chunk_len, sizeof(chunk_len));
		printf("Chunk Length (data): %u\n", chunk_len);

		uint8_t chunk_type[4];
		read_bytes(input_file, chunk_type, sizeof(chunk_type));
		printf("Chunk Bytes: ");
		print_bytes(chunk_type, sizeof(chunk_type));
		printf("Chunk Type : %.*s (0x%08X)\n",
						(int)sizeof(chunk_type), chunk_type, *(uint32_t*) chunk_type); 

		uint8_t chunk_data[chunk_len];
		read_bytes(input_file, chunk_data, sizeof(chunk_data));
		//print_bytes(chunk_data, sizeof(chunk_data));
		//printf("Chunk Data : %.*s\n", (int)sizeof(chunk_data), chunk_data); 
		//printf("Chunk Data : "); 
		//flip_bytes(&chunk_data, sizeof(chunk_data));
		//print_bytes(chunk_data, sizeof(chunk_data));
		//printf("Chunk Data : %.*s\n", (int)sizeof(chunk_data), chunk_data); 

		uint32_t chunk_crc;
		read_bytes(input_file, &chunk_crc, sizeof(chunk_crc));
		printf("Chunk CRC: 0x%08X\n", chunk_crc);
		printf("---------------------------------\n");
		
		if(*(uint32_t*)chunk_type == 0x444E4549){
			quit = true;
		}
  }

	//printf("%s is a valid PNG image\n", in_filepath);
	fclose(input_file);
	return 0;
}
