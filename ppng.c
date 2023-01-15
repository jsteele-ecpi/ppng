//cerebr4l_codes @2023
//this is meant solely for my personal education

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#define PNG_SIG_CAP 8
#define PNG_DAT_CAP (64*1024)

const uint8_t png_sig[] = {137, 80, 78, 71, 13, 10, 26, 10};

//would this be a better approach? Look into small helper func
struct Chunk{
	uint32_t length;
	uint32_t type;
	uint32_t crc;
	uint8_t data[PNG_DAT_CAP];  //chunk.length determines data size(max:2^31)
};

void read_buf(FILE *file, void *buf, size_t buf_cap)
{
	size_t n = fread(buf, buf_cap, 1, file);
	if(n!=1){
		if(ferror(file)){
			fprintf(stderr, "ERROR: could not read PNG Header: %s\n", 
				strerror(errno));
			exit(1);
		} else if(feof(file)){
				fprintf(stderr, "ERROR: reached end of file (EOF)\n");
				exit(1);
		} else{
				assert(0&&"unreachable");
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

int main(int argc, char **argv)
{
	(void) argc;

	//assert that there was an arg provided; the arg array providesa null terminator, allowing us to step through args until reaching NULL
	assert(*argv != NULL);
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
		fprintf(stderr, "ERROR: could not open file %s: %s\n", 
				in_filepath, strerror(errno));
		exit(1);

	}
	printf("Provided file: %s\n", in_filepath);

	if(*arg++!=NULL){
		//take next arg as out_filepath
		char *out_filepath = *argv++;
		
		FILE *output_file = fopen(out_filepath, "wb");
		if (output_file == NULL){
			fprintf(stderr, "ERROR: could not open file %s: %s\n", 
					out_filepath, strerror(errno));
			exit(1);
		}
	}

	printf("Destination file: %s\n", out_filepath);
	//png signature; first 8 bytes of file ALWAYS contains
	//the following decimal values: 137 80 78 71 13 10 26 10
	
	//capture first 8 bytes and store as array?
	uint8_t sig[PNG_SIG_CAP];
	read_buf(input_file, sig, PNG_SIG_CAP);
	print_bytes(sig, PNG_SIG_CAP);

	if(memcmp(sig, png_sig, PNG_SIG_CAP)!=0){
		fprintf(stderr, "ERROR: %s does not appear to be a valid PNG image\n", in_filepath);
		exit(1);
	} 
	printf("%s is a valid PNG image\n", in_filepath);
	fclose(input_file);
	return 0;
}
