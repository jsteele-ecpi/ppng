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
#define PNG_DATA_CAP (64*1024)
#define CHNK_BUF_CAP (64*1024)

#define read_bytes(file, buf, buf_cap) read_bytes_(file, buf, buf_cap, __FILE__, __LINE__)
#define write_bytes(file, buf, buf_cap) write_bytes_(file, buf, buf_cap, __FILE__, __LINE__)
bool quit = false;


//http://www.libpng.org/pub/png/spec/1.2/PNG-CRCAppendix.html
//c code to implement a crc (cyclic redundancy check)
   /* Table of CRCs of all 8-bit messages. */
   unsigned long crc_table[256];
   
   /* Flag: has the table been computed? Initially false. */
   int crc_table_computed = 0;
   
   /* Make the table for a fast CRC. */
   void make_crc_table(void)
   {
     unsigned long c;
     int n, k;
     for (n = 0; n < 256; n++) {
       c = (unsigned long) n;
       for (k = 0; k < 8; k++) {
         if (c & 1)
           c = 0xedb88320L ^ (c >> 1);
         else
           c = c >> 1;
       }
       crc_table[n] = c;
     }
     crc_table_computed = 1;
   }
   /* Update a running CRC with the bytes buf[0..len-1]--the CRC
      should be initialized to all 1's, and the transmitted value
      is the 1's complement of the final running CRC (see the
      crc() routine below)). */
   
   unsigned long update_crc(unsigned long crc, unsigned char *buf, int len)
   {
     unsigned long c = crc;
     int n;
   
     if (!crc_table_computed)
       make_crc_table();
     for (n = 0; n < len; n++) {
       c = crc_table[(c ^ buf[n]) & 0xff] ^ (c >> 8);
     }
     return c;
   }
   
   /* Return the CRC of the bytes buf[0..len-1]. */
   unsigned long crc(unsigned char *buf, int len)
   {
     return update_crc(0xffffffffL, buf, len) ^ 0xffffffffL;  
		 //Suffix L indicates a long value (at least 32 bits).
   }



// Ideally, I'd like to use this struct as a primitive obect
// to handle chunks more efficiently in the future
struct Chunk{
	uint32_t length;
	uint32_t type;
	uint8_t data[PNG_DATA_CAP];    //chunk.length determines data size(max:2^31)
	char *data_str[PNG_DATA_CAP]; //get data as string for formatting
	uint32_t crc;
  uint8_t flags;                // a set of flag to represent certain states 
};

void read_bytes_(FILE *file, void *buf, size_t buf_cap, const char *src_file, int src_line)
{
	size_t n = fread(buf, buf_cap, 1, file);
	if(n!=1){
		if(ferror(file)){
			fprintf(stderr,
							"%s:%d: ERROR: could not read %zu bytes from file: %s\n", 
							src_file, src_line, buf_cap, strerror(errno));
			exit(1);
		} else if(feof(file)){
				fprintf(stderr,
						"ERROR: could not read %zu  bytes from file: (EOF)\n",
						buf_cap);
				exit(1);
		} else{
				quit = true;  //band-aid?
//TODO: fread unreachable(?), recreate and debug
				//assert(0 && "unreachable");
		}
	}
}

void write_bytes_(FILE *file, void *buf, size_t buf_cap, const char *src_file, int src_line)
{
  size_t n = fwrite(buf, buf_cap, 1, file);
	if(n != 1){
		if(ferror(file)){
			fprintf(stderr, "%s:%d: ERROR: could not write %zu bytes to file: %s\n",
							src_file, src_line, buf_cap, strerror(errno));
			exit(1);
		} else {
			//assert(0 && "Unreachable!");
			quit = true;
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

void flip_bytes(void *buf_, size_t buf_cap)
{// needed for *big endian* byte ordering
	uint8_t *buf = buf_;
	for(size_t i = 0; i < buf_cap/2; ++i){
		uint8_t t = buf[i];
		buf[i] = buf[buf_cap - i - 1];
		buf[buf_cap - i - 1] = t;
	}
}

void skip_bytes(void *buf_, size_t size)
{// In case we aren't interested in a series of bytes/chunks
//TODO: test skip_bytes(), find logical reason to

	if(fseek(buf_, size, SEEK_CUR) < 0) {  // skip relative to current cursor position
		fprintf(stderr, "ERROR: could not skip bytes: %s\n", strerror(errno));
		exit(1);
	}
}

//TODO: figure out why this was scrapped in tsoding vid
/*
   void inject_chunk(FILE *file,
									void *buf, size_t buf_cap,
									//uint8_t chunk_type[4]),
		 							uint32_t chunk_crc)
{
	uint32_t chunk_size = buf_cap;
	flip_bytes(&chunk_size, sizeof(chunk_size));
  write_bytes(file, &chunk_size, sizeof(chunk_size));
  write_bytes(file, chunk_type, 4);
	write_bytes(file, buf, buf_cap);
	//uint32_t chunk_crc = 0;
	write_bytes(file, &chunk_crc, sizeof(chunk_crc));

}
*/
void usage(FILE *file, char *program)
{
		fprintf(file, "Usage: %s <input.png> [output.png]\n", program);
}


const uint8_t png_sig[] = {137, 80, 78, 71, 13, 10, 26, 10};
uint8_t chunk_buf[CHNK_BUF_CAP];

int main(int argc, char **argv)
{
	(void) argc;

//TODO: write a function to handle arguments better. 
//			e.g *program = nextarg(), *input_file = nextarg(), etc

	//assert that there was an arg provided; the arg array provides a null terminator, 
	//allowing us to step through args until reaching NULL
	assert(*argv != NULL);

	//take 1st arg provided (name of script), then increment the arg count
	char *program = *argv++;

	if(*argv == NULL){
		fprintf(stderr, "ERROR: no input file provided\n");
		usage(stderr, program);
		exit(1);
	}

	//take next arg as in_filepath
	char *in_filepath = *argv++;
	
	FILE *input_file = fopen(in_filepath, "rb");
	//input_file = fopen(in_filepath, "rb");
	if (input_file == NULL){
		fprintf(stderr, "READ_ERROR: could not open file %s: %s\n", 
				in_filepath, strerror(errno));
		exit(1);
	}
	printf("Provided file: %s\n", in_filepath);

	
	if(*argv == NULL){
		fprintf(stderr, "ERROR: no output file provided\n");
		usage(stderr, program);
		exit(1);
	}

	char *out_filepath = *argv++;
	FILE *output_file = fopen(out_filepath, "wb");
	//input_file = fopen(out_filepath, "rb");
	if (output_file == NULL){
		fprintf(stderr, "READ_ERROR: could not open file %s: %s\n", 
				out_filepath, strerror(errno));
		exit(1);
	}
	printf("Destination file: %s\n", out_filepath);

	//the first 8 bytes ALWAYS contains the following 
	//decimal values: 137 80 78 71 13 10 26 10
	
//TODO: create function to handle png signature read/cmp

	//capture first 8 bytes and store as array
	uint8_t sig[PNG_SIG_CAP];
	read_bytes(input_file, sig, PNG_SIG_CAP);
	write_bytes(output_file, sig, PNG_SIG_CAP);
	printf("png Sig Bytes: ");
	print_bytes(sig, PNG_SIG_CAP);
	printf("png Signature: %.*s\n", 4, (char*)sig); 
	printf("==================================\n");

  //compare the memory to verify if proper PNG file
	if(memcmp(sig, png_sig, PNG_SIG_CAP)!=0){
		fprintf(stderr, "ERROR: %s does not appear to be a valid PNG image\n", in_filepath);
		exit(1);
	} 

  while(!quit){

		/* chunk Structure: ---| length (data) | type | data | crc |--- */

		/* length: a 4-byte unsigned int, # of bytes in chunk data field */
		//read 4 bytes
		uint32_t chunk_len;  // length of chunk_data in bytes
		read_bytes(input_file, &chunk_len, sizeof(chunk_len));
		write_bytes(output_file, &chunk_len, sizeof(chunk_len));
		flip_bytes(&chunk_len, sizeof(chunk_len));
		printf("chunk Length : %u\n", chunk_len);

		uint8_t chunk_type[4];
		read_bytes(input_file, chunk_type, sizeof(chunk_type));
		write_bytes(output_file, chunk_type, sizeof(chunk_type));
		printf("Chunk Bytes  : ");
		print_bytes(chunk_type, sizeof(chunk_type));
		printf("Chunk Type   : %.*s (0x%08X)\n",
						(int)sizeof(chunk_type), chunk_type, *(uint32_t*) chunk_type); 

		uint8_t chunk_data[chunk_len];
		char chunk_data_str[chunk_len];
		//read_bytes(input_file, chunk_data, sizeof(chunk_data));
		//write_bytes(output_file, chunk_data, sizeof(chunk_data));
		size_t x = chunk_len;
		while(x > 0){
			size_t y = x;
			if(y > CHNK_BUF_CAP) y = CHNK_BUF_CAP;
			read_bytes(input_file, chunk_buf, y);
			write_bytes(output_file, chunk_buf, y);
			x -= y;
		}

		//check if chunk type is tEXt by casting the 4-byte array as an int32 and 
		//immediately dereferencing it - #type_punning
		if(*(uint32_t*)chunk_type == 0x74584574){

			//flip_bytes(&chunk_data, sizeof(chunk_data));
			//print_bytes(chunk_data, sizeof(chunk_data));
			printf("Chunk Data   : ");

			for(int i = 0; i < (int)sizeof(chunk_data); i++){

//TODO: determine what to do with chunk_data_'string'
			
				//if(i % 16 == 0)printf("\n");
				chunk_data_str[i] = (char)chunk_data[i];
				printf("%c", chunk_data_str[i]);
				//printf("Chunk Data   : %.*s\n", (int)sizeof(chunk_data), chunk_data); 
			}
			printf("\n");
		}


		uint32_t chunk_crc;
		read_bytes(input_file, &chunk_crc, sizeof(chunk_crc));
		write_bytes(output_file, &chunk_crc, sizeof(chunk_crc));
		printf("Chunk CRC    : 0x%08X\n", chunk_crc);

		printf("--------------------------------\n");
		
		// similar type pun to check if type is IEND
		if(*(uint32_t*)chunk_type == 0x444E4549){
			quit = true;
		}
  }

	fclose(input_file);
	fclose(output_file);
	return 0;
}
