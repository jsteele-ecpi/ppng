//cerebr4l @2023
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

//macros to handle simple debug when r/w file (this is why I watch his vids!)
#define read_bytes(file, buf, buf_cap) \
	read_bytes_(file, buf, buf_cap, __FILE__, __LINE__)
#define write_bytes(file, buf, buf_cap) \
	write_bytes_(file, buf, buf_cap, __FILE__, __LINE__)
bool quit = false;

//http://www.libpng.org/pub/png/spec/1.2/PNG-CRCAppendix.html
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
	is the 1's complement of the final running CRC */
unsigned long update_crc(unsigned long crc, unsigned char *buf, int len)
{
 unsigned long c = crc;
 int n;
 if (!crc_table_computed) make_crc_table();
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

/*
// and this struct to handle an entire file (array?) of chunks
struct Chunks{
	Chunk *chunk_array[];
};
*/

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
//TODO: (1): fread unreachable(?), recreate and debug
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
{
	//TODO: test skip_bytes(), find logical reason to use this function
	if(fseek(buf_, size, SEEK_CUR) < 0) {  // skip relative to cursor position
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
	make_crc_table();

  //TODO: handle args better, and add options - getopt()???
  //			e.g *program = nextarg(), *input_file = nextarg(), etc

	//apparently argv allows us to step through args until reaching NULL
	assert(*argv != NULL);

	//take 1st arg provided (name of script), then increment the arg count
	char *program = *argv++;

	if(*argv == NULL){
		fprintf(stderr, "ERROR: no input file provided\n");
		usage(stderr, program);
		exit(1);
	}

	char *in_filepath = *argv++;
	FILE *input_file = fopen(in_filepath, "rb");
	if (input_file == NULL){
		fprintf(stderr, "READ_ERROR: could not open file %s: %s\n", 
				in_filepath, strerror(errno));
		exit(1);
	}
	printf("Provided file: %s\n", in_filepath);

  //TODO: (1): make output optional	
	if(*argv == NULL){
		/*
		fprintf(stderr, "ERROR: no output file provided\n");
		usage(stderr, program);
		exit(1);
		*/

	  //TODO: create function to handle png signature read/cmp

		//capture first 8 bytes and store as array
		uint8_t sig[PNG_SIG_CAP];
		read_bytes(input_file, sig, PNG_SIG_CAP);
		//compare the memory to verify if proper PNG file
		if(memcmp(sig, png_sig, PNG_SIG_CAP)!=0){
			fprintf(stderr, 
					"ERROR: %s does not appear to be a valid PNG image\n",
					in_filepath);
			exit(1);
		} 
		printf("png Sig Bytes: ");
		print_bytes(sig, PNG_SIG_CAP);
		printf("png Signature: %.*s\n", 4, (char*)sig); 
		printf("==================================\n");


		while(!quit)
		{ // global boolean for dirty control

		  /* chunk Structure: ---| length (data) | type | data | crc |--- */

			/* length: 4-byte uint, (# of bytes in chunk data field) */
			uint32_t chunk_len;  
			read_bytes(input_file, &chunk_len, sizeof(chunk_len));
			flip_bytes(&chunk_len, sizeof(chunk_len));

			/* Type: 4-byte uint */
			uint8_t chunk_type[4];
			read_bytes(input_file, chunk_type, sizeof(chunk_type));

			/* Data: {chunk_len}-byte uint stored as array of bytes */
			uint8_t chunk_data[chunk_len];
			char chunk_data_str[chunk_len];
			read_bytes(input_file, chunk_data, sizeof(chunk_data));

			/* CRC: 4-byte redundancy check, calculated upon data bytes */
			uint32_t chunk_crc;
			read_bytes(input_file, &chunk_crc, sizeof(chunk_crc));

			//display captured values
			printf("Chunk Type   : %.*s (0x%08X)\n",
							(int)sizeof(chunk_type), chunk_type,
							*(uint32_t*) chunk_type); 
			//printf("Chunk Bytes  : ");
			//print_bytes(chunk_type, sizeof(chunk_type));
			printf("Chunk CRC    : 0x%08X\n", chunk_crc);
			printf("Chunk Length : %u\n", chunk_len);

			//check if chunk type is tEXt by casting the 4-byte array as
			//an int32 and immediately dereferencing it - #type_punning
			if(*(uint32_t*)chunk_type == 0x74584574
				|| *(uint32_t*)chunk_type == 0x65566968){
				printf("Chunk Data   : ");
				for(int i = 0; i < (int)sizeof(chunk_data); i++){
	        //TODO: determine what to do with chunk_data_'string'
					//if(i % 16 == 0) printf("\n");
					//chunk_data_str[i] = (char)chunk_data[i];
					//printf("%c", chunk_data_str[i]);
					chunk_data_str[i] = (char)chunk_data[i];
					printf("%c", chunk_data_str[i]);
				}
				printf("\n");
			}
			printf("--------------------------------\n");
			
			// similar type pun to check if type is IEND
			if(*(uint32_t*)chunk_type == 0x444E4549){
				quit = true;
			}
		}	
		fclose(input_file);
		return 0;
	}else{
		// optional output was provided: copy file by chunks and inject
		// our own chunk in the process
		char *out_filepath = *argv++;
		FILE *output_file = fopen(out_filepath, "wb");
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
		//compare the memory to verify if proper PNG file
		if(memcmp(sig, png_sig, PNG_SIG_CAP)!=0){
			fprintf(stderr, 
					"ERROR: %s does not appear to be a valid PNG image\n",
					in_filepath);
			exit(1);
		} 
		write_bytes(output_file, sig, PNG_SIG_CAP);
		printf("png Sig Bytes: ");
		print_bytes(sig, PNG_SIG_CAP);
		printf("png Signature: %.*s\n", 4, (char*)sig); 
		printf("==================================\n");


		while(!quit)
		{ // global boolean for dirty control

		/* Chunk Structure: ---| Length (data) | Type | Data | CRC |--- */

			/* length: 4-byte uint, (# of bytes in chunk data field) */
			uint32_t chunk_len;  
			read_bytes(input_file, &chunk_len, sizeof(chunk_len));
			write_bytes(output_file, &chunk_len, sizeof(chunk_len));
			flip_bytes(&chunk_len, sizeof(chunk_len));

			/* Type: 4-byte uint */
			uint8_t chunk_type[4];
			read_bytes(input_file, chunk_type, sizeof(chunk_type));
			write_bytes(output_file, chunk_type, sizeof(chunk_type));

			/* Data: {chunk_len}-byte uint stored as array of bytes */
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

			/* CRC: 4-byte redundancy check, calculated upon data bytes */
			uint32_t chunk_crc;
			read_bytes(input_file, &chunk_crc, sizeof(chunk_crc));
			write_bytes(output_file, &chunk_crc, sizeof(chunk_crc));

			/* Injecting custom chunk after IHDR */
			if(*(uint32_t*)chunk_type == 0x52444849){
				uint32_t inject_sz = 13;
				flip_bytes(&inject_sz, sizeof(inject_sz));
				write_bytes(output_file, &inject_sz, sizeof(inject_sz));
				flip_bytes(&inject_sz, sizeof(inject_sz));
				char *inject_type = "hiVe";
				write_bytes(output_file, inject_type, 4);
				//unsigned char *inject_data = "Hello, world!";
				//write_bytes(output_file, &inject_data, inject_sz);
				write_bytes(output_file, "Hello, world!", inject_sz);
				//uint32_t inject_crc = crc(inject_data, inject_sz);
				uint32_t inject_crc = crc("Hello, world!", inject_sz);
				write_bytes(output_file, &inject_crc, sizeof(inject_crc));
			}


			//display captured values
			printf("Chunk Type   : %.*s (0x%08X)\n",
							(int)sizeof(chunk_type), chunk_type, *(uint32_t*) chunk_type); 
			//printf("Chunk Bytes  : ");
			//print_bytes(chunk_type, sizeof(chunk_type));
			printf("Chunk CRC    : 0x%08X\n", chunk_crc);
			printf("Chunk Length : %u\n", chunk_len);

			//check if chunk type is tEXt by casting the 4-byte array as an int32 and 
			//immediately dereferencing it - #type_punning
			if(*(uint32_t*)chunk_type == 0x74584574 
				|| *(uint32_t*)chunk_type == 0x65566968){
				printf("Chunk Data   : ");
				for(int i = 0; i < (int)sizeof(chunk_data); i++){
	        //TODO: determine what to do with chunk_data_'string'
					chunk_data_str[i] = (char)chunk_buf[i];
					printf("%c", chunk_data_str[i]);
				}
				printf("\n");
			}
			printf("--------------------------------\n");
			
			// similar type pun to check if type is IEND
			if(*(uint32_t*)chunk_type == 0x444E4549){
				quit = true;
			}
		}
		fclose(input_file);
		fclose(output_file);
	}
	return 0;
}
