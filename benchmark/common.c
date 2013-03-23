#include "common.h"

void report_error(char* action, FENC_ERROR result)
{
	debug("%s...\n\t%s (%d)\n", action, libfenc_error_to_string(result), result);
}

void print_buffer_as_hex(uint8* data, size_t len)
{
#ifdef DEBUG
	size_t i;
	
	for (i = 0; i < len; i++) {
		printf("%02x ", data[i]);
	}
	printf("\n");
#endif
}

ssize_t read_file(FILE *f, char** out) {
	
	ssize_t MAX_LEN = SIZE_MAX * 4;
	if(f != NULL) {
		/* See how big the file is */
		fseek(f, 0L, SEEK_END);
		ssize_t out_len = ftell(f);
		debug("out_len: %zd\n", out_len);
		if(out_len <= MAX_LEN) {
			/* allocate that amount of memory only */
			if((*out = (char *) malloc(out_len+1)) != NULL) {
				fseek(f, 0L, SEEK_SET);
				fread(*out, sizeof(char), out_len, f);
				return out_len;
			}
		}
	}
	return 0;
}

int ret_num_bits(int value1)
{
	int j;
	
	for(j = 0; j < BITS; j++) {
		if(value1 < pow(2,j)) {
			double x = (double)j;
			// round to nearest multiple of 4
			int newj = (int) ceil(x/4)*4;
			debug("numberOfBits => '%d'\n", newj);
			return newj;
		}
	}
	return 0;
}
