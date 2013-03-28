#ifndef BENCHMARK_H
#define BENCHMARK_H

#include <sys/time.h>
#define TEST_INIT(F) \
	FILE *testfp = fopen(F, "w");\
	struct timeval start, stop;\
	double duration;
#define START gettimeofday(&start, 0);
#define STOP \
	gettimeofday(&stop, 0);\
	duration = (1000000 * (stop.tv_sec - start.tv_sec) + stop.tv_usec - start.tv_usec) / 1000;\
	fprintf(testfp, "%.3f ", duration);
#define PRINT_LINE fprintf(testfp, "\n");
#define TEST_END fclose(testfp);

#endif
