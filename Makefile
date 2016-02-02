C=gcc
CFLAGS=-I. -O3 -funroll-loops -ggdb
DEPS = op.h
OBJ = op_arch.o op_bench.o op_core.o op_fp2.o op_fp6.o op_fp12.o op_map.o op_test.o test-bench.o

%.o: %.c $(DEPS)
	$(CC)  -c -o $@ $< $(CFLAGS)

test-bench: $(OBJ)
	gcc -o $@ $^ $(CFLAGS) -lcrypto

clean:
	rm *.o test-bench
