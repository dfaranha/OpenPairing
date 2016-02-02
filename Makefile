C=gcc
CFLAGS=-I. -O3 -funroll-loops -ggdb -I/home/dfaranha/projects/openssl-1.0.1r/crypto/ec
DEPS = op.h
OBJ = op_arch.o op_bench.o op_core.o op_fp2.o op_fp6.o op_fp12.o op_map.o op_test.o test-bench.o

%.o: %.c $(DEPS)
	$(CC)  -c -o $@ $< $(CFLAGS)

test-bench: $(OBJ)
	gcc -o $@ $^ $(CFLAGS) /home/dfaranha/projects/openssl-1.0.1r/libcrypto.a -ldl

clean:
	rm *.o test-bench
