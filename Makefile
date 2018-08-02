CFLAGS=-O3 -g
OBJ=simon.o

test_simon: $(OBJ) test_simon.c
	gcc test_simon.c simon.o -o test_simon $(CFLAGS)

two_round_linear: $(OBJ) two_round_linear.c
	gcc two_round_linear.c simon.o -o two_round_linear $(CFLAGS)

reduced_linear: $(OBJ) reduced_linear.c
	gcc reduced_linear.c $(OBJ) -o reduced_linear $(CFLAGS)

differential: $(OBJ) differential.c
	gcc differential.c $(OBJ) -o differential $(CFLAGS)

simon.o: simon.c simon.h
	gcc -c simon.c $(CFLAGS)

clean:
	rm -f $(OBJ) two_round_linear test_simon reduced_linear differential