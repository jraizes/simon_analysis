CFLAGS=-O3 -g

test_simon: simon.o test_simon.c
	gcc test_simon.c simon.o -o test_simon $(CFLAGS)

two_round_linear: simon.o two_round_linear.c
	gcc two_round_linear.c simon.o -o two_round_linear $(CFLAGS)

simon.o: simon.c simon.h
	gcc -c simon.c $(CFLAGS)

clean:
	rm -f simon.o two_round_linear test_simon