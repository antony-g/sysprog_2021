all: test.o userfs.o
	gcc test.o userfs.o -o task_3

test.o: test.c
	gcc -c test.c -o test.o

userfs.o: userfs.c
	gcc -c userfs.c -o userfs.o

clean:
	rm -rf *.o task_3
