CFLAGS=-Wall -pedantic -ansi -std=c99
LIBS=-lhttp_parser -lmongoc -lyajl -luv

main: main.c
	gcc main.c $(CFLAGS) -o main $(LIBS)
clean:
	rm -f main
