CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS =

SRC = main.c
OBJ = main.o
EXEC = nome

$(EXEC): $(OBJ)
	$(CC) $(OBJ) -o $(EXEC) $(LDFLAGS)

clean: 
	rm -f $(OBJ) $(EXEC)
