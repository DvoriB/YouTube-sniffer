CC := clang

ifeq ($(DEBUG),1)
	CFLAGS :=  -O0 -g
else
	CFLAGS :=  -O1 
endif

LDFLAGS := -lpcap    -ljson-c -pthread  

# -fsanitize=address

run: main.o hashTable.o
	$(CC) -o run main.o  hashTable.o $(LDFLAGS)
main.o: main.c
	$(CC) $(CFLAGS) -c main.c $(LDFLAGS)
hashTable.o: hashTable.c hashTable.h
	$(CC) $(CFLAGS) -c hashTable.c $(LDFLAGS) 

clear:
	rm  -f *.o run *csv

