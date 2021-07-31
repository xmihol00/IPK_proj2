
CC = g++
CFLAGS = -std=c++17 -Wall -Wextra
OBJ = sniffer.o main.o
LIBS = -lpcap
PROGRAM = ipk-sniffer

.PHONY: all clean pack

all: $(PROGRAM)
$(PROGRAM): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) $(LIBS) -o $(PROGRAM)

%.o: %.c sniffer.h
	$(CC) $(CFLAGS) $< -c -o $@

clean:
	@rm $(OBJ) $(PROGRAM) 2>/dev/null || true

pack:
	tar -czvf xmihol00.tar sniffer.cpp sniffer.h main.cpp packet_generator.py README manual.pdf Makefile
