CC		:= g++
LIBS	:= -std=c++14 -L../src -ldghv -lgmp -lm
INCLUDE	:= -I.
CFLAGS	:= -g -Wall -DDEBUG -O0 $(INCLUDE)
CXXFLAGS:= $(CFLAGS) -DHAVE_CONFIG_H
OBJECTS	:= CMNT.o CNT.o DGHV.o

.PHONY	: all clean rebuild $(OBJECTS) ploy_operation.o

all: $(OBJECTS) ploy_operation.o

clean:
	rm -rf *.o

rebuild: clean all

$(OBJECTS): %.o: %test.c
	$(CC) $(CXXFLAGS) $^ $(LIBS) -o $@

ploy_operation.o: ploy_operation.c
	$(CC) $(CXXFLAGS) $^ $(LIBS) -o $@
