
TARGET  := libdghv.a
CC      := g++
AR      = ar
RANLIB  = ranlib
LIBS    := -lstdc++ -lgmpxx -lgmp -lm
LDFLAGS :=
DEFINES :=
INCLUDE := -I.
DEBUGFLAGS	:= -g -DDEBUG -O0
RELEASEFLAGS:= -O3
CFLAGS  := -Wall $(DEBUGFLAGS) $(DEFINES) $(INCLUDE)
CXXFLAGS:= $(CFLAGS) -DHAVE_CONFIG_H

SOURCE  := $(wildcard *.c) $(wildcard *.cpp)
OBJS    := $(patsubst %.c,%.o,$(patsubst %.cpp,%.o,$(SOURCE)))

.PHONY : everything objs clean veryclean rebuild

everything : $(TARGET)

all : $(TARGET)

objs : $(OBJS)

rebuild: veryclean everything

clean :
	rm -fr *.o

veryclean : clean
	rm -fr $(TARGET)

$(TARGET) : $(OBJS)
	$(AR) cru $(TARGET) $(OBJS)
	$(RANLIB) $(TARGET)
