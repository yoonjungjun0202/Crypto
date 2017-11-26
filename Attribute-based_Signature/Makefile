CC = gcc
LIBS = -lpbc -lgmp -lcrypto
TARGET = abs
OBJECTS = myVector.o myPoly.o myPredicate.o abs.o

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ $(LIBS)
	rm *.o

clean: 
	rm abs
