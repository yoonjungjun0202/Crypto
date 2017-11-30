CC = gcc
LIBS = -lcrypto
TARGET = elgamal
OBJECTS = elgamal_signature.o

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ $(LIBS)
	rm *.o

clean:
	rm $(TARGET)
