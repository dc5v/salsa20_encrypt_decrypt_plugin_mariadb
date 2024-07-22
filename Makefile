CC = gcc
CFLAGS = -fPIC -Wall -I/usr/include/mysql
LIBS = -lsodium -lmysqlclient
TARGET = salsa20_encrypt_decrypt_plugin.so

all: $(TARGET)

$(TARGET): salsa20_encrypt_decrypt_plugin.o
	$(CC) -shared -o $@ $^ $(LIBS)

salsa20_encrypt_decrypt_plugin.o: salsa20_encrypt_decrypt_plugin.c
	$(CC) $(CFLAGS) -c salsa20_encrypt_decrypt_plugin.c

clean:
	rm -f *.o $(TARGET)

.PHONY: all clean
