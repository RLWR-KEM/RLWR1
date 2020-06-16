OPENSSL_DIR=/usr


INCDIR   := inc
SRCDIR   := src


CC=cc

OPENSSL_INCLUDE_DIR=$(OPENSSL_DIR)/include
OPENSSL_LIB_DIR=$(OPENSSL_DIR)/lib

CFLAGS=-O3 -I$(OPENSSL_INCLUDE_DIR) -I./$(INCDIR) -I./$(INCDIR)/bch
LDFLAGS=-L$(OPENSSL_LIB_DIR) -lcrypto -lssl


all:

	$(CC) $(CFLAGS) -c main.c ./$(SRCDIR)/*.c $(LDFLAGS)
	$(CC) $(CFLAGS) *.o -o main  $(LDFLAGS)
