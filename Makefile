CC		:= gcc
CFLAGS	:=
LDFLAGS	:= -fPIC -shared

all:
	$(CC) $(CFLAGS) $(LDFLAGS) -c deferred_plugin.c
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,-soname,deferred_plugin.so -o deferred_plugin.so deferred_plugin.o

clean:
	rm -f *.o
	rm -f *.so
