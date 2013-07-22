
all: checks.so bysant.so

checks.so: checks.c checks.h
	$(CC) -I/usr/include/lua5.1 -o checks.so -shared -fPIC checks.c

bysant.so: bysant_class.c bysantd.c bysant_common.c lbysantd.c awt_endian.c awt_endian.h bysantd.h  bysant.h
	$(CC) -I/usr/include/lua5.1 -o bysant.so -shared -fPIC bysant_class.c bysantd.c bysant_common.c lbysantd.c awt_endian.c

clean:
	rm -f *.o *.so