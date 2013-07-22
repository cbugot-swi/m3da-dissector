 

bysant: 
	$(CC) -I/usr/include/lua5.1 -o bysant.so -shared -fPIC bysant_class.c bysantd.c bysant_common.c lbysantd.c awt_endian.c

clean:
	rm -f *.o *.so