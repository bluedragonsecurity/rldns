OBJ = obj
SRC = src

all : rldns

rldns : main.o  
	gcc -Wall -fPIC -pthread -fstack-protector-all -o rldns $(OBJ)/main.o 

main.o : $(SRC)/main.c $(SRC)/vars.h $(SRC)/structs.h $(SRC)/oops.h $(SRC)/headers.h 
	gcc -Wall -fPIC -pthread -fstack-protector-all -c $(SRC)/main.c -o $(OBJ)/main.o 

clean: 
	rm -f $(OBJ)/*

install:
	rm -rf /usr/local/rldns;mkdir /usr/local/rldns
	mkdir /usr/local/rldns/zones		
	cp rldns /usr/local/rldns
	cp rldns.conf /usr/local/rldns
	cp zones/* /usr/local/rldns/zones
	cp docs/rldns.1 /usr/share/man/man1
