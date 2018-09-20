all : client.o server.o server_select.o packet.o
	gcc -o client client.o packet.o
	gcc -o server server.o packet.o
	gcc -o server_select server_select.o packet.o

server_select.o : server_select.c
	gcc -c -o server_select.o server_select.c

server.o : server.c
	gcc -c -o server.o server.c

client.o : client.c
	gcc -c -o client.o client.c

packet.o : packet.c
	gcc -c -o packet.o packet.c

clean :
	rm client server server_select *.o