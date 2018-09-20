/*
	client.c
	- client program for project 1

	Author @ Juan Lee (juanlee@kaist.ac.kr)
*/

#include "packet.h"

int main(int argc, char *argv[]){
	int clientfd, i, length, tmpLength;
	char buf[MAX_BUFFER_LENGTH] = {0};
	char *data;
	char *host = NULL, *port = NULL, *keyword = NULL, *op = NULL;
	unsigned short checksum;

	// data up to 10MB
	data = (char*)calloc(1, MAX_PACKET_LENGTH);

	if(argc != 9){
		free(data);
		fprintf(stderr, "Argument Error\n");
		return -1;
	}

	// assign parameters
	for(i = 1; i<9; i++){
		if(strcmp(argv[i], "-h") == 0){
			host = argv[i+1];
		}
		else if(strcmp(argv[i], "-k") == 0){
			keyword = argv[i+1];
		}
		else if(strcmp(argv[i], "-p") == 0){
			port = argv[i+1];
		}
		else if(strcmp(argv[i], "-o") == 0){
			op = argv[i+1];
		}
	}

	if(host == NULL || port == NULL || keyword == NULL || op == NULL){
		free(data);
		fprintf(stderr, "Argument Failed\n");
		return -1;
	}

	if((clientfd = open_clientfd(host, port)) < 0){
		free(data);
		fprintf(stderr, "Connect Failed\n");
		return -1;
	}

	// read data from stdin
	length = 0;
	while(fgets(buf, MAX_BUFFER_LENGTH-1, stdin) != NULL){
		tmpLength = strlen(buf);
		
		// copy buffer
		for(i = length; i<length+tmpLength; i++){
			data[i] = buf[i - length];
		}
		length += tmpLength;

		// clear buffer
		for(i=0; i<MAX_BUFFER_LENGTH; i++){
			buf[i] = 0;
		}
	}


	// send packets
	Packet *packet = Packet_create();
	Packet_setOperation(packet, atoi(op));
	Packet_setKeyword(packet, keyword);
	Packet_setLength(packet, length);
	Packet_setData(packet, data);

	checksum = Calculate_Checksum((char*)packet);

	Packet_setChecksum(packet, checksum);

	Packet_sendPacket(packet, clientfd);

	Packet_destroy(packet);
	free(data);

	// recv packet
	packet = Packet_create();

	Packet_recvPacket(packet, clientfd);

	unsigned short recvChecksum = Packet_getChecksum(packet);
	Packet_setChecksum(packet, 0);
	unsigned short calcChecksum = Calculate_Checksum((char*)packet);

	if(recvChecksum == calcChecksum)
		printf("%s", packet->data);

	// check checksum
	Packet_destroy(packet);

	// close fd
	close(clientfd);

	return 0;
}
