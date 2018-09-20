/*
	server.c
	- server program for project 1

	Author @ Juan Lee (juanlee@kaist.ac.kr)
*/

#include "packet.h"

int main(int argc, char *argv[]){
	int listenfd, connfd, i;
	socklen_t clientlen;
	char *port = NULL;
	struct sockaddr_storage clientaddr;

	if(argc != 3){
		fprintf(stderr, "Argument Error\n");
		return -1;
	}

	// assign parameters
	for(i = 1; i<3; i++){
		if(strcmp(argv[i], "-p") == 0){
			port = argv[i+1];
		}
	}

	if(port == NULL){
		fprintf(stderr, "Argument Failed\n");
		return -1;
	}

	if((listenfd = open_listenfd(port)) < 0){
		fprintf(stderr, "Listen Failed\n");
		return -1;
	}

	// main loop of server
	clientlen = sizeof(struct sockaddr_storage);
	while(1){
		if((connfd = accept(listenfd, (SA*)&clientaddr, &clientlen)) < 0){
			fprintf(stderr, "Accept Failed\n");
			continue;
		}

		if(fork() == 0) { // for client
			Packet *packet = Packet_create();
			Packet_recvPacket(packet, connfd);

			// Reject protocol violation
			unsigned short recvChecksum = Packet_getChecksum(packet);
			Packet_setChecksum(packet, 0);
			unsigned short calcChecksum = Calculate_Checksum((char*)packet);
			if(recvChecksum != calcChecksum){
				close(connfd);
				exit(0);
			}

			if(Packet_getOperation(packet) == 0){ // 0 for encrypt
				Packet_encrypt(packet);
			}
			else if(Packet_getOperation(packet) == 1){
				Packet_decrypt(packet);
			}

			Packet_sendPacket(packet, connfd);
			Packet_destroy(packet);

			close(connfd);
			exit(0);
		}
		else { // for server
			close(connfd);
		}
	}

	close(listenfd);
	return 0;
}
