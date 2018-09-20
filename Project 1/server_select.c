/*
	server_select.c
	- select version of server program for project 1

	Author @ Juan Lee (juanlee@kaist.ac.kr)
*/

#include "packet.h"

int main(int argc, char *argv[]){
	int listenfd, connfd, i;
	socklen_t clientlen; 
	struct sockaddr_in clientaddr, serveraddr; 
	char* port;
	static pool pool;

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

	pool.maxi = -1;    
    for (i=0; i< FD_SETSIZE; i++) 
        pool.clientfd[i] = -1;  
 
    /* Initially, listenfd is only member of select read set */ 
    pool.maxfd = listenfd;  
    FD_ZERO(&pool.read_set); 
    FD_SET(listenfd, &pool.read_set);   

    clientlen = sizeof(struct sockaddr_in);
	while (1) {
		pool.ready_set = pool.read_set; 
		pool.nready = select(pool.maxfd+1, &pool.ready_set, NULL, NULL, NULL); 
 
		if (FD_ISSET(listenfd, &pool.ready_set)) { 
			connfd = accept(listenfd, (SA *)&clientaddr, &clientlen); 
			
			pool.nready--;
			for(i=0; i<FD_SETSIZE; i++){
				if(pool.clientfd[i] < 0){
					pool.clientfd[i] = connfd;
					FD_SET(connfd, &pool.read_set);

					if(connfd > pool.maxfd)
						pool.maxfd = connfd;
					if(i > pool.maxi)
						pool.maxi = i;

					break;
				}
			}
			if(i == FD_SETSIZE){
				fprintf(stderr, "Too many clients\n");
			}
		}

		for(i = 0; (i <= pool.maxi) && pool.nready > 0; i++){
			connfd = pool.clientfd[i];

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
			FD_CLR(connfd, &pool.read_set);
			pool.clientfd[i] = -1;
		}
	} 

	close(listenfd);
	return 0;
}