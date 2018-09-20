/*
	packet.h
	- packet and socket helper functions

	Author @ Juan Lee (juanlee@kaist.ac.kr)
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <ctype.h>
#include "endian.h"

/* Constraints */
#define MAX_BUFFER_LENGTH 1024
#define MAX_PACKET_LENGTH 1024*1024*10
#define LISTENQ 1024
#define PACKET_ROW 64

/* Typedef Structure */
typedef struct sockaddr SA;

/* Socket Helper Function */
int open_clientfd(char *hostname, char *port);
int open_listenfd(char *port);
void safeRead(int fd, char* dest, int size);
unsigned short Calculate_Checksum(const char* buf);

typedef struct POOL{
	int maxfd;
	fd_set read_set, ready_set;
	int nready;
	int maxi;
	int clientfd[FD_SETSIZE];
} pool;

/* Protocols */
typedef struct PACKET{
	short op;
	unsigned short checksum;
	char keyword[4];
	unsigned long long length;
	char *data;
} Packet;

Packet* Packet_create();

void Packet_encrypt(Packet *p);
void Packet_decrypt(Packet *p);

void Packet_setOperation(Packet *p, short op);
short Packet_getOperation(Packet *p);

void Packet_setChecksum(Packet *p, unsigned short checksum);
unsigned short Packet_getChecksum(Packet *p);

void Packet_setKeyword(Packet *p, char* keyword);
char* Packet_getKeyword(Packet *p);

void Packet_setLength(Packet *p, unsigned long long length);
long Packet_getLength(Packet *p);

void Packet_setData(Packet *p, char* data);
char* Packet_getData(Packet *p);

void Packet_sendPacket(Packet *p, int fd);
void Packet_recvPacket(Packet *p, int fd);

void Packet_destroy(Packet* p);