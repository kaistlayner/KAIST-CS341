/*
	packet.c
	- packet and socket helper functions

	Author @ Juan Lee (juanlee@kaist.ac.kr)
*/

#include "packet.h"

/*
	open_clientfd: char*, char* -> int
	- open client fd

	ref: CS230 Lecture Slides
	Note: I took this course and learned all the below codes last semester.
*/
int open_clientfd(char *hostname, char *port) {
    int clientfd, rc;
    struct addrinfo hints, *listp, *p;

    /* Get a list of potential server addresses */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM;  /* Open a connection */
    hints.ai_flags = AI_NUMERICSERV;  /* ... using a numeric port arg. */
    hints.ai_flags |= AI_ADDRCONFIG;  /* Recommended for connections */
    if ((rc = getaddrinfo(hostname, port, &hints, &listp)) != 0) {
        fprintf(stderr, "getaddrinfo failed (%s:%s)\n", hostname, port);
        return -2;
    }
  
    /* Walk the list for one that we can successfully connect to */
    for (p = listp; p; p = p->ai_next) {
        /* Create a socket descriptor */
        if ((clientfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0) 
            continue; /* Socket failed, try the next */

        /* Connect to the server */
        if (connect(clientfd, p->ai_addr, p->ai_addrlen) != -1) 
            break; /* Success */
        if (close(clientfd) < 0) { /* Connect failed, try another */  //line:netp:openclientfd:closefd
            fprintf(stderr, "open_clientfd: close failed");
            return -1;
        } 
    } 

    /* Clean up */
    freeaddrinfo(listp);
    if (!p) /* All connects failed */
        return -1;
    else    /* The last connect succeeded */
        return clientfd;
}

/*
	open_listenfd: char* -> int
	- open listen fd

	ref: CS230 Lecture Slides
*/
int open_listenfd(char *port){
	struct addrinfo hints, *listp, *p;
    int listenfd, rc, optval=1;

    /* Get a list of potential server addresses */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM;             /* Accept connections */
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG; /* ... on any IP address */
    hints.ai_flags |= AI_NUMERICSERV;            /* ... using port number */
    if ((rc = getaddrinfo(NULL, port, &hints, &listp)) != 0) {
        fprintf(stderr, "getaddrinfo failed (port %s)\n", port);
        return -2;
    }

    /* Walk the list for one that we can bind to */
    for (p = listp; p; p = p->ai_next) {
        /* Create a socket descriptor */
        if ((listenfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0) 
            continue;  /* Socket failed, try the next */

        /* Eliminates "Address already in use" error from bind */
        setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,    //line:netp:csapp:setsockopt
                   (const void *)&optval , sizeof(int));

        /* Bind the descriptor to the address */
        if (bind(listenfd, p->ai_addr, p->ai_addrlen) == 0)
            break; /* Success */
        if (close(listenfd) < 0) { /* Bind failed, try the next */
            fprintf(stderr, "open_listenfd close failed");
            return -1;
        }
    }


    /* Clean up */
    freeaddrinfo(listp);
    if (!p) /* No address worked */
        return -1;

    /* Make it a listening socket ready to accept connection requests */
    if (listen(listenfd, LISTENQ) < 0) {
        close(listenfd);
	return -1;
    }
    return listenfd;
}

/*
	safeRead: int char* int -> void
	- wait and read until required size is read
*/
void safeRead(int fd, char* dest, int size){
	char buf[MAX_BUFFER_LENGTH] = {0};

	int nRead = 0;
	while(size-nRead){
		int toRead = size-nRead < MAX_BUFFER_LENGTH-1 ? size-nRead : MAX_BUFFER_LENGTH-1;
		read(fd, buf, toRead);
		for(int i=nRead; i<nRead + strlen(buf); i++){
			dest[i] = buf[i-nRead];
		}
		nRead += strlen(buf);

		for(int i=0; i<MAX_BUFFER_LENGTH; i++){
			buf[i] = 0;
		}
	}
}

/*
	Calculate_Checksum: const Packet*, unsigned -> unsigned short
	- calculate checksum

	ref: http://locklessinc.com/articles/tcp_checksum/
*/
unsigned short Calculate_Checksum(const char* buf){
	unsigned long long sum = 0;
	unsigned t1, t2, i;
	unsigned short t3, t4;

	// for header
	const unsigned long long *header = (unsigned long long *) buf;
	for(i = 0; i < 2; i++){
		unsigned long long s = *header++;
		sum += s;
		if(sum < s) sum ++;
	}

	// for data
	const unsigned long long *b = (unsigned long long *) Packet_getData((Packet*)buf);
	unsigned size = Packet_getLength((Packet*)buf) - 16;

	/* Main loop - 8 bytes at a time */
	while (size >= sizeof(unsigned long long))
	{
		unsigned long long s = *b++;
		sum += s;
		if (sum < s) sum++;
		size -= 8;
	}

	/* Handle tail less than 8-bytes long */
	buf = (const char *) b;
	if (size & 4)
	{
		unsigned s = *(unsigned *)buf;
		sum += s;
		if (sum < s) sum++;
		buf += 4;
	}

	if (size & 2)
	{
		unsigned short s = *(unsigned short *) buf;
		sum += s;
		if (sum < s) sum++;
		buf += 2;
	}

	if (size)
	{
		unsigned char s = *(unsigned char *) buf;
		sum += s;
		if (sum < s) sum++;
	}

	/* Fold down to 16 bits */
	t1 = sum;
	t2 = sum >> 32;
	t1 += t2;
	if (t1 < t2) t1++;
	t3 = t1;
	t4 = t1 >> 16;
	t3 += t4;
	if (t3 < t4) t3++;

	return ~t3;
}

/*
	Packet_create : void -> Packet*
	- dynamically allocate new packet and return its pointer
*/
Packet* Packet_create(){
	Packet* p = (Packet*) calloc(1, sizeof(Packet));
	memset(p, 0, sizeof(Packet)); // clear Packet
	return p;
}

/*
	Packet_encrypt : Packet* -> void
	- encrypt packet and modify itself
*/
void Packet_encrypt(Packet *p){
	unsigned length = Packet_getLength(p);
	unsigned i, keyIndex = 0;

	for(i = 0; i<length; i++){
		p->data[i] = tolower(p->data[i]); // make it lower

		if(isalpha(p->data[i])){
			p->data[i] = p->data[i] + p->keyword[keyIndex++] - 'a';

			if(keyIndex == 4) keyIndex = 0;
			if(p->data[i] > 'z') p->data[i] -= 26;
		}
	}

	Packet_setChecksum(p, 0);
	unsigned short checksum = Calculate_Checksum((char*)p);
	Packet_setChecksum(p, checksum);
}

/*
	Packet_decrypt : Packet* -> void
	- decrypt packet and modify itself
*/
void Packet_decrypt(Packet *p){
	unsigned length = Packet_getLength(p);
	unsigned i, keyIndex = 0;

	for(i = 0; i<length; i++){
		p->data[i] = tolower(p->data[i]); // make it lower

		if(isalpha(p->data[i])){
			p->data[i] = p->data[i] - p->keyword[keyIndex++] + 'a';
			if(keyIndex == 4) keyIndex = 0;
			if(p->data[i] < 'a') p->data[i] += 26;
		}
	}

	Packet_setChecksum(p, 0);
	unsigned short checksum = Calculate_Checksum((char*)p);
	Packet_setChecksum(p, checksum);
}

/*
	Packet_setOperation : Packet* short -> void
	- set opcode in network order
	- 2 bytes code

	short op:
	- 0 for encrypt
	- 1 for derypt
*/
void Packet_setOperation(Packet *p, short op){
	p->op = htobe16(op);
}

/*
	Packet_getOperation : Packet* -> short
	- get operation code from packet
	- written in network order
*/
short Packet_getOperation(Packet *p){
	return be16toh(p->op);
}

/*
	Packet_setChecksum : Packet* int -> void
	- set checksum
	- 2bytes and 1's complement of data sum

	ref: http://locklessinc.com/articles/tcp_checksum/
*/
void Packet_setChecksum(Packet *p, unsigned short checksum){
	p->checksum = checksum;
}

/*
	Packet_getChecksum : Packet* -> unsigned short
	- get checksum
*/
unsigned short Packet_getChecksum(Packet *p){
	return p->checksum;
}

/*
	Packet_setKeyword : Packet* char* -> void
	- set keyword
	- 4 bytes from char* to char[4]
*/
void Packet_setKeyword(Packet *p, char* keyword){
	strncpy(p->keyword, keyword, 4); // 4 bytes
}

/*
	Packet_getKeyword : Packet* -> char*
	- get keyword
*/
char* Packet_getKeyword(Packet *p){
	return p->keyword;
}

/*
	Packet_setLength : Packet* long -> void
	- set length
	- 8 bytes and network order
*/
void Packet_setLength(Packet *p, unsigned long long length){
	p->length = htobe64(length + 16); // header is 16 bytes-length
}

/*
	Packet_getLength : Packet* -> long
	- get length
	- written in network order
*/
long Packet_getLength(Packet* p){
	return be64toh(p->length);
}

/*
	Packet_setData : Packet* char* -> void
	- copy data
*/
void Packet_setData(Packet *p, char* data){
	p->data = strdup(data);
}

/*
	Packet_getData : Packet* -> char*
	- return data without copying, so that it should be freed
*/
char* Packet_getData(Packet* p){
	return p->data;
}

/*
	Packet_sendPacket : Packet* int -> void
	- send packet into fd
*/
void Packet_sendPacket(Packet *p, int fd){
	write(fd, (char*)&p->op, 2);
	write(fd, (char*)&p->checksum, 2);
	write(fd, p->keyword, 4);
	write(fd, (char*)&p->length, 8);
	write(fd, p->data, Packet_getLength(p) - 16);
}

/*
	Packet_recvPacket : Packet* int -> void
	- receive packet from fd
*/
void Packet_recvPacket(Packet* p, int fd){
	read(fd, (char*)&p->op, 2);
	read(fd, (char*)&p->checksum, 2);
	read(fd, p->keyword, 4);
	read(fd, (char*)&p->length, 8);

	long length = Packet_getLength(p) - 16;
	p->data = (char*)calloc(length, sizeof(char));

	safeRead(fd, p->data, length);
}

/*
	Packet_destroy : Packet* -> void
	- free packet pointer
*/
void Packet_destroy(Packet* p){
	free(p->data);
	free(p);
}
