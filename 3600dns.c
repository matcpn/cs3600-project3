/*
 * CS3600, Spring 2014
 * Project 3 Starter Code
 * (c) 2013 Alan Mislove
 *
 */

#include <math.h>
#include <ctype.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "3600dns.h"

/**
 * This function will print a hex dump of the provided packet to the screen
 * to help facilitate debugging.  In your milestone and final submission, you 
 * MUST call dump_packet() with your packet right before calling sendto().  
 * You're welcome to use it at other times to help debug, but please comment those
 * out in your submissions.
 *
 * DO NOT MODIFY THIS FUNCTION
 *
 * data - The pointer to your packet buffer
 * size - The length of your packet
 */
static void dump_packet(unsigned char *data, int size) {
    unsigned char *p = data;
    unsigned char c;
    int n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[ 16*3 + 5] = {0};
    char charstr[16*1 + 5] = {0};
    for(n=1;n<=size;n++) {
        if (n%16 == 1) {
            /* store address for this line */
            snprintf(addrstr, sizeof(addrstr), "%.4x",
               ((unsigned int)p-(unsigned int)data) );
        }
            
        c = *p;
        if (isprint(c) == 0) {
            c = '.';
        }

        /* store hex str (for left side) */
        snprintf(bytestr, sizeof(bytestr), "%02X ", *p);
        strncat(hexstr, bytestr, sizeof(hexstr)-strlen(hexstr)-1);

        /* store char str (for right side) */
        snprintf(bytestr, sizeof(bytestr), "%c", c);
        strncat(charstr, bytestr, sizeof(charstr)-strlen(charstr)-1);

        if(n%16 == 0) { 
            /* line completed */
            printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        } else if(n%8 == 0) {
            /* half line: add whitespaces */
            strncat(hexstr, "  ", sizeof(hexstr)-strlen(hexstr)-1);
            strncat(charstr, " ", sizeof(charstr)-strlen(charstr)-1);
        }
        p++; /* next byte */
    }

    if (strlen(hexstr) > 0) {
        /* print rest of buffer if not empty */
        printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
}

int findTheColon(char* c) {
	for (int i = 0; *(c + i) != '\0'; i++) {
		if (*(c + i) == ':') {
			return i;
		}
	}
	return -1;
} 

//return location of dot
int findNextDot(char* domain) {
	int i = 0;
	for (; *(domain + i) != '\0'; i++) {
		if(*(domain + i) == '.') {
			return i;
		}
	}
	if (*(domain + i) == '\0') {
		return i;
	}
	return -1;
}

void parseArguments(char* argv[], char** parsedArgs, int* numberOfDots) {
	if (*argv[1] == '-') {
		// We were given -ns|-mx flags and need to respond accordingly
	}
	else if (*argv[1] == '@') {
		int colonLocation = findTheColon(argv[1]);
		if (colonLocation > 0) {
			//we know we have a port
		}
		else {
			//use DEFAULTPORT global variable
			**parsedArgs = calloc(15, sizeof(char)); // first arg is server, (xxx.xxx.xxx.xxx = 15 chars max)
			strcpy(*parsedArgs, argv[1] + 1);
			**(parsedArgs + 1) = calloc(2, sizeof(char)); //2nd arg is port, using default here
			**(parsedArgs + 1) = DEFAULTPORT;
			char* domain = calloc(256, sizeof(char)); // 256 max domain name size, we looked this one up
			strcpy(domain, argv[2]);
			int i = 2; //starting point for the dynamic array
			while(*domain != '\0') {
				int nextDot = findNextDot(domain);
				if (nextDot > 0) {
					**(parsedArgs + i) = calloc(nextDot + 1, sizeof(char));
					sprintf(**(parsedArgs + i), "%d", nextDot);
					strncpy(**(parsedArgs + i) + 1, domain, nextDot);
					domain = *(domain + nextDot);
					i++;
					*numberOfDots++;
				}
			}
		}
	}
	else {
		//we shouldn't get here, this is invalid input
		printf("Error: Invalid Syntax");
	}

}

int main(int argc, char *argv[]) {
  /**
   * I've included some basic code for opening a socket in C, sending
   * a UDP packet, and then receiving a response (or timeout).  You'll 
   * need to fill in many of the details, but this should be enough to
   * get you started.
   */

  // process the arguments
   char** parsedArgs;
   int numberOfDots = 0;
   parseArguments(argv, parsedArgs, &numberOfDots);

  // construct the DNS request
   int domainLen = 0;
   if (*argv[1] == '-') {
		domainLen = strlen(argv[2]);
   }
   else {
 		domainLen = strlen(argv[1]);
   }
   char* question = calloc(domainLen+2, sizeof(char));
   for (int i = 2; i < numberOfDots + 2; i++) {
   	strcat(question, **(parsedArgs + i));
   }
   *(question + domainLen + 1) = 0x0;
   *(question + domainLen + 2) = 0x0;

   char* header = calloc(12, sizeof(char));
   //id is 1337
   *header = 0x05;
   *(header + 1) = 0x39; 
   //qr is 0, opcode is 0000, AA is 0, TC is 0, RD is 1
   *(header + 2) = 0x1; 
   //RA is 0, Z is 000, RCODE is 0000
   *(header + 3) = 0x0;
   //QDCOUNT = 1
   *(header + 4) = 0x0;
   *(header + 5) = 0x1; 
   //ANCOUNT = 0
   *(header + 6) = 0x0; 
   *(header + 7) = 0x0; 
   //NSCOUNT = 0
   *(header + 8) = 0x0; 
   *(header + 9) = 0x0;
   //ARCOUNT = 0
   *(header + 10) = 0x0; 
   *(header + 11) = 0x0; 

   char* packet = calloc(domainLen + 14, sizeof(char));
   strcpy(packet, header);
   strcat(packet, question);

  // send the DNS request (and call dump_packet with your request)
  
  // first, open a UDP socket  
  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  // next, construct the destination address
  struct sockaddr_in out;
  out.sin_family = AF_INET;
  out.sin_port = htons(**(parsedArgs + 1));
  out.sin_addr.s_addr = inet_addr(**parsedArgs);

  if (sendto(sock, packet, domainLen + 14, 0, &out, sizeof(out)) < 0) {
    // an error occurred
  }

  // wait for the DNS reply (timeout: 5 seconds)
  struct sockaddr_in in;
  socklen_t in_len;

  // construct the socket set
  fd_set socks;
  FD_ZERO(&socks);
  FD_SET(sock, &socks);

  // construct the timeout
  struct timeval t;
  t.tv_sec = 5;
  t.tv_usec = 0;

  char inputBuffer[65536];
  // wait to receive, or for a timeout
  if (select(sock + 1, &socks, NULL, NULL, &t)) {
    if (recvfrom(sock, inputBuffer, 65536, 0, &in, &in_len) < 0) {
      // an error occured
    }
  } else {
    // a timeout occurred
  }

  // print out the result
  
  return 0;
}
