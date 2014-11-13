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

void parseArguments(char* argv[], char* parsedArgs[]) {
	if (*argv[1] == '-') {
		// We were given -ns|-mx flags and need to respond accordingly
		parsedArgs[0] = *argv[1];
	}
	else if (*argv[1] == '@') {
			//we know we have a non-default port
      parsedArgs[1] = calloc(15, sizeof(char)); // first arg is server, (xxx.xxx.xxx.xxx = 15 chars max)
      strcpy(parsedArgs[1], argv[1] + 1);
      parsedArgs[1] = strtok(parsedArgs[1], ":");
      parsedArgs[2] = calloc(5, sizeof(char)); //2nd arg is port, using default here
      char* temp = strtok(NULL, ":");
      parsedArgs[2] = 53;
      if (temp != NULL) {
        parsedArgs[2] = atoi(temp);
      }
      parsedArgs[3] = calloc(256, sizeof(char)); // 256 max domain name size, we looked this one up
      strcpy(parsedArgs[3], argv[2]);
	}
	else {
		//we shouldn't get here, this is invalid input
		printf("Error: Invalid Syntax");
	}

}

/*
The packet, the offset to where you want to start reading depending on the bits that you need the values of, and the domain name to return.
*/
int readLabel(unsigned char* packet, int* offset, char* nameToReturn, int pointerFollowed) {
  
  if (packet[*offset] != '\0') {
    // labelTag is whether or not its a pointer
    char labelTag = (packet[*offset] & 0xC0) >> 6;

    // Gonna be doing some nested for loops, need 2 counters.
    // Length of the label to read, the offset to start reading from after the label
    int charCounter, secondCharCounter, labelLength, nextOffset;

    for (secondCharCounter = 0; nameToReturn[secondCharCounter] != '\0'; secondCharCounter++) {
      if (secondCharCounter > 255)
        return -1;
    }
    if (!pointerFollowed) {
        nameToReturn[secondCharCounter] = '.';
        nameToReturn[secondCharCounter + 1] = '\0';
    }


    if (labelTag == 3) {
      //we have a pointer
      nextOffset = ntohs(*((unsigned short *)(packet + *offset))) & 0x3fff;
      readLabel(packet, &nextOffset, nameToReturn, 1);

      *offset = *offset + 2;
      return 0;      
    }
    else if (labelTag == 0) {
      //we know its not a pointer
      // Length of the label is the offset past the packet ex: 3www
      labelLength = packet[*offset];

      for (charCounter = 1; charCounter <= labelLength; charCounter++) {
        char temp = packet[*offset + charCounter];

        for (secondCharCounter = 0; nameToReturn[secondCharCounter] != '\0'; secondCharCounter++) {
          if (secondCharCounter > 255)
            return -1;
        }

        nameToReturn[secondCharCounter] = temp;
        nameToReturn[secondCharCounter + 1] = '\0';
      }

      *offset = *offset + labelLength + 1;
      readLabel(packet, offset, nameToReturn, 0);
    }    
    else {
      return -1;
    }
  }
  *offset = *offset + 1;
  return 0;
}

int main(int argc, char *argv[]) {
  /**
   * I've included some basic code for opening a socket in C, sending
   * a UDP packet, and then receiving a response (or timeout).  You'll 
   * need to fill in many of the details, but this should be enough to
   * get you started.
   */

  // process the arguments
   char* parsedArgs[4];
   parseArguments(argv, parsedArgs);

  // construct the DNS request
   int domainLen = 0;
   if (*argv[1] == '-') {
		domainLen = strlen(argv[3]);
   }
   else {
 		domainLen = strlen(argv[2]);
   }

   char* domainName = parsedArgs[3];
   char* question = calloc(domainLen + 6, sizeof(char));
   int offset = 0;
   int lengthOfSubdomain = 0;
   while (offset < domainLen) {
	   while (domainName[offset] != '.' && domainName[offset] != '\0') {
	   		question[offset+1] = domainName[offset];
	   		lengthOfSubdomain++;
	   		offset++;
		}
		question[offset-lengthOfSubdomain] = lengthOfSubdomain;
		lengthOfSubdomain = 0;
		offset++;
	}

	//null terminator
	question[domainLen + 1] = 0x0;
	//QTYPE
   	question[domainLen + 2] = 0x0;
   	question[domainLen + 3] = 0x1; //A Record
   	//QCLASS = 1
   	question[domainLen + 4] = 0x0;
   	question[domainLen + 5] = 0x1;

   unsigned char header[12];
   //id is 1337
   header[0] = 0x05;
   header[1] = 0x39; 
   //qr is 0, opcode is 0000, AA is 0, TC is 0, RD is 1
   header[2] = 0x1; 
   //RA is 0, Z is 000, RCODE is 0000
   header[3] = 0x0;
   //QDCOUNT = 1
   header[4] = 0x0;
   header[5] = 0x1; 
   //ANCOUNT = 0
   header[6] = 0x0; 
   header[7] = 0x0; 
   //NSCOUNT = 0
   header[8] = 0x0; 
   header[9] = 0x0;
   //ARCOUNT = 0
   header[10] = 0x0; 
   header[11] = 0x0; 

   char* packet = calloc(domainLen + 18, sizeof(char));
   memcpy(packet, header, 12);
   memcpy(packet+12, question, domainLen+6);

  // send the DNS request (and call dump_packet with your request)
  dump_packet(packet, domainLen + 18);

  // first, open a UDP socket  
  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  // next, construct the destination address
  struct sockaddr_in out;
  out.sin_family = AF_INET;
  out.sin_port = htons(parsedArgs[2]);
  out.sin_addr.s_addr = inet_addr(parsedArgs[1]);

  if (sendto(sock, packet, domainLen + 18, 0, &out, sizeof(out)) < 0) {
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

  char inputBuffer[188];
  // wait to receive, or for a timeout
  if (select(sock + 1, &socks, NULL, NULL, &t)) {
    if (recvfrom(sock, inputBuffer, 188, 0, &in, &in_len) < 0) {
      // an error occured
    }
  } else {
    // a timeout occurred
    printf("NORESPONSE\n");
    return -1;
  }

  // print out the result
  char* authType;
  unsigned short ID = ntohs(*((unsigned short *) inputBuffer));
  unsigned char QR = (*(inputBuffer+2) & 0x80) >> 7;
  unsigned char OPCODE = (*(inputBuffer+2) & 0x78) >> 3;
  unsigned char AA = (*(inputBuffer+2) & 0x4) >> 2;
  unsigned char TC = (*(inputBuffer+2) & 0x2) >> 1;
  unsigned char RA = (*(inputBuffer+2) & 0x80) >> 7;
  unsigned char RCODE = *(inputBuffer + 3) & 0xF;

  if (ID != 0x539) {
      printf("We got someone else's packet. Stealing all the money out of it");
      return -1;
  }

  if (QR != 1) {
    printf("The QR was wrong");
    return -1;
  }

  if (OPCODE) {
    printf("The OPCODE was wrong");
    return -1;
  }

  if (AA) {
    authType = "auth";
  }
  else {
    authType = "nonauth";
  }

  if (TC) {
    printf("Message got truncated");
    return -1;
  }

  if (!RA) {
    printf("Recursion didnt work");
    return -1;
  }

  switch(RCODE) {
    case 0:
      break;
    case 1:
      printf("Format Error\n"); 
      return -1;
    case 2:
      printf("Server Failure\n"); 
      return -1;
    case 3:
      printf("NOTFOUND\n");
      return -1;
    case 4:
      printf("Not Implemented\n");
      return -1;
    case 5:
      printf("Refused\n");
      return -1;
    default:
      printf("Bad RCODE");
      return -1;
  }

  unsigned short QDCOUNT = ntohs(*((unsigned short *)(inputBuffer + 4)));
  unsigned short ANCOUNT = ntohs(*((unsigned short *)(inputBuffer + 6)));

  //16 to skip past the header
  int nameOffset = 20 + domainLen;

  for(int i = 0; i < ANCOUNT; i++) {
    char nameReturned[256] = {0};
    unsigned char ipReturned[5] = {0};
    //printf("\n%i\n", ANCOUNT);
    unsigned short ATYPE = ntohs(*((unsigned short *)(inputBuffer + nameOffset)));
    nameOffset += 10; // skip past a bunch of stuff

    //dump_packet(inputBuffer, 188);
    
    //printf("%d\t%d\n", ATYPE, 0x0001);

    if (ATYPE == 0x0001) {
      ipReturned[0] = *(inputBuffer + nameOffset);
      nameOffset++;
      ipReturned[1] = *(inputBuffer + nameOffset);
      nameOffset++;
      ipReturned[2] = *(inputBuffer + nameOffset);
      nameOffset++;
      ipReturned[3] = *(inputBuffer + nameOffset);
      nameOffset++;
      printf("IP\t%d.%d.%d.%d\t%s\n", ipReturned[0], ipReturned[1], ipReturned[2], ipReturned[3], authType);
    }
    else if (ATYPE == 0x0005) {
      readLabel(inputBuffer, &nameOffset, nameReturned, 1);
      printf("CNAME\t%s\t%s\n", nameReturned, authType);
      nameOffset++;
    }
    else {
      //printf("\nsome random bullshit\n");
    }
  }

  return 0;
}
