/*
 * CS3600, Spring 2014
 * Project 2 Starter Code
 * (c) 2013 Alan Mislove
 *
 */

#ifndef __3600DNS_H__
#define __3600DNS_H__

static const unsigned short ID = 1337;
static const unsigned short QDCOUNT = 1;
static const unsigned short ANCOUNT = 0;
static const unsigned short NSCOUNT = 0;
static const unsigned short ARCOUNT = 0;

typedef struct secondRow_s {
	unsigned short QR : 1;
	unsigned short OPCODE : 4;
	unsigned short AA : 1;
	unsigned short TC : 1;
	unsigned short RD : 1;
	unsigned short RA : 1;
	unsigned short Z : 3;
	unsigned short RCODE : 4;
} secondRow;

#endif

