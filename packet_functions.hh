#include <click/config.h>
CLICK_DECLS

/*
	Creates a new packet with new packet header
*/
WritablePacket * GenericEncap(Packet * p, uint8_t * header, unsigned int header_length);

/*
	Removes header and saves it into header argument;
	Assumes header is a valid data size;
*/
WritablePacket * GenericDencap(Packet * p, uint8_t * header, unsigned int header_length);

/*
	Removes header and saves it into header argument;
	Assumes header is a valid data size;
*/
void getHeader(Packet * p, uint8_t * header, unsigned int header_length);
