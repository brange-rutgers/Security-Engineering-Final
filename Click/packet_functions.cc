#include "packet_functions.hh"
CLICK_DECLS
/*
	Creates a new packet with new packet header
*/
WritablePacket * GenericEncap(Packet * p, uint8_t * header, unsigned int header_length)
{
	WritablePacket * w;
	
	if (p == NULL || header == NULL) return NULL;
	
	std::string data = std::string(header, header_length);
	data += std::string(p->data(), p->length());
	w = Packet::make(data.c_str(), data.length());
	return w;
}

/*
	Removes header and saves it into header argument;
	Assumes header is a valid data size;
*/
WritablePacket * GenericDencap(Packet * p, uint8_t * header, unsigned int header_length)
{
	WritablePacket * w;
	int w_length = p->length() - header_length;
	
	if (p == NULL || header == NULL) return NULL;
	if (w_length < 1) return NULL;
	
	char * data = (char *) malloc(w_length);
	memcpy(header, p->data(), header_length);
	memcpy(data, p->data() + header_length, w_length);
	w = Packet::make(data, w_length);
	free(data);
	return w;
}

/*
	Removes header and saves it into header argument;
	Assumes header is a valid data size;
*/
void getHeader(Packet * p, uint8_t * header, unsigned int header_length)
{
	int w_length = p->length() - header_length;
	
	if (p == NULL || header == NULL) return NULL;
	if (w_length < 1) return NULL;
	
	memcpy(header, p->data(), header_length);
}
CLICK_ENDDECLS
ELEMENT_REQUIRES(userlevel|ns)
ELEMENT_PROVIDES(packet_functions)
