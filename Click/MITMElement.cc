#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "MITMElement.hh"

CLICK_DECLS

MITMElement::MITMElement(){this->maxSize = 4048;}
MITMElement::~MITMElement(){}

int MITMElement::configure(Vector<String> &conf, ErrorHandler * errh)
{
	/*
	if (cp_va_kparse(conf, this, errh, "MAXPACKETSIZE", cpkM, cpInteger, &maxSize, cpEnd) < 0)
	{
		;//return -1;
	}
	*/
	if (maxSize <= 0)
	{
		return errh->error("maxsize should be larger than 0");
	}
	
	return 0;
}

int get_port(int port, Packet *p)
{
	if (p == NULL)	return -1;
	if (port == 0)	return 1;
	if (port == 1)	return 0;
	return -1;
}

Packet * process(Packet *p)
{
	return p;
}

void MITMElement::push(int port, Packet *p)
{
	int output_port = -1;
	Packet * output_packet = NULL;
	
	click_chatter("Got a packet of size %d",p->length());
	if (p->length() > maxSize)
	{
		p->kill();
	}
	else
	{
		output_port = get_port(port, p);
		output_packet = process(p);
		
		if (output_port == -1 || output_packet->length() > maxSize)
		{
			if (p != output_packet)
			{
				p->kill();				
			}
			output_packet->kill();
		}
		else
		{
			output(output_port).push(output_packet);			
		}
	}
}

CLICK_ENDDECLS
EXPORT_ELEMENT(MITMElement)
