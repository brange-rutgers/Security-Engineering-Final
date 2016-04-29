#ifndef CLICK_MITMELEMENT_HH
#define CLICK_MITMELEMENT_HH
#include <click/element.hh>

CLICK_DECLS

class MITMElement : public Element
{
	public:
		MITMPushElement();
		~MITMPushElement();
		const char *class_name() const { return "MITMElement";}
		const char *port_count() const { return "2/2"; }
		const char *processing() const { return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);
		void push(int port, Packet *);
	
	private: uint32_t maxSize;
};

CLICK_ENDDECLS
#endif
