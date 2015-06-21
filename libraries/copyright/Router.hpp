#include "Node.hpp"

class Router : public Node
{
    public:
        pcap_if_t *interfaceIndex;
        unsigned int res, inum;
        unsigned char *ARPRequestBuffer;


        Router(unsigned int interfaceNumber, const char *IP, const char *MAC)
        : Node(interfaceNumber, IP, MAC)
        {
            interfaceIndex = getInterfaceIndex(interfaceNumber);
            ARPRequestBuffer = getARPRequestBuffer();
        }


        ~Router()
        {
            delete ARPRequestBuffer;
        }


        pcap_if_t * getInterfaceIndex(unsigned int interfaceNumber)
        {
            unsigned int i;
            pcap_if_t *alldevs, *d;
            unsigned char errbuf[PCAP_ERRBUF_SIZE];

            pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, (char *)errbuf);
            for (d = alldevs, i = 0; i < interfaceNumber-1; d = d->next, i++);

            return d;
        }


        unsigned char *getARPRequestBuffer()
        {
            unsigned char *buffer = (unsigned char *)new int8_t[42];
            static unsigned char broadcastMAC[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

            Ethernet *EthernetDatagram = new Ethernet (buffer);
            EthernetDatagram->setSource(MAC);
            EthernetDatagram->setDestination(broadcastMAC);
            EthernetDatagram->setType(ETHERNET_ARP);

            ARP *ARPDatagram = new ARP (buffer, EthernetDatagram);
            ARPDatagram->setHardware(1);
            ARPDatagram->setProcotocol(2048);
            ARPDatagram->setHardwareAddressLength(6);
            ARPDatagram->setProcotolAddressLength(4);
            ARPDatagram->setOpCode(1);
            ARPDatagram->setSourceMAC(MAC);
            ARPDatagram->setSourceIPv4(IP);
            ARPDatagram->setDestinationMAC(broadcastMAC);

            delete EthernetDatagram;
            delete ARPDatagram;

            return buffer;
        }


        unsigned char *getARPRequest(unsigned char *buffer, int32_t IP)
        {
            unsigned char *ARPRequest = (unsigned char *)new int8_t[42];
            memcpy(ARPRequest, buffer, 42);

            Ethernet *EthernetDatagram = new Ethernet(ARPRequest);
            ARP *ARPDatagram = new ARP (ARPRequest, EthernetDatagram);
            ARPDatagram->setDestinationIPv4(IP);

            // ARPDatagram->prepareDataForEthernetAndIPv4();
            // EthernetDatagram->show();
            // ARPDatagram->show();


            delete EthernetDatagram;
            delete ARPDatagram;

            return ARPRequest;
        }


        unsigned char *getMAC(const char *IP)
        {
            return getMAC(inet_addr(IP));
        }


        unsigned char *getMAC(int32_t IP)
        {
            unsigned char errbuf[PCAP_ERRBUF_SIZE];
            const unsigned char *pkt_data;
            struct pcap_pkthdr *header;

            Ethernet *EthernetDatagram;
            ARP *ARPDatagram;

            unsigned char *result, *ARPRequest = getARPRequest(ARPRequestBuffer, IP);

            pcap_t *fp = pcap_open_live(interfaceIndex->name, 65535, PCAP_OPENFLAG_PROMISCUOUS, 1, (char *)errbuf);

            pcap_sendpacket(fp, ARPRequest, 42);
            while((res = pcap_next_ex( fp, &header, &pkt_data)) >= 0)
            {
                if (res == 0)
                    continue;

                EthernetDatagram = new Ethernet((unsigned char*)pkt_data);

                if (ntohs(EthernetDatagram->header->type) == ETHERNET_ARP)
                {
                    // EthernetDatagram->show();

                    ARPDatagram = new ARP((unsigned char*)pkt_data, EthernetDatagram);

                    if (ARPDatagram->isSimpleReply() && ARPDatagram->protocolIsIPv4() && ARPDatagram->hardwareIsEthernet())
                    {
                        ARPDatagram->prepareDataForEthernetAndIPv4();

                        if (ARPDatagram->sourceIPv4is(IP))
                        {
                            // ARPDatagram->show();
                            result = new uint8_t[6];
                            memcpy(result, ARPDatagram->data->src_mac, 6);
                            break;
                        }
                    }

                    delete ARPDatagram;
                }

                delete EthernetDatagram;
            }

            pcap_close(fp);

            delete ARPRequest;

            return result;
        }
};
