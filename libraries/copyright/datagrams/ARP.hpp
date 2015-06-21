class ARP
{
    public:

        #pragma pack(push, 1)
        // Header ARP
        typedef struct Header
        {
            uint16_t hardware;
            uint16_t protocol;
            uint8_t hardware_address_length;
            uint8_t protocol_address_length;
            uint16_t opcode;
        };

        typedef struct EthernetAndIPv4Data
        {
            uint8_t src_mac[6];
            uint32_t src_addr;
            uint8_t dst_mac[6];
            uint32_t dst_addr;
        };
        #pragma pack(pop)


        Ethernet *EthernetDatagram;
        Header *header;
        EthernetAndIPv4Data *data;


        uint16_t length;
        uint16_t offset;
        unsigned char *buffer;


        ARP (unsigned char *buffer, Ethernet *EthernetDatagram)
        {
            this->EthernetDatagram = EthernetDatagram;
            this->buffer = buffer + this->EthernetDatagram->offset;
            header = (Header *)this->buffer;
        }


        bool hardwareIsEthernet()
        {
            return (ntohs(header->hardware) == 1);
        }


        bool protocolIsIPv4()
        {
            return (ntohs(header->protocol) == 2048);
        }

        bool sourceIPv4is(uint32_t IP)
        {
            return (data->src_addr == IP);
        }

        bool ipv4RequestedIs(uint32_t IP)
        {
            return (data->dst_addr == IP);
        }

        bool isSimpleRequest()
        {
            return (ntohs(header->opcode) == 1);
        }

        bool isSimpleReply()
        {
            return (ntohs(header->opcode) == 2);
        }


        void prepareDataForEthernetAndIPv4()
        {
            data = (EthernetAndIPv4Data *)(buffer + sizeof(Header));
            length = sizeof(Header) + sizeof(EthernetAndIPv4Data);
            offset = length + EthernetDatagram->offset;
        }


        void setHardware(uint16_t hardware)
        {
            hardware = ntohs(hardware);
            memcpy(buffer, (unsigned char *)&hardware, 2);
        }


        void setProcotocol(uint16_t protocol)
        {
            protocol = ntohs(protocol);
            memcpy(buffer+2, (unsigned char *)&protocol, 2);
        }


        void setHardwareAddressLength(uint8_t length)
        {
            memcpy(buffer+4, (unsigned char *)&length, 1);
        }


        void setProcotolAddressLength(uint8_t length)
        {
            memcpy(buffer+5, (unsigned char *)&length, 1);
        }


        void setOpCode(uint16_t code)
        {
            code = ntohs(code);
            memcpy(buffer+6, (unsigned char *)&code, 2);
        }

        void setSourceMAC(unsigned char *MAC)
        {
             memcpy(buffer+8, MAC, 6);
        }

        void setSourceIPv4(uint32_t IP)
        {
             memcpy(buffer+14, (unsigned char *)&IP, 4);
        }

        void setDestinationMAC(unsigned char *MAC)
        {
             memcpy(buffer+18, MAC, 6);
        }

        void setDestinationIPv4(uint32_t IP)
        {
             memcpy(buffer+24,(unsigned char *)&IP, 4);
        }

        void show()
        {
            if (protocolIsIPv4() && hardwareIsEthernet())
            {
                char *src_addr = IPv4::toString(data->src_addr);
                char *dst_addr = IPv4::toString(data->dst_addr);
                char *dst_mac = Ethernet::toString(data->dst_mac);
                char *src_mac = Ethernet::toString(data->src_mac);

                printf("Datagrama ARP:\n");
                printf("{ info:\n");
                printf("    { hardware: %d,\n", ntohs(header->hardware));
                printf("      protocol: %d,\n", ntohs(header->protocol));
                printf("      hardware_address_length: %d,\n", header->hardware_address_length);
                printf("      protocol_address_length: %d,\n", header->protocol_address_length);
                printf("      opcode: %d,\n", ntohs(header->opcode));
                printf("      src_mac: '%s',\n", src_mac);
                printf("      src_addr: '%s',\n", src_addr);
                printf("      dst_mac: '%s',\n", dst_mac);
                printf("      dst_addr: '%s' },\n", dst_addr);
                printf("  hdrlen: %i,\n", length);
                printf("  offset: %i }", offset);

                printf("\n\nEm Hex:\n");
                Utilities::showHex(buffer, length);

                printf("\n");

                delete dst_mac;
                delete src_mac;
                delete src_addr;
                delete dst_addr;
            }
            else
                printf("Datagrama ARP desconhecido...");


            printf("\n\n");
        }
};
