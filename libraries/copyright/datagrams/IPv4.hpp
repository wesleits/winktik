#define IP_ICMP 1
#define IP_TCP 6
#define IP_UDP 17


class IPv4
{
    public:

        // Header IPv4
        typedef struct Header
        {
            uint8_t ihl :4;               // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
            uint8_t version :4;           // 4-bit IPv4 version
            uint8_t ecn :2;               // IP type of service
            uint8_t dscp :6;

            uint16_t total_length;        // Total length
            uint16_t id;                  // Unique identifier


            uint16_t frag_offset :13;

            uint16_t more_fragment :1;
            uint16_t dont_fragment :1;
            uint16_t reserved_zero :1;


            uint8_t ttl;                  // Time to live
            uint8_t protocol;             // Protocol(TCP,UDP etc)
            uint16_t checksum;            // IP checksum
            uint32_t src_addr;              // Source address
            uint32_t dst_addr;             // Source address
        };

        Ethernet *EthernetDatagram;
        Header *header;

        uint16_t length;
        uint16_t offset;
        unsigned char *buffer;


        IPv4 (unsigned char *buffer, Ethernet *EthernetDatagram)
        {
            this->buffer = buffer + EthernetDatagram->offset;
            this->EthernetDatagram = EthernetDatagram;

            header = (Header *)this->buffer;

            length = header->ihl * 4;
            offset = length + this->EthernetDatagram->offset;
        }


        void setSource(uint32_t IP)
        {
            memcpy(buffer+12, (unsigned char *)&IP, 4);
        }


        static bool isValidAddress(const char *IP)
        {
            int len = strlen(IP);

            if (len < 7 || len > 15)
                return false;

            char tail[16];
            tail[0] = 0;

            unsigned int d[4];
            int c = sscanf(IP, "%3u.%3u.%3u.%3u%s", &d[0], &d[1], &d[2], &d[3], tail);

            if (c != 4 || tail[0])
                return false;

            for (int i = 0; i < 4; i++)
                if (d[i] > 255)
                    return false;

            return true;
        }


        static char *toString(uint32_t IP)
        {
            uint8_t bytes[4];
            bytes[0] = IP & 0xFF;
            bytes[1] = (IP >> 8) & 0xFF;
            bytes[2] = (IP >> 16) & 0xFF;
            bytes[3] = (IP >> 24) & 0xFF;

            char* result = new char [16];

            sprintf(result, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);

            return result;
        }


        void setDestination(uint32_t IP)
        {
            memcpy(buffer+16, (unsigned char *)&IP, 4);
        }


        void recalculateChecksum()
        {
            uint16_t zero = 0;

            memcpy(buffer+10, (unsigned char *)&zero, 2);

            uint16_t checksumIPv4 = Utilities::caculateChecksum(buffer, length, 0);
            memcpy(buffer+10, (unsigned char *)&checksumIPv4, 2);
        }


        void show ()
        {
            char *src_addr = toString(header->src_addr);
            char *dst_addr = toString(header->dst_addr);

            printf("Datagrama IPv4:\n");
            printf("{ info:\n");
            printf("    { version: %d,\n", header->version);
            printf("      ihl: %d,\n", header->ihl);
            printf("      dscp: %d,\n", header->dscp);
            printf("      ecn: %d,\n", header->ecn);
            printf("      total_length: %d,\n", ntohs(header->total_length));
            printf("      id: %d,\n", ntohs(header->id));
            printf("      reserved_zero: %d,\n", header->reserved_zero);
            printf("      dont_fragment: %d,\n", header->dont_fragment);
            printf("      more_fragment: %d,\n", header->more_fragment);
            printf("      frag_offset: %d,\n", header->frag_offset);
            printf("      ttl: %d,\n", header->ttl);
            printf("      protocol: %d,\n", header->protocol);
            printf("      checksum: %d,\n", ntohs(header->checksum));
            printf("      src_addr: '%s',\n", src_addr);
            printf("      dest_addr: '%s' },\n", dst_addr);
            printf("  hdrlen: %i,\n", length);
            printf("  offset: %i }\n\n", offset);

            delete src_addr;
            delete dst_addr;
        }
};
