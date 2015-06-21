class ICMP
{
    private:
        unsigned char *buffer;

    public:

        //Header ICMP
        typedef struct Header
        {
            uint8_t type;           // ICMP Error type
            uint8_t code;           // Type sub code
            uint16_t checksum;
            uint16_t id;
            uint16_t seq;
        };


        // Important Lengths of ICMP
        typedef struct Lengths
        {
            static const uint16_t header = sizeof(Header);
            uint16_t datagram;
            uint16_t data;
        };


        IPv4 *IPv4Datagram;
        Header *header;
        Lengths *length;

        uint16_t offset;
        unsigned char* data;

        ICMP (unsigned char *buffer, IPv4 *IPv4Datagram)
        {
            this->IPv4Datagram = IPv4Datagram;
            header = (Header *)(buffer + this->IPv4Datagram->offset);
            this->buffer = (unsigned char*)header;

            length = new Lengths();
            length->datagram = ntohs(IPv4Datagram->header->total_length) - IPv4Datagram->length;
            length->data = length->datagram - length->header;

            offset = IPv4Datagram->offset + length->header;
            data = this->buffer + length->header;
        }


        ~ICMP ()
        {
            delete length;
        }


        void show ()
        {
            switch(header->type)
            {
                case 0:
                {
                    printf(" (ICMP Echo Reply)\n");
                    break;
                }

                case 8:
                {
                    printf(" (ICMP Echo Request)\n");
                    break;
                }

                case 11:
                {
                    printf(" (TTL Expired)\n");
                    break;
                }
            }

            printf("\nDatagrama ICMP:\n");
            printf("{ info:\n");
            printf("      type: %d,\n", header->type);
            printf("      code: %d,\n", header->code);
            printf("      checksum: %d },\n", ntohs(header->checksum));
            printf("      id: %d,\n", ntohs(header->id));
            printf("      seq: %d },\n", ntohs(header->seq));
            printf("  offset: %i }\n", offset);

            if (length->data > 0)
            {
                printf("\nDados:\n");
                Utilities::showHex(data, length->data);
            }

            printf("\n");
        }
};
