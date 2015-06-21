class UDP
{
    private:
        unsigned char *buffer;

    public:

        //Header UDP
        typedef struct Header
        {
            uint16_t sourcePort;  // Source port no.
            uint16_t destPort;    // Dest. port no.
            uint16_t length;      // Udp packet length
            uint16_t checksum;    // Udp checksum (optional)
        };


        // Important Lengths of UDP
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

        UDP (unsigned char *buffer, IPv4 *IPv4Datagram)
        {
            this->IPv4Datagram = IPv4Datagram;
            header = (Header *)(buffer + this->IPv4Datagram->offset);
            this->buffer = (unsigned char*)header;

            length = new Lengths();
            length->datagram = ntohs(this->IPv4Datagram->header->total_length) - this->IPv4Datagram->length;
            length->data = length->datagram - length->header;

            offset = this->IPv4Datagram->offset + length->header;
            data = this->buffer + length->header;
        }


        ~UDP ()
        {
            delete length;
        }

        void recalculateChecksum()
        {
            uint16_t zero = 0;

            memcpy(buffer+8, (unsigned char *)&zero, 2);


            uint32_t sum =
            ((IPv4Datagram->buffer[12] << 8) | IPv4Datagram->buffer[13]) +
            ((IPv4Datagram->buffer[14] << 8) | IPv4Datagram->buffer[15]) +
            ((IPv4Datagram->buffer[16] << 8) | IPv4Datagram->buffer[17]) +
            ((IPv4Datagram->buffer[18] << 8) | IPv4Datagram->buffer[19]);
            sum += IPv4Datagram->header->protocol;
            sum += length->datagram;


            uint16_t checksum = Utilities::caculateChecksum(buffer, length->datagram, sum);

            memcpy(buffer+8, (unsigned char *)&checksum, 2);
        }




        void show ()
        {
            printf("Datagrama UDP:\n");
            printf("{ info:\n");
            printf("      srcport: %d,\n", ntohs(header->sourcePort));
            printf("      dstport: %d,\n", ntohs(header->destPort));
            printf("      hdrlen: %d,\n", ntohs(header->length));
            printf("      checksum: %d },\n", ntohs(header->checksum));
            printf("  offset: %i }", offset);

            if (length->data > 0)
            {
                printf("\n\nDados:\n");
                Utilities::showHex(data, length->data);
                printf("\n");
            }
            else printf("\n\n");
        }
};
