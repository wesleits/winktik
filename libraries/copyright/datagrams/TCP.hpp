class TCP
{
    public:

        unsigned char *buffer;

        //Header TCP
        typedef struct Header
        {
            uint16_t source_port; // source port
            uint16_t dest_port; // destination port
            uint32_t sequence; // sequence number - 32 bits
            uint32_t acknowledge; // acknowledgement number - 32 bits

            uint8_t ns :1; //Nonce Sum Flag Added in RFC 3540.
            uint8_t reserved_part1 :3; //according to rfc
            uint8_t data_offset :4; /*The number of 32-bit words in the TCP header.
            This indicates where the data begins.
            The length of the TCP header is always a multiple
            of 32 bits.*/

            uint8_t fin :1; //Finish Flag
            uint8_t syn :1; //Synchronise Flag
            uint8_t rst :1; //Reset Flag
            uint8_t psh :1; //Push Flag
            uint8_t ack :1; //Acknowledgement Flag
            uint8_t urg :1; //Urgent Flag

            uint8_t ecn :1; //ECN-Echo Flag
            uint8_t cwr :1; //Congestion Window Reduced Flag


            uint16_t window; // window
            uint16_t checksum; // checksum
            uint16_t urgent_pointer; // urgent pointer
        };


        // Important Lengths of TCP
        typedef struct Lengths
        {
            uint16_t header;
            uint16_t datagram;
            uint16_t data;
        };


        IPv4 *IPv4Datagram;
        Header *header;
        Lengths *length;

        uint16_t offset;
        unsigned char* data;


        TCP (unsigned char *buffer, IPv4 *IPv4Datagram)
        {
            this->IPv4Datagram = IPv4Datagram;
            header = (Header *)(buffer + this->IPv4Datagram->offset);
            this->buffer = (unsigned char*)header;

            length = new Lengths();
            length->header = header->data_offset * 4;
            length->datagram = ntohs(this->IPv4Datagram->header->total_length) - this->IPv4Datagram->length;
            length->data = length->datagram - length->header;

            offset = this->IPv4Datagram->offset + length->header;
            data = this->buffer + length->header;
        }


        ~TCP ()
        {
            delete length;
        }


        void recalculateChecksum()
        {
            uint16_t zero = 0;

            memcpy(buffer+16, (unsigned char *)&zero, 2);


            uint32_t sum =
            ((IPv4Datagram->buffer[12] << 8) | IPv4Datagram->buffer[13]) +
            ((IPv4Datagram->buffer[14] << 8) | IPv4Datagram->buffer[15]) +
            ((IPv4Datagram->buffer[16] << 8) | IPv4Datagram->buffer[17]) +
            ((IPv4Datagram->buffer[18] << 8) | IPv4Datagram->buffer[19]);
            sum += IPv4Datagram->header->protocol;
            sum += length->datagram;


            uint16_t checksum = Utilities::caculateChecksum(buffer, length->datagram, sum);

            memcpy(buffer+16, (unsigned char *)&checksum, 2);
        }


        void show ()
        {
            printf("Datagrama TCP:\n");
            printf("{ info:\n");
            printf("    { srcport: %u,\n", ntohs(header->source_port));
            printf("      dstport: %u,\n", ntohs(header->dest_port));
            printf("      seqno: %u,\n", ntohl(header->sequence));
            printf("      ackno: %u,\n", ntohl(header->acknowledge));
            printf("      hdrlen: %d,\n", header->data_offset);
            printf("      cwr: %d,\n", header->cwr);
            printf("      ecn: %d,\n", header->ecn);
            printf("      urg: %d,\n", header->urg);
            printf("      ack: %d,\n", header->ack);
            printf("      psh: %d,\n", header->psh);
            printf("      rst: %d,\n", header->rst);
            printf("      syn: %d,\n", header->syn);
            printf("      fin: %d,\n", header->fin);
            printf("      window: %d,\n", ntohs(header->window));
            printf("      checksum: %d,\n", ntohs(header->checksum));
            printf("      urgentptr : %d },\n", header->urgent_pointer);
            printf("  hdrlen: %i,\n", length->header);
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
