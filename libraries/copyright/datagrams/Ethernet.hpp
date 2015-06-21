#define ETHERNET_IPV4 2048
#define ETHERNET_ARP 2054

class Ethernet
{
    public:

        // Header Ethernet
        typedef struct Header
        {
            uint8_t dst_mac[6];
            uint8_t src_mac[6];
            uint16_t type;
        };

        unsigned char *buffer;
        Header *header;
        static const uint16_t offset = sizeof(Header);

        Ethernet (unsigned char *buffer)
        {
            this->buffer = buffer;
            header = (Header *)(this->buffer);
        }


        void setDestination(unsigned char *MAC)
        {
            memcpy(buffer, MAC, 6);
        }


        static bool isValidAddress(const char* mac)
        {
            int i = 0;
            int s = 0;

            while (*mac)
            {
                if (isxdigit(*mac))
                    i++;

                else if (*mac == ':')
                {
                    if (i == 0 || i / 2 - 1 != s)
                        break;

                    ++s;
                }
                else
                    return false;

                ++mac;
            }

            return (i == 12 && s == 5);
        }

        static unsigned char *stringToBytes(const char *MAC)
        {
            unsigned char *bytes = new uint8_t[6];
            int values[6];


            sscanf(MAC, "%x:%x:%x:%x:%x:%x%c", &values[0], &values[1], &values[2], &values[3], &values[4], &values[5]);

            /* convert to uint8_t */
            for(int  i = 0; i < 6; ++i)
                bytes[i] = (uint8_t) values[i];


            return bytes;
        }

        void setSource(unsigned char *MAC)
        {
            memcpy(buffer+6, MAC, 6);
        }


        void setType(uint16_t type)
        {
            type = ntohs(type);
            memcpy(buffer+12, (unsigned char *)&type, 2);
        }


        bool sourceIsEqualTo(unsigned char *MAC)
        {
            return (memcmp(header->src_mac, MAC, 6) == 0);
        }


        bool destinationIsEqualTo(unsigned char *MAC)
        {
            return (memcmp(header->dst_mac, MAC, 6) == 0);
        }


        static char *toString(unsigned char *MAC)
        {
            char* result = new char [18];

            sprintf(result, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]);

            return result;
        }

        void show ()
        {
            char *dst_mac = toString(header->dst_mac);
            char *src_mac = toString(header->src_mac);

            printf("Datagrama Ethernet:\n");
            printf("{ info:\n");
            printf("    { dst_mac: '%s',\n", dst_mac);
            printf("      src_mac: '%s',\n", src_mac);
            printf("      type: %i },\n", ntohs(header->type));
            printf("  offset: %i }\n\n", offset);

            delete dst_mac;
            delete src_mac;
        }
};
