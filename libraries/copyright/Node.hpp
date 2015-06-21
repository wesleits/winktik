class Node
{
    public:

        unsigned int interfaceNumber;
        unsigned char *MAC;
        int32_t IP;


        Node(unsigned int pInterfaceNumber, const char *IP, const char *MAC)
        {
            interfaceNumber = pInterfaceNumber;
            this->IP = inet_addr(IP);

            if (MAC[2] != ':')
                this->MAC = (unsigned char *)MAC;
            else
                this->MAC = Ethernet::stringToBytes(MAC);
        }

        ~Node()
        {
            delete MAC;
        }
};
