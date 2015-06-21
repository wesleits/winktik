#define HAVE_REMOTE

#include <cstdio>
#include <winsock2.h>
#include <locale.h>


#include "libraries/the3rd/winpcap/pcap/pcap.h"


#include "libraries/copyright/Utilities.hpp"
#include "libraries/copyright/datagrams/Ethernet.hpp"
#include "libraries/copyright/datagrams/IPv4.hpp"
#include "libraries/copyright/datagrams/ARP.hpp"
#include "libraries/copyright/datagrams/TCP.hpp"
#include "libraries/copyright/datagrams/UDP.hpp"
#include "libraries/copyright/datagrams/ICMP.hpp"
#include "libraries/copyright/Router.hpp"


pcap_t *fp;
Ethernet *EthernetDatagram;
IPv4 *IPv4Datagram;
TCP *TCPDatagram;
UDP *UDPDatagram;
ICMP *ICMPDatagram;
ARP *ARPDatagram;


Router *gateway;
Node *nextNode;
Node *client;

bool debugIsActive;

/*
Router *gateway = new Node(1, "10.1.0.17", "84:8f:69:b7:3d:92");
Node *nextNode = new Node(1, "10.1.0.1", "10:fe:ed:66:7a:aa");
Node *client = new Node(1, "10.1.0.19", "00:0c:29:82:a4:6f");
*/


void processPackage(unsigned char* buffer, int bufferSize)
{
    EthernetDatagram = new Ethernet(buffer);

    switch(ntohs(EthernetDatagram->header->type))
    {
        case ETHERNET_IPV4:
        {
            IPv4Datagram = new IPv4 (buffer, EthernetDatagram);

            if (EthernetDatagram->destinationIsEqualTo(gateway->MAC))
            {
                switch (IPv4Datagram->header->protocol)     //Check the Protocol and do accordingly...
                {
                    case IP_TCP:
                    {
                        if (EthernetDatagram->sourceIsEqualTo(client->MAC))
                        {
                            EthernetDatagram->setSource(gateway->MAC);
                            EthernetDatagram->setDestination(nextNode->MAC);

                            IPv4Datagram->setSource(gateway->IP);
                            IPv4Datagram->recalculateChecksum();

                            TCPDatagram = new TCP (buffer, IPv4Datagram);
                            TCPDatagram->recalculateChecksum();

                            pcap_sendpacket(fp, buffer, bufferSize);

                            if (debugIsActive)
                            {
                                printf("|||||||||||||||||||||||||||||||| COMEÇO do pacote ||||||||||||||||||||||||||||||||\n");
                                    EthernetDatagram->show();
                                    IPv4Datagram->show();
                                    TCPDatagram->show();
                                printf("|||||||||||||||||||||||||||||||| FIM do pacote ||||||||||||||||||||||||||||||||\n\n");
                            }

                            delete TCPDatagram;
                        }

                        else if (EthernetDatagram->sourceIsEqualTo(nextNode->MAC))
                        {
                            EthernetDatagram->setSource(gateway->MAC);
                            EthernetDatagram->setDestination(client->MAC);

                            IPv4Datagram->setDestination(client->IP);
                            IPv4Datagram->recalculateChecksum();

                            TCPDatagram = new TCP(buffer, IPv4Datagram);
                            TCPDatagram->recalculateChecksum();

                            pcap_sendpacket(fp, buffer, bufferSize);

                            if (debugIsActive)
                            {
                                printf("|||||||||||||||||||||||||||||||| COMEÇO do pacote ||||||||||||||||||||||||||||||||\n");
                                    EthernetDatagram->show();
                                    IPv4Datagram->show();
                                    TCPDatagram->show();
                                printf("|||||||||||||||||||||||||||||||| FIM do pacote ||||||||||||||||||||||||||||||||\n\n");
                            }

                            delete TCPDatagram;
                        }

                        break;
                    }


                    case IP_UDP:
                    {

                        if (EthernetDatagram->sourceIsEqualTo(client->MAC))
                        {
                            EthernetDatagram->setSource(gateway->MAC);
                            EthernetDatagram->setDestination(nextNode->MAC);

                            IPv4Datagram->setSource(gateway->IP);
                            IPv4Datagram->recalculateChecksum();

                            UDPDatagram = new UDP (buffer, IPv4Datagram);
                            UDPDatagram->recalculateChecksum();

                            pcap_sendpacket(fp, buffer, bufferSize);

                            if (debugIsActive)
                            {
                                printf("|||||||||||||||||||||||||||||||| COMEÇO do pacote ||||||||||||||||||||||||||||||||\n");
                                    EthernetDatagram->show();
                                    IPv4Datagram->show();
                                    UDPDatagram->show();
                                printf("|||||||||||||||||||||||||||||||| FIM do pacote ||||||||||||||||||||||||||||||||\n\n");
                            }

                            delete UDPDatagram;
                        }
                        else if (EthernetDatagram->sourceIsEqualTo(nextNode->MAC))
                        {
                            EthernetDatagram->setSource(gateway->MAC);
                            EthernetDatagram->setDestination(client->MAC);

                            IPv4Datagram->setDestination(client->IP);
                            IPv4Datagram->recalculateChecksum();

                            UDPDatagram = new UDP (buffer, IPv4Datagram);
                            UDPDatagram->recalculateChecksum();

                            pcap_sendpacket(fp, buffer, bufferSize);

                            if (debugIsActive)
                            {
                                printf("|||||||||||||||||||||||||||||||| COMEÇO do pacote ||||||||||||||||||||||||||||||||\n");
                                    EthernetDatagram->show();
                                    IPv4Datagram->show();
                                    UDPDatagram->show();
                                printf("|||||||||||||||||||||||||||||||| FIM do pacote ||||||||||||||||||||||||||||||||\n\n");
                            }

                            delete UDPDatagram;
                        }

                        break;
                    }

                    case IP_ICMP:
                    {
                        if (EthernetDatagram->sourceIsEqualTo(client->MAC))
                        {
                            EthernetDatagram->setSource(gateway->MAC);
                            EthernetDatagram->setDestination(nextNode->MAC);

                            IPv4Datagram->setSource(gateway->IP);
                            IPv4Datagram->recalculateChecksum();

                            pcap_sendpacket(fp, buffer, bufferSize);

                            if (debugIsActive)
                            {
                                ICMPDatagram = new ICMP(buffer, IPv4Datagram);

                                printf("|||||||||||||||||||||||||||||||| COMEÇO do pacote ||||||||||||||||||||||||||||||||\n");
                                    EthernetDatagram->show();
                                    IPv4Datagram->show();
                                    ICMPDatagram->show();
                                printf("|||||||||||||||||||||||||||||||| FIM do pacote ||||||||||||||||||||||||||||||||\n\n");
                            }
                        }
                        else if (EthernetDatagram->sourceIsEqualTo(nextNode->MAC))
                        {
                            EthernetDatagram->setSource(gateway->MAC);
                            EthernetDatagram->setDestination(client->MAC);

                            IPv4Datagram->setDestination(client->IP);
                            IPv4Datagram->recalculateChecksum();

                            pcap_sendpacket(fp, buffer, bufferSize);

                            if (debugIsActive)
                            {
                                ICMPDatagram = new ICMP(buffer, IPv4Datagram);

                                printf("|||||||||||||||||||||||||||||||| COMEÇO do pacote ||||||||||||||||||||||||||||||||\n");
                                    EthernetDatagram->show();
                                    IPv4Datagram->show();
                                    ICMPDatagram->show();
                                printf("|||||||||||||||||||||||||||||||| FIM do pacote ||||||||||||||||||||||||||||||||\n\n");
                            }
                        }

                        break;
                    }

                }
            }

            delete IPv4Datagram;
            break;
        }

        case ETHERNET_ARP:
        {
            ARPDatagram = new ARP (buffer, EthernetDatagram);

            if (ARPDatagram->isSimpleRequest() && ARPDatagram->protocolIsIPv4() && ARPDatagram->hardwareIsEthernet())
            {
                ARPDatagram->prepareDataForEthernetAndIPv4();

                if (ARPDatagram->ipv4RequestedIs(gateway->IP))
                {
                    EthernetDatagram->setDestination(EthernetDatagram->header->src_mac);
                    EthernetDatagram->setSource(gateway->MAC);

                    ARPDatagram->setOpCode(2);

                    ARPDatagram->setDestinationMAC(ARPDatagram->data->src_mac);
                    ARPDatagram->setDestinationIPv4(ARPDatagram->data->src_addr);

                    ARPDatagram->setSourceMAC(gateway->MAC);
                    ARPDatagram->setSourceIPv4(gateway->IP);

                    if (debugIsActive)
                    {
                        printf("|||||||||||||||||||||||||||||||| COMEÇO do pacote ||||||||||||||||||||||||||||||||\n");
                            EthernetDatagram->show();
                            ARPDatagram->show();
                        printf("|||||||||||||||||||||||||||||||| FIM do pacote ||||||||||||||||||||||||||||||||\n\n");
                    }

                    pcap_sendpacket(fp, buffer, ARPDatagram->offset);
                }
            }
            delete ARPDatagram;

            break;
        }
   }

   delete EthernetDatagram;
}



int main()
{

    /*
    gateway = new Router(1, "10.1.0.17", "84:8f:69:b7:3d:92");

    unsigned char* MAC = gateway->getMAC("10.1.0.2");
    printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]);


    MAC = gateway->getMAC("10.1.0.1");
    printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]);

    return 0;

    */


    // /*
    setlocale(LC_ALL, "Portuguese");
    printf("\n\n\n");
    printf("################################################\n");
    printf("####                                        ####\n");
    printf("####   Autor: Weslei Teixeira da Silveira   ####\n");
    printf("####   Versao: 0.9.9                        ####\n");
    printf("####                                        ####\n");
    printf("################################################\n");
    printf("\n\n\n");


    int i, res, inum;
    unsigned char errbuf[PCAP_ERRBUF_SIZE];
    char MAC[1024], IP[1024];
    char option[1024];
    const unsigned char *pkt_data;



    pcap_if_t *alldevs, *d;

    struct pcap_pkthdr *header;


    // The user didn't provide a packet source: Retrieve the local device list
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, (char *)errbuf) == -1)
    {
        fprintf(stderr, "Erro em pcap_findalldevs_ex: %s\n", errbuf);
        return -1;
    }

    i = 0;

    printf("Adaptadore(s) de rede, disponível(eis) em seu PC:\n\n");
    // Print the list
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s\n    ", ++i, d->name);

        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (Nenhuma descriçao disponível)\n");
    }

    if (i == 0)
    {
        fprintf(stderr, "Nenhuma interface encontrada! Saindo...\n");
        return -1;
    }

    do
    {
        printf("\nEntre com o número do adaptador que você gostaria de usar para criar a interface virtual : ");
    }
    while( !((scanf("%d", &inum) == 1) && (1 <= inum) && (inum <= i)) );



    // Jump to the selected adapter
    for (d = alldevs, i=0; i < inum-1; d = d->next, i++);


    printf("\n\n\nOk! Agora iremos, configurar a nossa interface virtual que será um roteador/gateway na rede...\n\n");

    do
    {
        printf("\nEntre com o MAC da interface virtual (Ex. fd:78:a7:4d:87:b8) : ");
        scanf ("%s", &MAC);
    }
    while (!Ethernet::isValidAddress(MAC));

    do
    {
        printf("\nEntre com o IP da interface virtual (Ex. 192.168.0.2) : ");
        scanf ("%s", &IP);
    }
    while (!IPv4::isValidAddress(IP));

    gateway = new Router(inum, IP, MAC);


    do
    {
        printf("\nEntre com a máscara de sub-rede da interface virtual (Ex. 255.255.0.0) : ");
        scanf ("%s", &IP);
    }
    while (!IPv4::isValidAddress(IP));

    do
    {
        printf("\nEntre com o gateway da interface virtual (Ex. 192.168.0.1) : ");
        scanf("%s", &IP);
    }
    while (!IPv4::isValidAddress(IP));

    nextNode = new Node(inum, IP, (const char*)gateway->getMAC(IP));


    printf("\n\n\nFinalmente, por último você irá digitar um IP que estará autorizado à se conectar em nossa interface \n\
virtual (%s) e ter acesso à internet através dela.\n", IPv4::toString(gateway->IP));

    do
    {
        printf("\nEntre com o IP (Ex. 192.168.0.3) : ");
        scanf("%s", &IP);
    }
    while (!IPv4::isValidAddress(IP));

    client = new Node(inum, IP, (const char*)gateway->getMAC(IP));


    printf("\n\nPronto! Nossa interface virtual já está configurada.\n\
Agora é só voce setar o gateway '%s', na interface do computador de IP '%s',\n\
para que este tenha acesso a internet! Legal né?!? Já conseguiu imaginar\n\
o leque de possibilidades, do que dá pra ser feito em cima desta \"base\"?\n\n",
    IPv4::toString(gateway->IP), IPv4::toString(client->IP));


    printf("\n\nMas antes de iniciar a executaçao da nossa interface virtual, gostaria de saber\n\
se você deseja visualizar, aqui nesta tela, todo o tráfego que passará nela. Note que ativar esta \n\
opçao, irá consumir muitos recursos de processamento e até deixará o roteamento extremamente mais lento.\n\
Enfim, gostaria de ativar o \"debug\"?\n");


    do
    {
        printf("\nDigite 's' para SIM ou 'n' para NAO: ");
        scanf("%s", &option);

        if (strcmp(option, "s") == 0)
        {
            debugIsActive = true;
            break;
        }

        else if (strcmp(option, "n") == 0)
        {
            debugIsActive = false;
            break;
        }
    }
    while(1);


    printf("\n\nOk! Interface iniciada...");


    if ( (fp= pcap_open_live(d->name,
                        65535,                          // snaplen
                        PCAP_OPENFLAG_PROMISCUOUS,      // flags
                        1,                              // read timeout
                        (char *)errbuf)
                        ) == NULL)

    {
        fprintf(stderr, "\nErro ao abrir o adaptador\n");
        return -1;
    }

    //read packets in a loop :)
    while((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
    {
        if (res == 0) // Timeout elapsed
            continue;

        processPackage((unsigned char*)pkt_data , header->caplen);
    }

    if (res == -1)
    {
        fprintf(stderr, "Erro ao ler os pacotes: %s\n", pcap_geterr(fp));
        return -1;
    }

    return 0;

    // */
}
