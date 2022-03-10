/******************************************************************************
 * Počítačové komunikace a sítě - IPK
 * Author: Kozhevnikov Dmitrii
 * Login: xkozhe00
 * 
 * Varianta: Zeta
 * Sniffer paketů
 * 
 * 2021
 */

#include <iostream>
#include <string.h>
#include <getopt.h>
#include <string>
#include <cstdlib>
#include <pcap/pcap.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <iomanip>

using namespace std;

pcap_t *myPcap;

/**
 * Function to control program work and exit.
 */
void clear(int signal) {
    (void)signal;
    pcap_close(myPcap);
    exit(0);
}

/**
 * The function writes out information from packages
 * @param data data for printing
 * @param size size of data
 */
void printPacketInfo(const u_char *data , int size)
{
	int i;
    int j;
    int line = 1; 

    cout << "0x0000:  ";        // print first line
	for(i = 0 ; i < size ; i++) {
		if (i != 0 &&  i % 16 == 0) {
            cout << "         "; 
			for(j = i - 16; j < i; j++) {

				if(data[j] >= 32 && data[j] <= 126){
                    cout << (unsigned char)data[j];
                } else {
                    cout << ".";
                } 
			}
            
            cout << endl;

            // printin next lines
            if (line < 10) {
                cout << "0x00" << line * 10 << ":  ";
                line++;
            } else if (line < 100) {
                cout << "0x0" << line * 10 << ":  ";
                line++;
            } else {
                cout << "0x" << line *10 << ":  ";
                line++;
            }
		} 
		

		if(i % 16 == 0) {
            cout << "   ";
        } 

        cout << " ";
        cout <<  hex << setfill('0') << setw(2) << static_cast<int>((unsigned int)data[i]) << dec;      // print hex
				
		if(i == size - 1) {

			for(j = 0; j < 15 - i % 16; j++) {
                cout << "   ";
			}
			
            cout << "         ";
			
			for(j = i - i % 16; j <= i; j++) {

				if(data[j] >= 32 && data[j] <= 128) {
                    cout << (unsigned char)data[j];
				} else {
                    cout << ".";
				}
			}
			
            cout << endl;
		}
        
	}
    cout << endl;
}

/**
 * This function writes out the basic information: the calculated time, ip addresses, port numbers, the number of bytes received in the packet. 
 * The statement is made taking into account the protocol type of the received packet.
 */
void printPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args;
    struct tm *realTime;                                    // control time
    char timeBuffer[64];                                    // time buffer
    char buffer[128];
    char timerBuffer[20];                                   // buffer for correct time
    char zoneBuffer[6];                                     // buffer for time-zone
    char sourceIP[INET_ADDRSTRLEN];                         // source IP
    char destinationIP[INET_ADDRSTRLEN];                    // destination IP
    char sourceIP6[INET6_ADDRSTRLEN];                       // source IP for IPv6
    char destinationIP6[INET6_ADDRSTRLEN];                  // destination IP for IPv6
    int sourcePort;                                         // source port number
    int destinationPort;                                    // destination port number
    struct ethhdr *ethHeader = (struct ethhdr *)packet;
    uint16_t protocol = ntohs(ethHeader->h_proto);

    /*   Time calculate   */
    realTime = localtime(&header->ts.tv_sec);
    memset(timeBuffer, 0, 64);
    strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%dT%T%z", realTime);

    for (int i = 0; i < 19; i++) {
        timerBuffer[i] = timeBuffer[i];
    }

    timerBuffer[19] = '\0';

    for (int i = 0; i < 5; i++) {
        zoneBuffer[i] = timeBuffer[19 + i]; 
    }

    zoneBuffer[5] = '\0';
    
    char timeZoneFormat[7];
    int j = 0;


    // make good print for time zone
    for (int i = 0; i < 7; i++) {
        
        timeZoneFormat[i] = zoneBuffer[j];
        if (i == 3) {
            timeZoneFormat[i] = ':';
            continue;
        }

        if (i == 6) {
            timeZoneFormat[i] = '\0';
            continue;
        }

        j++;
    }

    snprintf(buffer, sizeof(buffer), "%s.%03ld%s ", timerBuffer, header->ts.tv_usec / 1000, timeZoneFormat);    // print head
    /***************************/

    // ipv4
    if (protocol == ETH_P_IP) {
        int lenOfIpv4;
        struct ip *ipv4Header = (struct ip *)(packet + sizeof(struct ethhdr));
        inet_ntop(AF_INET, &ipv4Header->ip_src, sourceIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ipv4Header->ip_dst, destinationIP, INET_ADDRSTRLEN);
        lenOfIpv4 = 4 * ipv4Header->ip_hl;
        
        // TCP
        if (ipv4Header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcpHeader = (struct tcphdr *)(packet + sizeof(struct ethhdr) + lenOfIpv4);
            sourcePort = ntohs(tcpHeader->th_sport);
            destinationPort = ntohs(tcpHeader->th_dport);
            cout << buffer << sourceIP << " : " << sourcePort << " > " << destinationIP << " : " << destinationPort << ", " <<  "length: " << header->len << " bytes" << endl;
            printPacketInfo(packet, header->len);

        // UDP
        } else if (ipv4Header->ip_p == IPPROTO_UDP) {
            struct udphdr *udpHeader = (struct udphdr *)(packet + sizeof(struct ethhdr) + lenOfIpv4);
            sourcePort = ntohs(udpHeader->uh_sport);
            destinationPort = ntohs(udpHeader->uh_dport);
            cout << buffer << sourceIP << " : " << sourcePort << " > " << destinationIP << " : " << destinationPort << ", " <<  "length: " << header->len << " bytes" << endl;
            printPacketInfo(packet, header->len);
        }

    // ipv 6
    } else if (protocol == ETH_P_IPV6) {

        struct ip6_hdr *ip6Header = (struct ip6_hdr *)(packet + sizeof(struct ethhdr));
        inet_ntop(AF_INET6, &(ip6Header->ip6_src), sourceIP6, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6Header->ip6_dst), destinationIP6, INET6_ADDRSTRLEN);
        
        // TCP
        if (ip6Header->ip6_nxt == IPPROTO_TCP) {
            struct tcphdr *tcpHeader = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(ip6_hdr));
            sourcePort = ntohs(tcpHeader->th_sport);
            destinationPort = ntohs(tcpHeader->th_dport);
            cout << buffer << sourceIP6 << " : " << sourcePort << " > " << destinationIP6 << " : " << destinationPort << ", " <<  "length: " << header->len << " bytes" << endl;
            printPacketInfo(packet, header->len);

        // UDP
        } else if (ip6Header->ip6_nxt == IPPROTO_UDP) {
            struct udphdr *udpHeader = (struct udphdr *)(packet + sizeof(struct ethhdr) + sizeof(ip6_hdr));
            sourcePort = ntohs(udpHeader->uh_sport);
            destinationPort = ntohs(udpHeader->uh_dport);
            cout << buffer << sourceIP6 << " : " << sourcePort << " > " << destinationIP6 << " : " << destinationPort << ", " <<  "length: " << header->len << " bytes" << endl;
            printPacketInfo(packet, header->len);
        } else if (ip6Header->ip6_nxt == IPPROTO_ICMPV6) {
            cout << buffer << sourceIP6 << " > " << destinationIP6 << ", " <<  "length: " << header->len << " bytes" << endl;
            printPacketInfo(packet, header->len);
        } 
        
    // arp     
    } else if (protocol == ETH_P_ARP) {
        uint8_t sourceMACAddress[ETH_ALEN];
        memcpy(sourceMACAddress, ethHeader->h_source, sizeof(sourceMACAddress));
        
        uint8_t destinationMACAddress[ETH_ALEN];
        memcpy(destinationMACAddress, ethHeader->h_dest, sizeof(destinationMACAddress));
        cout << buffer;

        for (int i = 0; i < 6; i++) {
            cout << hex << setfill('0') << setw(2) << static_cast<int>(sourceMACAddress[i]);
            if (i != 5) {
                cout << ":";
            }
        }

        cout << " > ";

        for (int i = 0; i < 6; i++) {
            cout << hex << setfill('0') << setw(2) << static_cast<int>(destinationMACAddress[i]);
            if (i != 5) {
                cout << ":";
            }
        }

        cout << dec << ", " << "length: " << header->len << " bytes" << endl;
        printPacketInfo(packet, header->len);

    } else {
        cerr << "ERROR: Unknown packet type" << endl;
    }
}

/**
 * Packet sniffer
 * @param myInterfaceName name of the interface to work
 * @param packetNumber number of packets to process
 * @param filter filter expression
 */
int snifferFunction(char *myInterfaceName, int packetNumber, char *filter) {
    
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filtProg;                      // compiled filter expression
    bpf_u_int32 snifferIP;                            // sniffer IP
    bpf_u_int32 netmask;                              // netmask of interface
    u_char *activPacket = NULL;                       // packet in work

    if (pcap_lookupnet(myInterfaceName, &snifferIP, &netmask, errbuf)  == -1) {
        cerr << "ERROR: Can not use netmask for interface " << myInterfaceName << endl;
        snifferIP = 0;
        netmask = 0; 
    }

    myPcap = pcap_open_live(myInterfaceName, BUFSIZ, 1, 1000, errbuf);

    if (myPcap == NULL) {
        cerr << "ERROR: Could not open interface " << myInterfaceName << endl;
        exit(1);
    }

    if (pcap_datalink(myPcap) != DLT_EN10MB) {
        cerr << "ERROR: Ethernet not supported by interface " << myInterfaceName << endl;
        exit(2); 
    }

    if (pcap_compile(myPcap, &filtProg, filter, 0, snifferIP) == -1) {
        cerr << "ERROR: Bad filter parsing" << endl;
        exit(3);
    }

    if (pcap_setfilter(myPcap, &filtProg) == -1) {
        cerr << "ERROR: Bad filter instalation" << endl;
        exit(4);
    }

    if (!pcap_loop(myPcap, packetNumber, printPacket, activPacket)) {
        cerr << pcap_geterr(myPcap) << endl;
    }

    pcap_close(myPcap);
    return 0;
}

/**
 * Сhecking the existence of the specified interface in the list of interfaces
 * @param interface name of interface to control
 */
pcap_if_t *findInterface(string interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces;
              // interfaces
    pcap_if_t *temp;
    
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        cerr << "ERROR: Bad pcap findall devs" << endl;
        exit(-1);
    }

    for(temp = interfaces; temp; temp = temp->next) {
        if (temp->name == interface) {
            return temp;
        }
    }
    return nullptr;
}

/**
 * The function writes out a list of all available interfaces
 */
void printAllInterfaces() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces;      // interfaces
    pcap_if_t *temp;
    
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        cerr << "ERROR: Bad pcap findall devs" << endl;
        exit(-1);
    }

    for(temp = interfaces; temp; temp = temp->next) {
        cout << temp->name << endl;
    }
    pcap_freealldevs(temp);
}

/**
 * The main function. 
 * Checks the start arguments, make a filter and starts checking the packages
 */
int main(int argc, char *argv[])
{

    // start arguments control structure
    static struct option longopts[] = {
        {"interface", no_argument, 0, 'i'},
        {"tcp", no_argument, 0, 't'},
        {"udp", no_argument, 0, 'u'},
        {"arp", no_argument, 0, 0},
        {"icmp", no_argument, 0, 0},
        {0,0,0,0},
    };

    int optIndex = 0;           // index for options
    int result = 0;             // input instructions
    int port = 0;               // port number
    int iArgFlag = 0;           // control attribute by i-parameter
    int iCommandFlag = 0;       // -i or -interface
    int pCommandFlag = 0;       // -p
    int tCommandFlag = 0;       // -t
    int uCommandFlag = 0;       // -u
    int packetNumber = 1;       // number of packets
    int arpCommandFlag = 0;     // --arp
    int icmpCommandFlag = 0;    // --icmp
    char interface[256] = "";   // name of interface
    char filter[256] = "";
    string portStr = "";

    while ((result = getopt_long(argc, argv, "p:tun:i::", longopts, &optIndex)) != -1) {
        char *portString = nullptr;
        char *numString = nullptr;

        if (result < 0) {
            cerr << "ERROR: getopt_long() failed" << endl;
            exit(2);
        }
      
        switch(result) {
            case 0:
                if (!strcmp(longopts[optIndex].name, "arp")) {
                    arpCommandFlag = 1;
                }

                if (!strcmp(longopts[optIndex].name, "icmp")) {
                    icmpCommandFlag = 1;
                }
                break;


            case 'i':
                iCommandFlag = 1;

                if (argv[optind]) {


                    // control next argument
                    if (argv[optind][0] != '-' ) {
                        strcpy(interface, argv[optind]);
                        iArgFlag = 1;
                    }
                }
                break;


            case 'p':
                pCommandFlag = 1;
                portStr = optarg;
                port = strtol(optarg, &portString, 10);
                if (*portString) {
                    cerr << portString << endl;
                    cerr << "ERROR: Argument must be a number!" << endl;
                    return 1;
                }
                break;


            case 't':
                tCommandFlag = 1;
                break;


            case 'u':
                uCommandFlag = 1;
                break;


            case 'n':
                packetNumber = strtol(optarg, &numString, 10);
                if (*numString) {
                    cerr << "ERROR: Argument must be a number!" << endl;
                    return 1;
                }
                break;


            case '?':
                cerr << "ERROR: unknown argument" << endl;
                exit(1);


            default:
                cerr << "ERROR: unknown argument" << endl;
                exit(1);
            
        }    
    }

    int num = argc;

    // name of interface check
    if (iArgFlag == 1) {
        num = num - 1;
    }

    // bad arguments control
    if (optind < num) {
            
            while (optind < argc) {
                if (argv[optind] != interface) {
                    cerr << "ERROR: non-option ARGV" << argv[optind] << endl;
                    exit(EXIT_FAILURE);
                }
            }
            exit(2);
        }


    // print all interfaces, if no -i parameter
    if (iCommandFlag == 0 || (iCommandFlag == 1 && iArgFlag == 0)) {
        printAllInterfaces();
        exit(0);
    }


    // Command flags on true, if non flags
    if (tCommandFlag == 0 && uCommandFlag == 0 &&
        arpCommandFlag == 0 && icmpCommandFlag == 0) {
            tCommandFlag = 1;
            uCommandFlag = 1;
            arpCommandFlag = 1;
            icmpCommandFlag = 1;
    }


    // control start interface
    pcap_if_t *myInterfaceToWork = findInterface(interface);


    if (myInterfaceToWork == nullptr) {
        cerr << "No found interface" << endl;
        exit(2);
    } 
    
    /*  Creating filter   */
    if (tCommandFlag == 1) {
        strcat(filter, "tcp ");
    }

    if (uCommandFlag == 1) {
        if (tCommandFlag == 1) {
            strcat(filter, "or ");
        }
        strcat(filter, "udp ");
    }

    if (arpCommandFlag == 1) {
        if (tCommandFlag == 1 || uCommandFlag == 1) {
            strcat(filter, "or ");
        }
        strcat(filter, "arp ");
    }

    if (icmpCommandFlag == 1) {
        if (tCommandFlag == 1 || uCommandFlag == 1 || arpCommandFlag == 1) {
            strcat(filter, "or ");
        }
        strcat(filter, "icmp ");
    }

    if (pCommandFlag == 1) {
        if (tCommandFlag == 1 || uCommandFlag == 1 || arpCommandFlag == 1 || icmpCommandFlag == 1) {
            strcat(filter, "and ");
        } 
        strcat(filter, "port ");
        char a[256] = "";
        sprintf(a, "%d", port);
        strcat(filter, a);
        strcat(filter, " ");
    }
    
/************************/

    signal(SIGINT, clear);
    signal(SIGTERM, clear);
    signal(SIGQUIT, clear);

    
    snifferFunction(myInterfaceToWork->name, packetNumber, filter);

    pcap_freealldevs(myInterfaceToWork);
    //cout << "All good\n";
    return 0;
}