#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/select.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

//function to return the name of service (placeholder)
const char* get_service_name(int port) {
switch(port) {
    case 9: return "Discard Protocol";
    case 17: return "QOTD";
    case 19: return "Chargen";
    case 21: return "FTP";
    case 22: return "SSH";
    case 23: return "Telnet";
    case 25: return "SMTP";
    case 53: return "DNS";
    case 67: return "DHCP";
    case 68: return "DHCPC";
    case 69: return "TFTP";
    case 80: return "HTTP";
    case 88: return "Kerberos";
    case 110: return "POP3";
    case 123: return "NTP";
    case 143: return "IMAP";
    case 161: return "SNMP";
    case 162: return "SNMPTrap";
    case 179: return "BGP";
    case 443: return "HTTPS";
    case 465: return "SMTPS";
    case 514: return "Syslog";
    case 636: return "LDAPS";
    case 993: return "IMAPS";
    case 995: return "POP3S";
    case 1080: return "SOCKS";
    case 1194: return "OpenVPN";
    case 1433: return "MSSQLServer";
    case 1434: return "MSSQLServer (UDP)";
    case 1723: return "PPTP";
    case 3306: return "MySQL";
    case 3389: return "RDP";
    case 5432: return "PostgreSQL";
    case 5900: return "VNC";
    case 6379: return "Redis";
    case 6660: return "IRC";
    case 8080: return "HTTP-Proxy";
    case 8443: return "HTTPS-Alt";
    case 8888: return "Web-Proxy";
    case 27017: return "MongoDB";
    case 5000: return "UPnP";
    case 5060: return "SIP";
    case 5222: return "XMPP";
    case 5901: return "VNC";
    case 27015: return "Steam";
    case 1109: return "IMAP";
    case 5859: return "Apple-Push";

    default: return "Unknown Service";
    }
}


//function to parse a string of comma-separated ports and return them as an array
int* parse_ports(char* str, int* num_ports){
    //count the number of ports
    *num_ports = 0;
    for(int i = 0; str[i] != '\0'; i++){
        if(str[i] == ','){
            (*num_ports)++;
        }
    }
    (*num_ports)++; //last port after the last comma

    //allocate memory for the ports
    int* ports = (int*)malloc(*num_ports * sizeof(int));
    if(!ports){
        perror("[ERROR] Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    //parse the ports
    char* token = strtok(str, ",");
    int index = 0;
    while(token != NULL){
        ports[index++] = atoi(token);
        token = strtok(NULL, ",");
    }
    return ports;
}

//function to perform a TCP Connect Scan on the provided ports
void scan_ports(char* ip, int* ports, int num_ports){
    struct sockaddr_in server_addr;
    int sockfd;
    int result;
    fd_set write_fds;
    struct timeval timeout;
    int conn_result;

    printf("PORT\tSERVICE\t\t    STATE\n");
    printf("------------------------------------\n");

    for(int i = 0; i < num_ports; i++){
        sockfd = socket(AF_INET, SOCK_STREAM, 0); //create socket
        if(sockfd == -1){
            perror("[ERROR] Socket creation failed");
            return;
        }
        
        //set server address
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(ports[i]);
        server_addr.sin_addr.s_addr = inet_addr(ip);

        //set the socket to non-blocking mode
        int flags = fcntl(sockfd, F_GETFL, 0);
        fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

        //attempt to connect to the server
        result = connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));

        //open = syn/ack
        //closed = RST
        //unknown = /
        if (result < 0 && errno != EINPROGRESS) {
            if (errno == ECONNREFUSED) {
                printf("%-8d%-20s%-10s\n", ports[i], get_service_name(ports[i]), "Closed");
            } else {
                printf("%-8d%-20s%-10s\n", ports[i], get_service_name(ports[i]), "Unknown");
            }
            close(sockfd);
            continue;
        }

        FD_ZERO(&write_fds);
        FD_SET(sockfd, &write_fds);
        timeout.tv_sec = 0;
        timeout.tv_usec = 1000000;

        result = select(sockfd + 1, NULL, &write_fds, NULL, &timeout);

        if (result > 0) {
            socklen_t len = sizeof(conn_result);
            if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &conn_result, &len) == 0) {
                if (conn_result == 0){
                    printf("%-8d%-20s%-10s\n", ports[i], get_service_name(ports[i]), "Open");
                } else {
                    printf("%-8d%-20s%-10s\n", ports[i], get_service_name(ports[i]), "Closed");
                }
            } else {
                printf("%-8d%-20s%-10s\n", ports[i], get_service_name(ports[i]), "Unknown");
            }
        } else {
            printf("%-8d%-20s%-10s\n", ports[i], get_service_name(ports[i]), "Closed");
        }

        close(sockfd);
    }
}

///function for the SYN Scan
void syn_scan(char *ip, int* ports, int num_ports){
    struct sockaddr_in target;
    int sockfd;

    printf("PORT\tSERVICE\t\t    STATE\n");
    printf("------------------------------------\n");

    for (int i = 0; i < num_ports; i++){
        sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if(sockfd < 0){
            perror("[ERROR] Failed to create raw socket");
            return;
        }

        target.sin_family = AF_INET;
        target.sin_port = htons(ports[i]);
        target.sin_addr.s_addr = inet_addr(ip);

        struct tcphdr tcp_header;
        memset(&tcp_header, 0, sizeof(tcp_header));

        tcp_header.source = htons(12345);
        tcp_header.dest = htons(ports[i]);
        tcp_header.seq = htonl(rand());
        tcp_header.doff = 5;
        tcp_header.syn = 1;
        tcp_header.window = htons(1024);

        //sending SYN packets
        if(sendto(sockfd, &tcp_header, sizeof(tcp_header), 0, (struct sockaddr*)&target, sizeof(target)) < 0){
            perror("[ERROR] Failed to send SYN packet");
        }else{
            printf("%-8d%-20s%-10s\n", ports[i], get_service_name(ports[i]), "Open/Filtered (SYN Sent)");
        }
        close(sockfd);
    }
}

//main function
int main(int argc, char *argv[]){
    //check if the correct number (minimum) of arguments if provided
    if (argc < 3){
        fprintf(stderr, "[ERROR] Incorrect Usage. Example: \n");
        fprintf(stderr, "./nome -h <IP> -p <ports> [--method]\n");
        return EXIT_FAILURE;
    }

    char *ip = NULL;
    int top_ports = 0;
    int* ports = NULL;
    int num_ports = 0;
    int use_syn_scan = 0;

    //process the arguments
    for(int i = 1; i < argc; i++){
        if(strcmp(argv[i], "-h") == 0){
            ip = argv[++i]; //assign the IP after -h
        }else if(strcmp(argv[i], "-p") == 0){
            ports = parse_ports(argv[++i], &num_ports); //parse the ports passed after -p
        }else if(strcmp(argv[i], "--top") == 0){
            top_ports = atoi(argv[++i]); //assign the number of top ports
        }else if(strcmp(argv[i], "--syn") == 0){
            use_syn_scan = 1; //use SYN Scan
        }
    }

    if(ip == NULL) {
        fprintf(stderr, "[ERROR] Target IP not specified\n");
        return EXIT_FAILURE;
    }

    if(ports != NULL && top_ports > 0) {
        fprintf(stderr, "[ERROR] You cannot use both -p and --top at the same time.\n");
        return EXIT_FAILURE;
    }

    printf("Scanning IP: %s\n", ip);
    if (ports != NULL) {
        printf("Scanning the ports: ");
        for(int i = 0; i < num_ports; i++) {
            printf("%d", ports[i]);
            if(i < num_ports - 1) printf(", ");
        }
        printf("\n\n");

        // Medindo tempo de execução
        clock_t start_time = clock();

        if (use_syn_scan) {
            syn_scan(ip, ports, num_ports); //use syn scan
        } else {
            scan_ports(ip, ports, num_ports); //tcp connect
        }

        clock_t end_time = clock();
        double time_spent = (double)(end_time - start_time) / CLOCKS_PER_SEC;
        printf("\nScanned in: %.5fms\n", time_spent);
    }


    if(top_ports > 0){
        printf("Scanning the top %d most common ports...\n", top_ports);
    
        //here we go implement a way to scan the top N common ports, but for now, just a placeholder
    }

    //free allocated memory for ports
    if(ports != NULL){
        free(ports);
    }


    return EXIT_SUCCESS;
}
