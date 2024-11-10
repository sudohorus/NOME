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

//function to return the name of service (placeholder)
const char* get_service_name(int port) {
    switch(port) {
        case 20: return "FTP Data";
        case 21: return "FTP Control";
        case 22: return "SSH";
        case 23: return "Telnet";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 443: return "HTTPS";
        case 1433: return "MS SQL Server";
        case 3306: return "MySQL";
        case 8080: return "HTTP Alternate";
        case 69: return "TFTP";
        case 161: return "SNMP";
        case 162: return "SNMP Trap";
        case 445: return "Microsoft-DS";
        case 3389: return "RDP (Remote Desktop Protocol)";
        case 5432: return "PostgreSQL";
        case 6379: return "Redis";
        case 993: return "IMAPS";
        case 995: return "POP3S";
        case 465: return "SMTPS (SMTP Secure)";
        case 1521: return "Oracle DB";
        case 27017: return "MongoDB";
        case 5000: return "UPnP (Universal Plug and Play)";
        case 5060: return "SIP (Session Initiation Protocol)";
        case 8888: return "HTTP Alternate (Web Proxy)";
        case 9100: return "Printer (JetDirect)";
        case 9898: return "XMPP (Jabber)";
        case 27015: return "Steam";
        case 500: return "ISAKMP (IPSec)";
        case 514: return "Syslog";
        case 5140: return "TeamSpeak";
        case 993: return "IMAPS (Secure IMAP)";
        case 995: return "POP3S (Secure POP3)";
        case 389: return "LDAP (Lightweight Directory Access Protocol)";
        case 636: return "LDAPS (Secure LDAP)";
        case 443: return "HTTPS (HTTP Secure)";
        case 25: return "SMTP (Simple Mail Transfer Protocol)";
        case 110: return "POP3 (Post Office Protocol)";
        case 1812: return "RADIUS Authentication";
        case 1813: return "RADIUS Accounting";
        case 5000: return "UPnP (Universal Plug and Play)";
        case 5060: return "SIP (Session Initiation Protocol)";
        case 6660: return "IRC (Internet Relay Chat)";
        case 6661: return "IRC (Internet Relay Chat)";
        case 6662: return "IRC (Internet Relay Chat)";
        case 6663: return "IRC (Internet Relay Chat)";
        case 6664: return "IRC (Internet Relay Chat)";
        case 6665: return "IRC (Internet Relay Chat)";
        case 6666: return "IRC (Internet Relay Chat)";
        case 6670: return "IRC (Internet Relay Chat)";
        case 2222: return "DirectAdmin";
        case 3306: return "MySQL";
        case 5432: return "PostgreSQL";
        case 27017: return "MongoDB";
        case 5900: return "VNC (Virtual Network Computing)";
        case 1080: return "SOCKS Proxy";
        case 4444: return "Blaster Worm";
        case 1723: return "PPTP (Point-to-Point Tunneling Protocol)";
        case 636: return "LDAPS";
        case 2200: return "X Window System";
        case 8080: return "HTTP Alternate";
        case 11211: return "Memcached";
        case 8081: return "HTTP Alternate";
        case 5672: return "AMQP (Advanced Message Queuing Protocol)";
        case 10000: return "Webmin";
        case 1194: return "OpenVPN";
        case 8888: return "Web Proxy";
        case 9000: return "SonarQube";
        case 5671: return "AMQPS (AMQP Secure)";
        case 4000: return "ICQ (Instant Messaging)";
        case 3333: return "Direct Connect";
        case 8000: return "Common HTTP Alternate";
        case 15672: return "RabbitMQ HTTP API";
        case 7000: return "L2TP (Layer 2 Tunneling Protocol)";
    
        if (port >= 49152 && port <= 65535) {
            return "Dynamic/Private Port";
        }
    
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

    printf("PORT\tSERVICE\t\tSTATE\n");
    printf("-----------------------------------\n");

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
                printf("%d\t%s\t\tClosed\n", ports[i], get_service_name(ports[i]));
            } else {
                printf("%d\t%s\t\tUnknown\n", ports[i], get_service_name(ports[i]));
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
                    printf("%d\t%s\t\tOpen\n", ports[i], get_service_name(ports[i]));
                } else {
                    printf("%d\t%s\t\tClosed\n", ports[i], get_service_name(ports[i]));
                }
            } else {
                printf("%d\t%s\t\tUnknown\n", ports[i], get_service_name(ports[i]));
            }
        } else {
            printf("%d\t%s\t\tClosed\n", ports[i], get_service_name(ports[i]));
        }

        close(sockfd);
    }
}

//main function
int main(int argc, char *argv[]){
    //check if the correct number (minimum) of arguments if provided
    if (argc < 3){
        fprintf(stderr, "[ERROR] Incorrect Usage. Example: \n");
        fprintf(stderr, "./nome -h <IP> -p <ports>\n");
        return EXIT_FAILURE;
    }

    char *ip = NULL;
    int top_ports = 0;
    int* ports = NULL;
    int num_ports = 0;

    //process the arguments
    for(int i = 1; i < argc; i++){
        if(strcmp(argv[i], "-h") == 0){
            ip = argv[++i]; //assign the IP after -h
        }else if(strcmp(argv[i], "-p") == 0){
            ports = parse_ports(argv[++i], &num_ports); //parse the ports passed after -p
        }else if(strcmp(argv[i], "--top") == 0){
            top_ports = atoi(argv[++i]); //assign the number of top ports
        }
    }

    //validate IP
    if(ip == NULL){
        fprintf(stderr, "[ERROR] Target IP not specified\n");
        return EXIT_FAILURE;
    }

    //check if both --top and -p are provided together
    if(ports != NULL && top_ports > 0){
        fprintf(stderr, "[ERROR] You cannot use both -p and --top at the same time.\n");
        return EXIT_FAILURE;
    }

    printf("Scanning IP: %s\n", ip);
    if (ports != NULL) {
        printf("Scanning the ports: ");
        for(int i = 0; i < num_ports; i++){
            printf("%d", ports[i]);
            if(i < num_ports -1) printf(", ");
        }
        printf("\n\n");

        //measure execution time
        clock_t start_time = clock();
        scan_ports(ip, ports, num_ports);
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
