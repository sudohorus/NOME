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

    //parse the ports
    char* token = strtok(str, ",");
    int index = 0;
    while(token != NULL){
        ports[index++] = atoi(token);
        token = strtok(NULL, ",");
    }
    return ports;
}

//function to perform a TCP Connect Scan
void scan_ports(char* ip, int* ports, int num_ports){
    struct sockaddr_in server_addr;
    int sockfd;
    int result;
    fd_set write_fds;
    struct timeval timeout;
    int conn_result;

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
                printf("%d = Closed\n", ports[i]);
            } else {
                printf("%d = Unknown\n", ports[i]);
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
                    printf("%d = Open\n", ports[i]);
                } else {
                    printf("%d = Closed\n", ports[i]);
                }
            } else {
                printf("%d = Unknown\n", ports[i]);
            }
        } else {
            printf("%d = Closed\n", ports[i]);
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
        printf("\n");

        //measure execution time
        clock_t start_time = clock();
        //scan specified ports
        scan_ports(ip, ports, num_ports);
        clock_t end_time = clock();
        double time_spent = (double)(end_time - start_time) / CLOCKS_PER_SEC;
        printf("Scanned in: %.5fms\n", time_spent);
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
