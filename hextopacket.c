#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ICMP 1
#define TCP 6
#define UDP 17

unsigned int TOTAL_SIZE = 0;
unsigned int SIZE_PTR = 0;


int parse_tcp(char *, int);
int parse_udp(char *, int);
void parse_icmp(char *, int);
void parse_ip(char *, int);
char * hex_to_ip(char *);

char * hex_to_ip(char * hex_ip){

    char * ip = (char *) malloc(16);
    memset(ip, 0, 16);
    
    char * nr = (char *) malloc(4);
    memset(nr, 0, 4);

    strncpy(nr, hex_ip, 2);
    sprintf(nr, "%d", strtoul(nr, NULL, 16));
    strncat(ip + strlen(ip), nr, 3);
    strncat(ip + strlen(ip), ".", 1);
    memset(nr, 0, 4);
    
    strncpy(nr, hex_ip + 2, 2);
    sprintf(nr, "%d", strtoul(nr, NULL, 16));
    strncat(ip + strlen(ip), nr, 3);
    strncat(ip + strlen(ip), ".", 1);
    memset(nr, 0, 4);
    
    strncpy(nr, hex_ip + 4, 2);
    sprintf(nr, "%d", strtoul(nr, NULL, 16));
    strncat(ip + strlen(ip), nr, 3);
    strncat(ip + strlen(ip), ".", 1);
    memset(nr, 0, 4);
    
    strncpy(nr, hex_ip + 6, 2);
    sprintf(nr, "%d", strtoul(nr, NULL, 16));
    strncat(ip + strlen(ip), nr, 3);
    
    free(nr);
    
    return ip;
}

int parse_tcp(char * packet, int packet_size){

    char * buf = (char *) malloc(9);
    memset(buf, 0, 9);
    int pointer = 0;
    unsigned long int offset = 0;

    printf("TCP\n");

    strncpy(buf, packet + pointer, 4);
    printf("Source port: %s (%d)\n", buf, strtoul(buf, NULL, 16));
    pointer += 4;

    strncpy(buf, packet + pointer, 4);
    printf("Destination port: %s (%d)\n", buf, strtoul(buf, NULL, 16));
    pointer += 4;
 
    strncpy(buf, packet + pointer, 8);
    printf("Sequence number: %s (%d)\n", buf, strtoul(buf, NULL, 16));
    pointer += 8;

    strncpy(buf, packet + pointer, 8);
    printf("Acknowledge number: %s (%d)\n", buf, strtoul(buf, NULL, 16));
    pointer += 8;
   
    memset(buf, 0, 9);

    strncpy(buf, packet + pointer, 1);
    offset = strtoul(buf, NULL, 16);
    printf("Data offset: %s (%d)\n", buf, offset);
    pointer += 1;
     
    strncpy(buf, packet + pointer, 3);
    printf("Reserved and Flags: %s (%d)\n", buf, strtoul(buf, NULL, 16));
    pointer += 3;

    strncpy(buf, packet + pointer, 4);
    printf("Window size: %s (%d)\n", buf, strtoul(buf, NULL, 16));
    pointer += 4;
    
    strncpy(buf, packet + pointer, 4);
    printf("Checksum: %s (%d)\n", buf, strtoul(buf, NULL, 16));
    pointer += 4;

    strncpy(buf, packet + pointer, 4);
    printf("Urgent pointer: %s (%d)\n", buf, strtoul(buf, NULL, 16));
    pointer += 4;
    
    if(offset > 5){
        printf("Options not supported\n");
        pointer = offset * 8;
    }

    int data_size = (offset * 8) - pointer/2;
    
    if(data_size){
        char * data = (char *) malloc(data_size + 1);
        memset(data, 0, data_size + 1);
        strncpy(data, packet + pointer, data_size);
        printf("Data: %s\n", data);
        pointer += data_size;    
    }

    free(buf);
    
    return pointer / 2;

}

int parse_udp(char * packet, int packet_size){

    char * buf = (char *) malloc(9);
    memset(buf, 0, 9);
    int pointer = 0;
    unsigned long int length = 0;

    printf("UDP\n");

    strncpy(buf, packet + pointer, 4);
    printf("Source port: %s (%d)\n", buf, strtoul(buf, NULL, 16));
    pointer += 4;

    strncpy(buf, packet + pointer, 4);
    printf("Destination port: %s (%d)\n", buf, strtoul(buf, NULL, 16));
    pointer += 4;

    strncpy(buf, packet + pointer, 4);
    length = strtoul(buf, NULL, 16);
    printf("Length: %s (%d)\n", buf, length);
    pointer += 4;

    strncpy(buf, packet + pointer, 4);
    printf("Checksum: %s (%d)\n", buf, strtoul(buf, NULL, 16));
    pointer += 4;
   
    
    int data_size = length - 8;
    
    printf("DATA SIZE: %d\n", data_size);
    
    if(data_size){
        char * data = (char *) malloc(data_size + 1);
        memset(data, 0, data_size + 1);
        strncpy(data, packet + pointer, data_size);
        printf("Data: %s\n", data);
        pointer += data_size;
    }
    
    printf("\n");

    free(buf); 

    return pointer / 2;

}

void parse_icmp(char * packet, int packet_size){
    
    char * buf = (char *) malloc(9);
    memset(buf, 0, 9);
    int pointer = 0;
    unsigned long int type = 0;

    printf("ICMP\n");
    
    strncpy(buf, packet + pointer, 2);
    printf("Type: %s\n", buf);
    type = strtoul(buf, NULL, 16);
    pointer += 2;

    strncpy(buf, packet + pointer, 2);
    printf("Code: %s\n", buf);
    pointer += 2;

    strncpy(buf, packet + pointer, 4);
    printf("Checksum: %s\n", buf);
    pointer += 4;

    strncpy(buf, packet + pointer, 8);
    printf("Rest: %s\n", buf);
    pointer += 8;

    free(buf);

    printf("\n");

    if(type == 3){
        parse_ip(packet + pointer, packet_size - pointer);
    }

}

void parse_ip(char * packet, int packet_size){
    
    int BUF_SIZE = 9;
    int pointer = 0;
    unsigned long int IHL = 0;
    unsigned long int proto = 0;
    unsigned long int length = 0;

    if(strncmp(packet, "4", 1) == 0){
       printf("IPv4\n");
    }
    else if(strncmp(packet, "6", 1) == 0){
        printf("IPv6\nNOT SUPPORTED\n");
        return;
    }
    else{
        printf("Unknown IP type\n");
        return;
    }
    pointer += 1;
    

    char * buf = (char *) malloc(BUF_SIZE);
    memset(buf, 0, BUF_SIZE);

    //IHL
    strncpy(buf, packet + pointer, 1);
    printf("IHL: %s (%d * 4 = %dbytes)\n", buf, strtoul(buf, NULL, 16), strtoul(buf, NULL, 16) * 4); 
    IHL = strtoul(buf, NULL, 16);
    pointer += 1;

    //DSCP and ECN
    strncpy(buf, packet + pointer, 2);
    printf("DSCP & ECN: %s\n", buf);
    pointer += 2;

    //Total lenght
    strncpy(buf, packet + pointer, 4);
    length = strtoul(buf, NULL, 16);
    printf("Total length: %s (%dbytes)\n", buf, length);
    pointer += 4;
    
    //Identification
    strncpy(buf, packet + pointer, 4);
    printf("Identification: %s (%d)\n", buf, strtoul(buf, NULL, 16));
    pointer += 4;

    //Flags and Frag offset
    strncpy(buf, packet + pointer, 4);
    printf("Flags and Frag: %s\n", buf);
    pointer += 4;

    memset(buf, 0, BUF_SIZE); //Ugly hack as sizes get smaller again

    //TTL
    strncpy(buf, packet + pointer, 2);
    printf("TTL: %s (%d)\n", buf, strtoul(buf, NULL, 16));
    pointer += 2;

    //Proto
    strncpy(buf, packet + pointer, 2);
    proto = strtoul(buf, NULL, 16);
    printf("Proto: %s (%d)\n", buf, proto);
    pointer += 2;

    //Checksum
    strncpy(buf, packet + pointer, 4);
    printf("Checksum: %s (%d)\n", buf, strtoul(buf, NULL, 16));
    pointer += 4;

    //Source
    strncpy(buf, packet + pointer, 8);
    printf("Source: %s (%s)\n", buf, hex_to_ip(buf));
    pointer += 8;

    //Dest
    strncpy(buf, packet + pointer, 8);
    printf("Dest: %s (%s)\n", buf, hex_to_ip(buf));
    pointer += 8;

    if(IHL > 5){
        printf("OPTIONS NOT IMPLEMENTED\n");
        pointer = IHL * 8;
    }

    printf("\n");

    free(buf);
    
    if(TOTAL_SIZE == 0){
        TOTAL_SIZE = length;
    }

    SIZE_PTR += pointer / 2;

    printf("SIZE_PTR: %d\n", SIZE_PTR);

    if(proto == ICMP){
        parse_icmp(packet + pointer, packet_size - pointer); 
    }
    else if(proto == TCP){
        SIZE_PTR += parse_tcp(packet + pointer, packet_size - pointer);
    }
    else if(proto == UDP){
        SIZE_PTR += parse_udp(packet + pointer, packet_size - pointer);
    }
}


int main(int argc, char ** argv){
    
    if(argc < 2){
        printf("No package\n");
        return 0;
    }
        
    int packet_size = strlen(argv[1]) + 1;

    printf("PACKET SIZE: %d\n", packet_size - 1);
    
    char * packet = (char *) malloc(packet_size);
    strncpy(packet, argv[1], packet_size);

    parse_ip(packet, packet_size);
    printf("%d\n", SIZE_PTR);
    return 0;
}
