#ifndef ESP_OPEN_RTOS
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#else //not ESP_OPEN_RTOS

#include <stdarg.h>

#include <espressif/esp_common.h>
#include <espressif/esp_wifi.h>

#include <string.h>
#include <stdio.h>
#include <etstimer.h>
#include <esplibs/libmain.h>

#include <FreeRTOS.h>
#include <task.h>
#include <semphr.h>

#include <lwip/sockets.h>
#include <lwip/raw.h>
#include <lwip/igmp.h>
#include <lwip/prot/iana.h>

#include <sysparam.h>

#endif //not ESP_OPEN_RTOS


#define PROBE0 (unsigned char[]){ \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 /* 1Q 1Auth */ \
} //accessory_name with suffix goes here  @12
#define PROBE1 (unsigned char[]){ \
    0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, /* .local. @12+inl */ \
    0x00, 0xff, 0x80, 0x01, /* type ANY QU IN */ \
    0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04, /* A record TTL 120s */ \
    0xff, 0xff, 0xff, 0xff  /* ip address */ \
}
#define MDNS0 (unsigned char[]){ \
    0x00, 0x00, 0x84, 0x00, \
    0x00, 0x00, 0x00, 0x04, /* 4 answers */ \
    0x00, 0x00, 0x00, 0x02, /* 2 additional records                                // XX:XX:XX:XX:XX:XX._hap._tcp.local */ \
    0x11, 0x58, 0x58, 0x3a, 0x58, 0x58, 0x3a, 0x58, 0x58, 0x3a, 0x58, 0x58, 0x3a, 0x58, 0x58, 0x3a, 0x58, 0x58, \
    0x04, 0x5f, 0x68, 0x61, 0x70, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, /*@12         */ \
    0x00, 0x10, 0x80, 0x01, 0x00, 0x00, 0x11, 0x94,                         /*TXT, INflush, 4500s         //@inl+44 */ \
    0x00, 0x05,                                                                                           /*>txtlen@inl+53*1 */ \
    0x04, 0x73, 0x66, 0x3d, 0xff                                                   /*sf=x                 //>sf@inl+58*1 */ \
} //add TXT elements
#define MDNS1 (unsigned char[]){ \
    0xc0, 0x0c,                                                             /*referal to XX:name          //@2anl+111 */ \
    0x00, 0x21, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0xff,             /*SRV, INflush, 120s len      //@2anl+113 */ \
    0x00, 0x00, 0x00, 0x00,       0xff, 0xff                                /*prio, weight,               //>TCPport@2anl+127*2 */ \
} //host_name=accessory_name goes here
#define MDNS2 (unsigned char[]){ \
    0xc0, 0x28,                                                             /*referral to .local          //@2anl+150 */ \
    0xc0, 0xff,                                                             /*start of ref to hostname    */ \
    0x00, 0x01, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04,             /*A, INflush, 120s, len4      //@2anl+154 */ \
    0xff, 0xff, 0xff, 0xff,                                                 /*IP address                  //>IP@2anl+164*4 */ \
    0xc0, 0x1e,                                                             /*ref to _hap._tcp.local*/ \
    0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x11, 0x94, 0x00, 0x02, 0xc0, 0x0c, /*PTR, IN, TTL, len, ref to XX://@29         */ \
    0xc0, 0xff,                                                             /*ref to hostname */ \
    0x00, 0x2f, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x05,             /*NSEC, INflush, 120s, len      //@2anl+154 */ \
    0xc0, 0xff, 0x00, 0x01, 0x40,                                           /*only A record                  //>IP@2anl+164*4 */ \
    0xc0, 0x0c,                                                             /*ref to XX: */ \
    0x00, 0x2f, 0x80, 0x01, 0x00, 0x00, 0x11, 0x94, 0x00, 0x09,             /*NSEC, INflush, 4500s, len      //@2anl+154 */ \
    0xc0, 0x0c, 0x00, 0x05, 0x00, 0x00, 0x80, 0x00, 0x40                   /*TXT and SRV record             //>IP@2anl+164*4 */ \
}
#define MDNSADDR inet_addr("224.0.0.251")
static unsigned char *mdns=NULL;
static unsigned char *probe=NULL;
static int mdns_len=0;
static int probe_len=0;
static int probing=0;
static unsigned int bitmaps=0;
static uint16_t service_port;
static int base_inl;
static int8_t postfix=0;
#ifdef ESP_OPEN_RTOS
TimerHandle_t xTimer;
static QueueHandle_t xQueue;
struct AAnswer {
    in_addr_t addr;
    int nmbr;
};
static SemaphoreHandle_t xQM=NULL, xDTR=NULL;
static struct sockaddr_in clientSock;
static int    sd;
#endif

void hack_mdns_configure_finalize();

static void hack_mdns_configure_reinit(int change) {
    #ifdef ESP_OPEN_RTOS
    xSemaphoreTake( xDTR, ( TickType_t ) 2 ); //first time will fail, but that is OK
    #endif
    if (!postfix) { //we have an uninitialized postfix
        postfix=1;
    #ifdef ESP_OPEN_RTOS
        sysparam_get_int8("mdns", &postfix);
        //TODO put this somewhere sysparam_set_int8("mdns", postfix);
    #else
        postfix=-1; while (postfix<0) postfix=rand();
        postfix%=99; postfix++; //a random number between 1 and 99 represents sysparam reading
    #endif
        printf("postfix: %d\n",postfix);
    }
    if (change) {postfix++; if (postfix>99) postfix=1;}
    int inl=base_inl;
    if (postfix>1) {
        probe[13+inl++]='-';
        if (postfix>9) {
            probe[13+inl++]=postfix/10+0x30; probe[13+inl++]=postfix%10+0x30;
        } else {
            probe[13+inl++]=postfix%10+0x30;
        }
    }
    probe[12]=inl;
    memcpy(probe+13+inl,PROBE1,27);
    probe_len=40+inl;
    if (change) hack_mdns_configure_finalize();
}

void hack_mdns_configure_init(const char *inst_name, int port, const char *model_name) {
    service_port=port;
    base_inl=strlen(inst_name);
    //fixed bits using ci and c# max value, instancename with 3 extra for -NN postfix, modelname, sh space
    if (!mdns)   mdns=malloc(216+base_inl+3+strlen(model_name)+12); //to cater for re-runs
    //fixed bits plus instancename with 3 extra for -NN postfix
    if (!probe) probe=malloc( 40+base_inl+3);//to cater for re-runs
    memcpy(probe+13,inst_name,base_inl); //this location can be used by other code to read back
    memcpy(probe,PROBE0,12);
    memcpy(mdns,MDNS0,62);
    hack_mdns_configure_reinit(0);
}

void hack_mdns_add_txt(const char *key, const char *format, ...) {//make sf first item of this block so location is easy to predict
    va_list arg_ptr;
    char value[128];
    
    va_start(arg_ptr, format);
    int value_len = vsnprintf(value, sizeof(value), format, arg_ptr);
    va_end(arg_ptr);

    if (value_len && value_len < sizeof(value)-1) {
        char buffer[128];
        if (!strcmp(key,"sf")) {
            mdns[61]=value[0];
        } else {
            if (!strcmp(key,"id")) memcpy(mdns+13,value,17);
            int buffer_len = snprintf(buffer, sizeof(buffer), "%c%s=%s", (int)(strlen(key)+strlen(value)+1) , key, value);
            if (buffer_len < sizeof(buffer)-1) {
                memcpy(mdns+57+mdns[56],buffer,buffer_len);
                mdns[56]+=buffer_len;
            }
        }
    }
}

void hack_mdns_configure_finalize() {
    int inl=probe[12];
    int srv=mdns[56]+57;
    memcpy(mdns+srv,MDNS1,18);
    mdns[srv+11]=inl+9;
    mdns[srv+16]=service_port/256;
    mdns[srv+17]=service_port%256;
    mdns[srv+18]=inl;
    memcpy(mdns+srv+19,probe+13,inl);
    memcpy(mdns+srv+inl+19,MDNS2,70);
    mdns[srv+inl+22]=srv+18; //reference to hostname
    mdns[srv+inl+52]=srv+18; //reference to hostname
    mdns[srv+inl+64]=srv+18; //reference to hostname
    mdns_len=srv+inl+89;
    //IP address at mdns_len-56
    for (int i=0;i<probe_len;i++) printf("%02x%s",probe[i],(i+1)%16?" ":"\n");
    printf("\n");
    for (int i=0;i<probe_len;i++) printf(" %c%s",probe[i]>31?probe[i]:'.',(i+1)%16?" ":"\n");
    printf("\n");
#ifndef ESP_OPEN_RTOS
    for (int i=0;i<mdns_len;i++) printf("%02x%s",mdns[i],(i+1)%16?" ":"\n");
    printf("\n");
    for (int i=0;i<mdns_len;i++) printf(" %c%s",mdns[i]>31?mdns[i]:'.',(i+1)%16?" ":"\n");
    printf("\n");
#else
    xSemaphoreGive( xDTR ); // deblock the semaphores via hack_mdns_anno
#endif
}

#ifdef ESP_OPEN_RTOS
#define DEBUG0
#define DEBUG5

#ifdef DEBUG5
#define DEBUG(message, ...) printf(">>> " message , ##__VA_ARGS__)
#else
#define DEBUG(message, ...)
#endif
#ifdef DEBUG0
#define INFO(message, ...) printf("--- " message , ##__VA_ARGS__)
#else
#define INFO(message, ...)
#endif

/* START OF MACRO FUNCTION GETNAME */
#define GETNAME  \
j=i; tag=buf[j]; n=0; ref=0; \
while (tag) { /*if tag==0 then end of name */ \
    if (tag>=0xc0) { /*referring*/ \
        ref++;j=256*(tag-0xc0)+buf[j+1]; \
        if (ref==1) i+=2; \
    } else { \
        if (tag>0x40 || j+1+tag>len || n+tag>93) {printf("mdns-error t=%d i=%d j=%d n=%d\n",tag,i,j,n);return;} /*label longer 64 or pointing out of buf */ \
        memcpy(name+n,buf+j+1,tag); \
        n+=tag; \
        name[n++]=0x2e; /*full stop . */ \
        j+=tag+1; \
        if (!ref) i+=tag+1; \
    } \
    tag=buf[j]; \
} \
name[n]=0; /*close string */ \
if (!ref) i++ /*count the closing zero if never referred*/ \
/* END OF MACRO FUNCTION GETNAME, no closing ; */

/******************************************************************************
    * FunctionName : parse_mdns
    * Description  : returns which type of question needs to be answered relevant to us
    * Parameters   : buf -- data in
    * Returns      : unsigned int bitmap: see hack_mdns_recv
*******************************************************************************/
void parse_mdns(char* buf, unsigned int len, unsigned int *bitmap) {
    int response=0,flush=1;
    if (buf[0]||buf[1]||buf[3]||buf[4]) return; //not a valid request or response with id=0 and less than 256 questions
    if (buf[2]!=0     &&  buf[2]!=0x84) return;
    if (buf[2]==0x84) response=1;
    unsigned int i=5;
    unsigned int j,n,ref,tag;
    char   name[96]; //in real life never bigger than 80 but theoretically could be 256
    char   srvc[18+18]; //make these global?
    char   host[64];
    char   hap[]="_hap._tcp.local.";
    memcpy(srvc,mdns+13,mdns[12]);srvc[mdns[12]]=0;
    strcat(srvc,".");
    strcat(srvc,hap);
    memcpy(host,probe+13,probe[12]);host[probe[12]]=0;
    strcat(host,hap+9);
    DEBUG("SRVC: %s  HOST: %s ThisIsA %s @ %d\n",srvc,host,response?"Response":"Query",sdk_system_get_time()/1000);
    
    int qu=buf[i]; //number of questions
    int an=buf[i+2]; //number of answers
    int au=buf[i+4]; //number of authorities
    i=0x0c;   //start of name area
    while (qu) {
        GETNAME;
        DEBUG("Q%s: %s\n",buf[i+2]?"U":"M",name);
        if (!response) { //ignore questions in a response RFC6762:??
            switch (buf[i+1]) {  //is this a question for us?
                case 16: { //SRVC TXT
                    if (!strcmp(name,srvc)) {
                        INFO("Q%s srvcTXT\n",buf[i+2]?"U":"M");
                        *bitmap|=1; if (!buf[i+2]) *bitmap|=1*256; //QM
                    } break;
                }
                case 33: { //SRVC SRV
                    if (!strcmp(name,srvc)) {
                        INFO("Q%s srvcSRV\n",buf[i+2]?"U":"M");
                        *bitmap|=2; if (!buf[i+2]) *bitmap|=2*256; //QM
                    } break;
                }
                case  1: { //HOST A
                    if (!strcmp(name,host)) {
                        INFO("Q%s hostA\n",buf[i+2]?"U":"M");
                        *bitmap|=4; if (!buf[i+2]) *bitmap|=4*256; //QM
                    } break;
                }
                case 12: { //HAP PTR
                    if (!strcmp(name,hap)) {
                        INFO("Q%s _hapPTR\n",buf[i+2]?"U":"M");
                        *bitmap|=8; if (!buf[i+2]) *bitmap|=8*256; //QM
                    } break;
                }
                case 28: { //HOST AAAA
                    if (!strcmp(name,host)) {
                        INFO("Q%s hostAAAA\n",buf[i+2]?"U":"M");
                        *bitmap|=16; if (!buf[i+2]) *bitmap|=16*256; //QM
                    } break;
                }
                case 255: { //HOST or SRVC ANY
                    if (!strcmp(name,host)) {
                        INFO("Q%s hostANY\n",buf[i+2]?"U":"M");
                        *bitmap|=32; if (!buf[i+2]) *bitmap|=32*256; //QM
                    }
                    if (!strcmp(name,srvc)) {
                        INFO("Q%s srvcANY\n",buf[i+2]?"U":"M");
                        *bitmap|=64; if (!buf[i+2]) *bitmap|=64*256; //QM
                    } break;
                }
                default: break;
            }
        }
        i+=4; //flush type, Class and QM
        qu--; //next question
    }
    if (*bitmap || response) {
        while (an) {
            GETNAME;
            DEBUG("AN: %s\n",name);
            /* RFC6762/8.1 line 1475: In the case of a host
               probing using query type "ANY" as recommended above, any answer
               containing a record with that name, of any type, MUST be considered a
               conflicting response and handled accordingly. */
            if (probing && !strcmp(name,host)) {INFO("CF host\n"); *bitmap|=32*256*256*256;}
            if (probing && !strcmp(name,srvc)) {INFO("CF srvc\n"); *bitmap|=64*256*256*256;}
            flush=1;
            switch (buf[i+1]) {  //is this an answer about us?
                case 16: { //SRVC TXT
                    if (!strcmp(name,srvc)) {
                        if (response) {
                            //if content conflicts
                            INFO("CF srvc TXT or ECHO\n"); //RFC6762/Ch9
                            *bitmap|=1*256*256*256;
                        } else {
                            INFO("KT srvc\n");
                            *bitmap|=1*256*256;
                        }
                    } break;
                }
                case 33: { //SRVC SRV
                    if (!strcmp(name,srvc)) {
                        if (response) {
                            //if content conflicts
                            INFO("CF srvc SRV or ECHO\n"); //RFC6762/Ch9
                            *bitmap|=2*256*256*256;
                        } else {
                            INFO("KS srvc\n");
                            *bitmap|=2*256*256;
                        }
                    } break;
                }
                case  1: { //HOST A
                    if (!strcmp(name,host)) {
                        flush=0; i+=14; //flush type, Class, flush, ttl and len and IPv4
                        DEBUG("4: %d.%d.%d.%d\n",buf[i-4],buf[i-3],buf[i-2],buf[i-1]);
                        if (response) {
                            if (buf[i-4]!=probe[36+probe[12]] || buf[i-3]!=probe[37+probe[12]] || 
                                buf[i-2]!=probe[38+probe[12]] || buf[i-1]!=probe[39+probe[12]] ) {
                                INFO("CF host A\n"); //RFC6762/Ch9
                                *bitmap|=4*256*256*256;
                            } else {
                                INFO("ECHO host A\n"); //RFC6762/Ch9
                            }
                        } else {
                            INFO("KA host\n");
                            *bitmap|=4*256*256;
                        }
                    } break;
                }
                case 12: { //HAP PTR
                    if (!strcmp(name,hap)) {
                        //INFO("AN _hapPTR\n");
                        flush=0; i+=10; //flush type, Class, flush, ttl and len
                        GETNAME;
                        DEBUG("RP: %s\n",name);
                        if (!strcmp(name,srvc)) { //SRVC
                            if (response) {
                                INFO("ECHO srvc PTR\n");
                            } else {
                                INFO("KP srvc\n");
                                *bitmap|=8*256*256;
                            }
                        }
                    }
                    break;
                }
                case 28: { //HOST AAAA
                    if (!strcmp(name,host)) {
                        if (response) {
                            //if content conflicts
                            INFO("CF host AAAA or ECHO\n"); //RFC6762/Ch9
                            *bitmap|=16*256*256*256;
                        } else {
                            INFO("K6 host\n");
                            *bitmap|=16*256*256;
                        }
                    } break;
                }
                default: break;
            }
            if (flush) {
                i+=8; //flush type, Class, flush, and ttl
                i+=2+buf[i]*256+buf[i+1]; //flush len and content
            }
            an--; //next answer
        }
    }
    while (au) {
        GETNAME;
        DEBUG("AU: %s\n",name);
        if (!strcmp(name,host)) {INFO("AU host\n"); *bitmap|=32*256*256;}
        if (!strcmp(name,srvc)) {INFO("AU srvc\n"); *bitmap|=64*256*256;}
        i+=8; //flush type, Class, flush, and ttl
        i+=2+buf[i]*256+buf[i+1]; //flush len and content
        au--; //next authority
    }
}

void hack_mdns_recv(void *arg) {
    struct AAnswer answer;
    struct sockaddr_in localSock;
    struct ip_mreq group;
    char databuf[1500];
    int  datalen = sizeof(databuf);
    int len;
    unsigned int bitmap=0, bitmask=0;
    unsigned int cSlen=sizeof(clientSock);

    int reuse = 1; //TODO do we need this??
    if(setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) < 0)
 
    memset((char *) &localSock, 0, sizeof(localSock));
    localSock.sin_family = AF_INET;
    localSock.sin_port = htons(5353);
    localSock.sin_addr.s_addr = INADDR_ANY;
    if(bind(sd, (struct sockaddr*)&localSock, sizeof(localSock))) printf("error bind\n");
 
    while (sdk_wifi_station_get_connect_status() != STATION_GOT_IP) {printf("no-wifi-recv\n"); vTaskDelay(100);}
    group.imr_multiaddr.s_addr = MDNSADDR;
    group.imr_interface.s_addr = htonl(INADDR_ANY); //inet_addr("192.168.178.11");
    struct netif *netif = sdk_system_get_netif(STATION_IF);
    LOCK_TCPIP_CORE();
    if(setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&group, sizeof(group)) < 0) printf("error rsockopt\n");
    if (!(netif->flags & NETIF_FLAG_IGMP)) {
        netif->flags |= NETIF_FLAG_IGMP;
        if (igmp_start(netif)!= ERR_OK) printf("error igmp\n");
    }
    const ip_addr_t gMulticastV4Addr = IPADDR4_INIT_BYTES(224,0,0,251);
    if(igmp_joingroup_netif(netif, ip_2_ip4(&gMulticastV4Addr))!=ERR_OK)  printf("error join\n");
    UNLOCK_TCPIP_CORE();
    
    while(1) {
        while (sdk_wifi_station_get_connect_status() != STATION_GOT_IP) {printf("no-wifi-recv\n"); vTaskDelay(100);}
        len=recvfrom(sd, databuf, datalen,0,(struct sockaddr*)&clientSock, &cSlen);
        if (len < 0) printf("error recvfrom\n");
        else parse_mdns(databuf, len, &bitmap);
        //Q=question,M=multicast-q,A=Authority,K=KnownAnswer,C=conflict and NS=ANYsrvc,NH=ANYhost,6=AAAA,S=SRV,T=TXT,P=PTR
        if (bitmap) {//0x 40  20  10   8   4   2   1
                     //  QNS QNH  Q6  QP  QA  QS  QT  *1
                     //  MNS MNH  M6  MP  MA  MS  MT  *256
                     //  ANS ANH  K6  KP  KA  KS  KT  *256*256
                     //  CNS CNH  C6  CP  CA  CS  CT  *256*256*256
            INFO("bitmap: %06x clientaddr %08x @ %d\n",bitmap, clientSock.sin_addr.s_addr,sdk_system_get_time()/1000);
            if (bitmap&0x04000000) { //conflict: RFC6762/9
                INFO("conflicting A host detected\n");
                probing=3;
            }
            if (bitmap&0x20000000) { //conflict: RFC6762/8
                INFO("change host postfix\n");
                hack_mdns_configure_reinit(1);
                probing=4;
            }
            if (bitmap&0x00000020 && bitmap&0x00200000) {
                INFO("prober found\n");
                answer.addr=clientSock.sin_addr.s_addr; answer.nmbr=3; //defend
                xQueueSendToFront(xQueue, (void*)&answer, (TickType_t)0);
            }
            bitmap&=0x000F0F0F; //remove all bits related to conflicts and probing
            //dilemma: if QU but known answer, why bother? but will send answer anyway
            bitmask=((~bitmap)&0x0F00)>>8; //all unicast bits
            if (bitmap&bitmask) { //some relevant question was presented for Unicast answering
                answer.addr=clientSock.sin_addr.s_addr;
                if (bitmap&0x1) answer.nmbr=1; //TXT
                if (bitmap&0x2) answer.nmbr=2; //SRV
                if (bitmap&0x4) answer.nmbr=3; //A
                if (bitmap&0x8) answer.nmbr=4; //PTR             
                xQueueSendToBack(xQueue, (void*)&answer, (TickType_t)0);
            }
            //prepare multicast answers
            //bitmask=(~((bitmap>>8)&0xF00))&0xF00; //a known answer will null M bit and all Q and K bits
            bitmask=(~(bitmap>>8))&0xF00; //a known answer will null M bit and all Q and K bits
            DEBUG("bitmap=%06x bitmask=%06x &=%06x\n",bitmap,bitmask,bitmap&bitmask);
            bitmaps|=bitmap&bitmask;//merge bitmaps, only care about M bit
            //wait=sdk_os_random(20-120ms);
            if( bitmaps && xTimerIsTimerActive( xTimer ) == pdFALSE ){
                xTimerChangePeriod( xTimer, 100 / portTICK_PERIOD_MS, 0 ); //also starts timer
            }
            bitmap=0;
        }
    }
}

void vTimerCallback( TimerHandle_t xTimer ){
    if (bitmaps) {
        xTimerChangePeriod( xTimer, 1000 / portTICK_PERIOD_MS, 0 ); //start self with 1s to block  RFC6762/6line856
        struct AAnswer answer;
        answer.addr=MDNSADDR;
        if (bitmaps&0x100) answer.nmbr=1; //TXT
        if (bitmaps&0x200) answer.nmbr=2; //SRV
        if (bitmaps&0x400) answer.nmbr=3; //A
        if (bitmaps&0x800) answer.nmbr=4; //PTR             
        xQueueSendToBack(xQueue, (void*)&answer, (TickType_t)0);
    }
    INFO("bitmaps %06x timer @ %d\n",bitmaps,sdk_system_get_time()/1000);
    bitmaps=0;
}

void hack_mdns_anno(void *arg) {
    struct AAnswer answer;
    xSemaphoreTake( xDTR, ( TickType_t ) portMAX_DELAY );//wait till deblocked by hack_mdns_configure_finalize
    xSemaphoreGive( xDTR );
    while(1) {
        while (sdk_wifi_station_get_connect_status() != STATION_GOT_IP) {printf("no-wifi-anno\n"); vTaskDelay(100);}
//TODO    if (reconfig) skip probing; RFC6762/8.4
        //TODO random 0-250msec delay in wifi detection loop RFC6762/8.1
        probing=3;
        while (probing) { // keep looping if conflict is found as conveyed by setting back to probing=4; !
            if (probing==4) {probing--; vTaskDelay(500);}//5sec RFC6762/8.1 line 1485
            answer.addr=MDNSADDR; answer.nmbr=0;
            xQueueSendToBack(xQueue, (void*)&answer, (TickType_t)0);
            vTaskDelay(25);//250msec RFC6762/8.1
            probing--;
        }
        //TODO store postfix in sysparam
        answer.addr=MDNSADDR; answer.nmbr=4;
        xQueueSendToBack(xQueue, (void*)&answer, (TickType_t)0);
        vTaskDelay(100);//1sec RFC6762/8.3
        answer.addr=MDNSADDR; answer.nmbr=4;
        xQueueSendToBack(xQueue, (void*)&answer, (TickType_t)0);
        vTaskDelay(200);//2sec
        answer.addr=MDNSADDR; answer.nmbr=4;
        xQueueSendToBack(xQueue, (void*)&answer, (TickType_t)0);
        vTaskDelay(400);//4sec
        answer.addr=MDNSADDR; answer.nmbr=4;
        xQueueSendToBack(xQueue, (void*)&answer, (TickType_t)0);
        //*/
        int t=3600;//1hour
        while(t--) {
           if (sdk_wifi_station_get_connect_status() != STATION_GOT_IP || probing) t=0;
            vTaskDelay(100);//1sec
        }
    }
}

void hack_mdns_send(void *arg) {
    struct AAnswer answer;
    struct ip_info ipinfo;
    struct in_addr anyInterface;
    struct sockaddr_in mdnsSock;
    memset((char *) &mdnsSock, 0, sizeof(mdnsSock));
    mdnsSock.sin_family = AF_INET;
    mdnsSock.sin_addr.s_addr = MDNSADDR;
    mdnsSock.sin_port = htons(5353);
    char loopch = 0;
    if (setsockopt(sd, IPPROTO_IP, IP_MULTICAST_LOOP, (char *)&loopch, sizeof(loopch)) < 0) printf("error loopopt\n");
    while (sdk_wifi_station_get_connect_status() != STATION_GOT_IP) {printf("no-wifi-send\n"); vTaskDelay(100);}
    anyInterface.s_addr = htonl(INADDR_ANY); //inet_addr("192.168.178.11");
    if (setsockopt(sd, IPPROTO_IP, IP_MULTICAST_IF, (char *)&anyInterface, sizeof(anyInterface)) < 0) printf("error sockopt\n");
    while(1) {
        if (xQueueReceive(xQueue, &(answer), ( TickType_t ) portMAX_DELAY ) == pdTRUE ) {
            while (sdk_wifi_station_get_connect_status() != STATION_GOT_IP) {printf("no-wifi-send\n"); vTaskDelay(100);}
            sdk_wifi_get_ip_info(STATION_IF, &ipinfo);
            if (!probing) {
                memcpy(mdns+mdns_len-56,&ipinfo.ip.addr,4);
                mdnsSock.sin_addr.s_addr = answer.addr;
                mdns[7]=answer.nmbr;mdns[11]=6-answer.nmbr;
                sendto(sd, mdns, mdns_len, 0, (struct sockaddr*)&mdnsSock, sizeof(mdnsSock));
            } else {
                memcpy(probe+36+probe[12],&ipinfo.ip.addr,4);
                mdnsSock.sin_addr.s_addr = MDNSADDR;
                sendto(sd, probe, probe_len, 0, (struct sockaddr*)&mdnsSock, sizeof(mdnsSock));
            }
            INFO("Sent %d answers to %08x @ %d\n",answer.nmbr,mdnsSock.sin_addr.s_addr,sdk_system_get_time()/1000);
        }
    }
}

void hack_mdns_init() {

    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd<0) printf("error sd\n");


    xTimer = xTimerCreate("Timer",1,pdFALSE,NULL,vTimerCallback);
    xQueue = xQueueCreate(10, sizeof(struct AAnswer));
    xQM = xSemaphoreCreateBinary();
    xDTR = xSemaphoreCreateBinary(); //first give will be done by hack_mdns_configure_finalize
    xTaskCreate(hack_mdns_send, "mdnssend", 512, NULL, 1, NULL);
    xTaskCreate(hack_mdns_recv, "mdnsrecv", 1024, NULL, 1, NULL);
    xTaskCreate(hack_mdns_anno, "mdnsanno", 128, NULL, 1, NULL);
}

#endif //ESP_OPEN_RTOS
//////////////////////////////// code to test packet construction standalone below: use gcc hackmdns.c ; ./a.out

#ifndef ESP_OPEN_RTOS
int main() {
    srand(time(NULL));
    hack_mdns_configure_init("instancename",664,"modelname");

        // accessory model name (required)
    hack_mdns_add_txt("md", "%s", "modelname");
    // protocol version (required)
    hack_mdns_add_txt("pv", "1.0");
    // device ID (required)
    // should be in format XX:XX:XX:XX:XX:XX, otherwise devices will ignore it
    hack_mdns_add_txt("id", "%s", "12:23:34:45:56:AB");
    // current configuration number (required)
    hack_mdns_add_txt("c#", "%u", 1); //4294967295
    // current state number (required)
    hack_mdns_add_txt("s#", "1");
    // feature flags (required if non-zero)
    //   bit 0 - supports HAP pairing. required for all HomeKit accessories
    //   bits 1-7 - reserved
    hack_mdns_add_txt("ff", "0");
    // status flags
    //   bit 0 - not paired
    //   bit 1 - not configured to join WiFi
    //   bit 2 - problem detected on accessory
    //   bits 3-7 - reserved
    hack_mdns_add_txt("sf", "%d", 0);
    // accessory category identifier
    hack_mdns_add_txt("ci", "%d", 1); //65535
    hack_mdns_add_txt("sh", "%s", "ba64hash");
    
    hack_mdns_configure_finalize();
// second run
    hack_mdns_configure_init("instancename",664,"modelname");

        // accessory model name (required)
    hack_mdns_add_txt("md", "%s", "modelname");
    // protocol version (required)
    hack_mdns_add_txt("pv", "1.0");
    // device ID (required)
    // should be in format XX:XX:XX:XX:XX:XX, otherwise devices will ignore it
    hack_mdns_add_txt("id", "%s", "12:23:34:45:56:AB");
    // current configuration number (required)
    hack_mdns_add_txt("c#", "%u", 1); //4294967295
    // current state number (required)
    hack_mdns_add_txt("s#", "1");
    // feature flags (required if non-zero)
    //   bit 0 - supports HAP pairing. required for all HomeKit accessories
    //   bits 1-7 - reserved
    hack_mdns_add_txt("ff", "0");
    // status flags
    //   bit 0 - not paired
    //   bit 1 - not configured to join WiFi
    //   bit 2 - problem detected on accessory
    //   bits 3-7 - reserved
    hack_mdns_add_txt("sf", "%d", 1);
    // accessory category identifier
    hack_mdns_add_txt("ci", "%d", 1); //65535
    hack_mdns_add_txt("sh", "%s", "ba64hash");
    
    hack_mdns_configure_finalize();
    
    hack_mdns_configure_reinit(1);
}
#endif  //not ESP_OPEN_RTOS
