HEADER FILES
--------------------------------------------------------------------------------------------------------------------------------
#include<time.h>
#include<stdio.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<string.h>
#include<sys/select.h>
#include<pthread.h>
#include<signal.h>
#include<stdlib.h>
#include<fcntl.h>
#include<sys/shm.h>
#include<unistd.h>
#include<sys/un.h>
#include<netinet/ip.h>
#include<arpa/inet.h>
#include<pcap.h>
#include<errno.h>
#include<netinet/if_ether.h>
#include<net/ethernet.h>
#include<netinet/ether.h>
#include<netinet/udp.h>

/**
 This function is used to send file descriptor over Unix domain socket
 You can use this function with file descriptor return
 by any one of below functions
 1 .  socketpair();
 2 .  socket(AF_UNIX,...);
 3 .  socket(AF_LOCAL,...);
 @param socket file_descriptor_of_sender
 @param fd_to_send
*/
				SEND_FD AND RECV_FD
---------------------------------------------------------------------------------------------------------------------

int send_fd(int socket, int fd_to_send)
 {
  struct msghdr socket_message;
  struct iovec io_vector[1];
  struct cmsghdr *control_message = NULL;
  char message_buffer[1];
  /* storage space needed for an ancillary element with a paylod of length is CMSG_SPACE(sizeof(length)) */
  char ancillary_element_buffer[CMSG_SPACE(sizeof(int))];
  int available_ancillary_element_buffer_space;

  /* at least one vector of one byte must be sent */
  message_buffer[0] = 'F';
  io_vector[0].iov_base = message_buffer;
  io_vector[0].iov_len = 1;

  /* initialize socket message */
  memset(&socket_message, 0, sizeof(struct msghdr));
  socket_message.msg_iov = io_vector;
  socket_message.msg_iovlen = 1;

  /* provide space for the ancillary data */
  available_ancillary_element_buffer_space = CMSG_SPACE(sizeof(int));
  memset(ancillary_element_buffer, 0, available_ancillary_element_buffer_space);
  socket_message.msg_control = ancillary_element_buffer;
  socket_message.msg_controllen = available_ancillary_element_buffer_space;

  /* initialize a single ancillary data element for fd passing */
  control_message = CMSG_FIRSTHDR(&socket_message);
  control_message->cmsg_level = SOL_SOCKET;
  control_message->cmsg_type = SCM_RIGHTS;
  control_message->cmsg_len = CMSG_LEN(sizeof(int));
  *((int *) CMSG_DATA(control_message)) = fd_to_send;

  return sendmsg(socket, &socket_message, 0);
 }
 
 
 
 
 
 int recv_fd(int socket)
 {
  int sent_fd, available_ancillary_element_buffer_space;
  struct msghdr socket_message;
  struct iovec io_vector[1];
  struct cmsghdr *control_message = NULL;
  char message_buffer[1];
  char ancillary_element_buffer[CMSG_SPACE(sizeof(int))];

  /* start clean */
  memset(&socket_message, 0, sizeof(struct msghdr));
  memset(ancillary_element_buffer, 0, CMSG_SPACE(sizeof(int)));

  /* setup a place to fill in message contents */
  io_vector[0].iov_base = message_buffer;
  io_vector[0].iov_len = 1;
  socket_message.msg_iov = io_vector;
  socket_message.msg_iovlen = 1;

  /* provide space for the ancillary data */
  socket_message.msg_control = ancillary_element_buffer;
  socket_message.msg_controllen = CMSG_SPACE(sizeof(int));

  if(recvmsg(socket, &socket_message, MSG_CMSG_CLOEXEC) < 0)
   return -1;

  if(message_buffer[0] != 'F')
  {
   /* this did not originate from the above function */
   return -1;
  }

  if((socket_message.msg_flags & MSG_CTRUNC) == MSG_CTRUNC)
  {
   /* we did not provide enough space for the ancillary element array */
   return -1;
  }

  /* iterate ancillary elements */
   for(control_message = CMSG_FIRSTHDR(&socket_message);
       control_message != NULL;
       control_message = CMSG_NXTHDR(&socket_message, control_message))
  {
   if( (control_message->cmsg_level == SOL_SOCKET) &&
       (control_message->cmsg_type == SCM_RIGHTS) )
   {
    sent_fd = *((int *) CMSG_DATA(control_message));
    return sent_fd;
   }
  }

  return -1;
 }
 ----------------------------------------------------------------------------------------------------
pipes

server.c

int main()
{  
	mkfifo("s2c_pipe1",0666);
	mkfifo("s2c_pipe2",0666);
	mkfifo("s2c_pipe3",0666);

	mkfifo("c2s_pipe1",0666);
	mkfifo("c2s_pipe2",0666);
	mkfifo("c2s_pipe3",0666);

    char buffer[MAX_BUF];	
    int rfd1,rfd2,rfd3,wfd1,wfd2,wfd3;
    
    rfd1=open("c2s_pipe1", O_RDONLY| O_NONBLOCK);
    rfd2=open("c2s_pipe2", O_RDONLY);
    rfd3=open("c2s_pipe3", O_RDONLY);

    wfd1=open("s2c_pipe1", O_WRONLY);
    wfd2=open("s2c_pipe2", O_WRONLY);
    wfd3=open("s2c_pipe3", O_WRONLY);



    while(1){
    	
    	read(rfd1,buffer,sizeof(buffer));
    	write(wfd2,buffer,sizeof(buffer));
    	write(wfd3,buffer,sizeof(buffer));

    	//printf("%s\n",buffer );
    	read(rfd2,buffer,sizeof(buffer));
    	write(wfd1,buffer,sizeof(buffer));
    	write(wfd3,buffer,sizeof(buffer));

    	read(rfd3,buffer,sizeof(buffer));
    	write(wfd1,buffer,sizeof(buffer));
    	write(wfd2,buffer,sizeof(buffer));

    }
	
	   
	//unlink("c2s_pipe");	
	return 0;
}

client1.c

int main()
{  
	char buffer[50];

//c2s  client to server  
	//mkfifo("c2s_pipe1",0666);
    //mkfifo("s2c_pipe1",0666); 
    
	int wfd,rfd;
	int c=fork();

	if(c >0 ){
		//parent process
		while(1){
			wfd=open("c2s_pipe1",O_WRONLY);
			read(0,buffer,sizeof(buffer));
		    write(wfd,buffer,sizeof(buffer));
	    //close(wfd);
		}

	}
	else if( c==0 ){
        //child process
			while(1){
				rfd=open("s2c_pipe1",O_RDONLY);
				read(rfd,buffer,sizeof(buffer));
	  		   // write(1,buffer,sizeof(buffer));
	  		    printf("%s\n",buffer);
	           //close(fd);
		     }
			
	}
	else
		perror("fork()");   
	//unlink("c2s_pipe");	
	return 0;
}






---------------------------------------------------------------------------------------------------
					PRINT IP HEADER AND UDP HEADER AS IT IS	
----------------------------------------------------------------------------------------------------------------------------

void print_boundary(){
	int i;

	printf("\n");

	for(i=0;i<20;i++)
	printf(" ");

	for(i=0;i<17;i++)
	printf("_");

	printf("\n");

	for(i=0;i<20;i++)
	printf(" ");
}
void print_data(int num,int fact,int extra){
	printf("%d",num);

	int count=0;
	int i;
	if(num!=0)
	while(num/fact==0)
	{
		fact/=10;
		count++;
	}

	else
	while(fact!=1)
	{
		fact=fact/10;
		printf(" ");
	}

	for(i=0;i<count;i++)
	printf(" ");


	for(i=0;i<extra;i++)
	printf(" ");

	printf("|");
}
void print_ip(struct sockaddr_in s){
	char *ip_addr;
	int n;

	ip_addr=inet_ntoa(s.sin_addr);
	n=strlen(ip_addr);
	printf("%s",ip_addr);
	int i;
	for(i=0;i<15-n;i++)
	printf(" ");
	printf("|");
}
void print_iphdr(struct iphdr *ip){
	print_boundary();
	printf("|");

	print_data(ip->version,1,0);

	print_data(ip->ihl,10,0);

	print_data(ip->tos,100,0);

	print_data(ntohs(ip->tot_len),10000,1);

	print_boundary();
	printf("|");

	print_data(ip->id,10000,3);

	print_data(ip->frag_off,10000,1);

	print_boundary();
	printf("|");

	print_data(ip->ttl,100,1);

	print_data(ip->protocol,100,0);

	print_data(ip->check,10000,1);

	print_boundary();
	printf("|");

	struct sockaddr_in s;

	s.sin_addr.s_addr=ip->saddr;
	print_ip(s);

	print_boundary();
	printf("|");

	s.sin_addr.s_addr=ip->daddr;
	print_ip(s);

	print_boundary();
	printf("\n\n");
}


void print_udphdr(struct udphdr* udp){
	print_boundary();
	printf("|");

	print_data(ntohs(udp->source),10000,2);

	print_data(ntohs(udp->dest),10000,2);

	print_boundary();
	printf("|");


	print_data(ntohs(udp->len),10000,2);

	print_data(udp->check,10000,2);

	print_boundary();
	printf("\n\n");
}








----------------------------------------------------------------------------------------

        CONNECTION ORIENTED SERVER	( usage -:  "./a.out port_no")
        TCP socket
        1. Creation
        2. Binding
        3. Listen
        4. Accept

---------------------------------------------------------------------------------------------------------------------------------
int main(int argc,char *argv[ ]){
	if(argc!=2)
	printf("\n usage ./a.out port_no");

	int sfd;
	struct sockaddr_in serv_addr,cli_addr;
	socklen_t cli_len;
	int port_no=atoi(argv[1]);
    /**
        Create tcp socket using given parameters
    */
	if((sfd = socket(AF_INET,SOCK_STREAM,0))==-1)
	perror("\n socket ");
	else printf("\n socket created successfully");

	bzero(&serv_addr,sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port_no);
	serv_addr.sin_addr.s_addr = INADDR_ANY;
    /**
        Bind created socket to an interface
    */
	if(bind(sfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr))==-1)
	perror("\n bind : ");
	else printf("\n bind successful ");

    /**
        Listen for incoming connection
    */
	listen(sfd,10);

	int nsfd;
	/**
        Accept connection if any one requested over this port and ip address
	*/
	if((nsfd = accept(sfd , (struct sockaddr *)&cli_addr , &cli_len))==-1)
	perror("\n accept ");
	else printf("\n accept successful");
	...

}
---------------------------------------------------------------------------------
		          CONNECTION ORIENTED CLIENT( usage -:  "./a.out port_no")
		            TCP socket
                    1. Creation
                    2. Connect to server
---------------------------------------------------------------------------------------------------------------------------------
int main(){
	if(argc!=2)
	printf("\n usage ./a.out port_no");

	int sfd;
	struct sockaddr_in serv_addr;
	int port_no=atoi(argv[1]);

	bzero(&serv_addr,sizeof(serv_addr));
    /**
        Create tcp socket using given parameters
    */
	if((sfd = socket(AF_INET , SOCK_STREAM , 0))==-1)
	perror("\n socket");
	else printf("\n socket created successfully\n");

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port_no);
	serv_addr.sin_addr.s_addr = INADDR_ANY;
    /**
        Connect tcp socket using given parameters
    */
	if(connect(sfd , (struct sockaddr *)&serv_addr , sizeof(serv_addr))==-1)
	perror("\n connect : ");
	else printf("\nconnect succesful");
    ...
}
---------------------------------------------------------------------------------
    CONNECTION LESS SERVER	( usage -:  "./a.out port_no")
            UDP socket
            1. Creation
            2. Binding
---------------------------------------------------------------------------------------------------------------------------------
int main(){
	if(argc!=2)
	printf("\n usage ./a.out port_no");

	int sfd;
	struct sockaddr_in serv_addr,cli_addr;
	socklen_t cli_len;
	int port_no=atoi(argv[1]);

	if((sfd = socket(AF_INET,SOCK_DGRAM,0))==-1)
	perror("\n socket ");
	else printf("\n socket created successfully");

	bzero(&serv_addr,sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port_no);
	serv_addr.sin_addr.s_addr = INADDR_ANY;

	if(bind(sfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr))==-1)
	perror("\n bind : ");
	else printf("\n bind successful ");
	...
}
-------------------------------------------------------------------------------------
		          CONNECTION LESS CLIENT	( usage -:  "./a.out port_no")
                    UDP socket
                    1. Creation
---------------------------------------------------------------------------------------------------------------------------------
int main(){
    if(argc!=2)
	printf("\n usage ./a.out port_no");

	int sfd;
	struct sockaddr_in serv_addr;
	int port_no=atoi(argv[1]);

	bzero(&serv_addr,sizeof(serv_addr));

	if((sfd = socket(AF_INET , SOCK_DGRAM , 0))==-1)
	perror("\n socket");
	else printf("\n socket created successfully\n");

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port_no);
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	...
}
------------------------------------------------------------------------
        UNIX domain SOCKET CONNECTION ORIENTED SERVER	( usage -:  "./a.out")
        1. Creation
        2. Binding
        3. Listen
        4. Accept
---------------------------------------------------------------------------------------------------------------------------------
#define ADDRESS  "mysocket"
int main(){
	int  usfd;
	struct sockaddr_un userv_addr,ucli_addr;
  	int userv_len,ucli_len;

	usfd = socket(AF_UNIX , SOCK_STREAM , 0);
	perror("socket");

  	bzero(&userv_addr,sizeof(userv_addr));

  	userv_addr.sun_family = AF_UNIX;
	strcpy(userv_addr.sun_path, ADDRESS);
	unlink(ADDRESS);
	userv_len = sizeof(userv_addr);

	if(bind(usfd, (struct sockaddr *)&userv_addr, userv_len)==-1)
	perror("server: bind");

	listen(usfd, 5);

	ucli_len=sizeof(ucli_addr);

	int nusfd;
	nusfd=accept(usfd, (struct sockaddr *)&ucli_addr, &ucli_len);
	...
}
---------------------------------------------------------------------------------
    UNIX domain SOCKET CONNECTION ORIENTED CLIENT	( usage -:  "./a.out")
        1. Creation
        2. Connect
---------------------------------------------------------------------------------------------------------------------------------
#define ADDRESS     "mysocket"
int main(){
    int usfd;
	struct sockaddr_un userv_addr;
  	int userv_len,ucli_len;

  	usfd = socket(AF_UNIX, SOCK_STREAM, 0);

  	if(usfd==-1)
  	perror("\nsocket  ");

  	bzero(&userv_addr,sizeof(userv_addr));
  	userv_addr.sun_family = AF_UNIX;
   	strcpy(userv_addr.sun_path, ADDRESS);

	userv_len = sizeof(userv_addr);

	if(connect(usfd,(struct sockaddr *)&userv_addr,userv_len)==-1)
	perror("\n connect ");

	else printf("\nconnect succesful");

    ...
}
-----------------------------------------------------------------------------------------
    RAW SOCKET SENDER  including only ip header you can include tcp and udp header as well	( usage -:  "./a.out" in super mode)
------------------------------------------------------------------------------------------------------------------------------------------
#define DEST "127.0.0.1"
#define SOURCE "127.0.0.1"

int main(void)
{

	int sfd;
	struct sockaddr_in daddr,saddr;
	char packet[50];

	/* point the iphdr to the beginning of the packet */
	struct iphdr *ip = (struct iphdr *)packet;

	if ((sfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("error:");
		exit(EXIT_FAILURE);
	}

	int one=1;
	const int *val=&one;
	setsockopt(sfd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one));
	perror("setsockopt ");

	daddr.sin_family = AF_INET;
	daddr.sin_port = 0; /* not needed in SOCK_RAW */
	inet_pton(AF_INET, DEST, (struct in_addr *)&daddr.sin_addr.s_addr);
	memset(daddr.sin_zero, 0, sizeof(daddr.sin_zero));

	saddr.sin_family = AF_INET;
	saddr.sin_port = 0; /* not needed in SOCK_RAW */
	inet_pton(AF_INET, SOURCE, (struct in_addr *)&saddr.sin_addr.s_addr);
	memset(saddr.sin_zero, 0, sizeof(saddr.sin_zero));


	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 0;
	ip->tot_len = htons(40);	/* 16 byte value */
	ip->frag_off = 0;		/* no fragment */
	ip->ttl = 64;			/* default value */
	ip->protocol = IPPROTO_RAW;	/* protocol at L4 */
	ip->check = 0;			/* not needed in iphdr */
	ip->saddr = saddr.sin_addr.s_addr
	ip->daddr = daddr.sin_addr.s_addr;

	while(1)
	{
		scanf("%s",packet+sizeof(struct iphdr));
		sendto(sfd, (char *)packet, sizeof(packet), 0, (struct sockaddr *)&daddr, (socklen_t)sizeof(daddr));
	}
}




----------------------------------------------------------------------------------

           RAW SOCKET RECIEVER
         ( usage -:  "./a.out" in super mode)
---------------------------------------------------------------------------------------------------------------------------------
int main(void)
{
	int sfd;
	struct sockaddr_in saddr;
	char packet[50];
	struct iphdr *ip = (struct iphdr *)packet;

	if ((sfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
	{
		perror("error:");
		exit(EXIT_FAILURE);
	}

	memset(packet, 0, sizeof(packet));
	int fromlen = sizeof(saddr);

	while(1)
	{
		recvfrom(sfd, (char *)&packet, sizeof(packet), 0,(struct sockaddr *)&saddr, &fromlen);
		printf("%s\n",packet+sizeof(struct iphdr));
	}
}

--------------------------------------------------------------------------------------------------------------------------------
		         SOCKET PAIR	( usage -:  "./a.out")
---------------------------------------------------------------------------------------------------------------------------------

int main()
{
	int usfd[2];
	if(socketpair(AF_UNIX,SOCK_STREAM,0,usfd)==-1)
	perror("socketpair ");
			
	int c=fork();
			
	if(c==-1)
	perror("\nfork ");
			
	else if(c>0)
	{
		close(usfd[1]);
	}
			
	else if(c==0)
	{
		close(usfd[0]);	
		dup2(usfd[1],0);
		execvp(file_name,args);
	}
	
	---------
	---------
}

----------------------------------------------------------------------------

    Pcap library helper function(s)
    To compile use  -lpcap
    e.g. gcc sniff.c -o sniff -lpcap
---------------------------------------------------------------------------------------------------------------------------------
/**
    This function is called by pcap_loop(...) function
    Whenever a packet is captured by pcap session  then it calls callback function
*/
void my_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*packet){
    struct ether_header *eptr;  /* net/ethernet.h */

    /* lets start with the ether header... */
    eptr = (struct ether_header *) packet;

    fprintf(stdout,"ethernet header source: %s\n"
            ,ether_ntoa((const struct ether_addr *)&eptr->ether_shost));
    fprintf(stdout," destination: %s\n "
            ,ether_ntoa((const struct ether_addr *)&eptr->ether_dhost));

    /* check to see if we have an ip packet */
    if (ntohs (eptr->ether_type) == ETHERTYPE_IP)
    {
        fprintf(stdout,"(IP)\n");
        struct iphdr *ip = (struct iphdr *)(packet+sizeof(struct ether_header));
	printf("\nip header is  - \n");
	print_iphdr(ip); 		//print your ip header here
					//---------------------------


	if(ip->protocol==IPPROTO_UDP)
	{
		struct udphdr *udp = (struct udphdr *)(packet+sizeof(struct ether_header)+sizeof(struct iphdr));
		printf("\nudp header is - \n");
		print_udphdr(udp);	// print your udp header here
					//-----------------------------
	}


	if(ip->protocol==IPPROTO_TCP)
	{
		struct tcphdr *tcp = (struct tcphdr *)(packet+sizeof(struct ether_header)+sizeof(struct iphdr));
		printf("\ntcp header is - \n");
		//print_tcphdr(tcp);	// print your tcp header here
					//-----------------------------
	}

    }else  if (ntohs (eptr->ether_type) == ETHERTYPE_ARP)
    {
        fprintf(stdout,"(ARP)\n");
    }else  if (ntohs (eptr->ether_type) == ETHERTYPE_REVARP)
    {
        fprintf(stdout,"(RARP)\n");
    }else {
        fprintf(stdout,"(?)");
      //  exit(1);
    }

}

/**
    libpcap main program
    It takes one argument
    1.  Number of packets
*/
int main(int argc,char **argv){
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    bpf_u_int32 maskp;          /* subnet mask               */
    bpf_u_int32 netp;           /* ip                        */
    u_char* args = NULL;

    /* Options must be passed in as a string because I am lazy */
    if(argc < 2){
        fprintf(stdout,"Usage: %s numpackets \"options\"\n",argv[0]);
        return 0;
    }

    /* grab a device to peak into... */
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL)
    { printf("%s\n",errbuf); exit(1); }

    /* ask pcap for the network address and mask of the device */
    pcap_lookupnet(dev,&netp,&maskp,errbuf);

    /* open device for reading. NOTE: defaulting to
     * promiscuous mode*/
    descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf);
    if(descr == NULL)
    { printf("pcap_open_live(): %s\n",errbuf); exit(1); }

    /* ... and loop */

    pcap_loop(descr,atoi(argv[1]),my_callback,args);

    fprintf(stdout,"\nfinished\n");
    return 0;
}
/***
    This program is same  as above but it includes filter like arp , tcp packet e.t.c
*/
int main(){
        char dev[]="eth0";/**Device name on which packet will be sniffed*/
        char errbuf[PCAP_ERRBUF_SIZE];/**Error buffer*/
        struct bpf_program  fp;/**compiled program*/
        char filter[]="arp dst net 172.30.100.195"; /**Filter expression*/
        bpf_u_int32  mask;/**our netmask*/
        bpf_u_int32 net;/**our IP address*/
        int optimize=0;/** FIlter expressions has to be optimized or not ?*/
        const u_char *packet;
        int NoofPacket = -1 ;/** -1 signifies there is no limit */
        pcap_t* phandle; /**Pcap session handler*/

        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
             fprintf(stderr, "Can't get netmask for device %s\n", dev);
             net = 0;
             mask = 0;
             return 1;
        }
		int on = 1;/**promiscuous mode*/
		phandle = pcap_open_live(dev, BUFSIZ,on,-1, errbuf);
        if (phandle == NULL) {
             fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
             return(2);
        }
        printf("Device : %s opened for sniffing\n",dev);

        if (pcap_compile(phandle, &fp, filter,optimize, net) == -1) {
             fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(phandle));
             return(3);
        }
        printf("Program compiled with filter : %s\n",filter);


        if (pcap_setfilter(phandle, &fp) == -1) {
             fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(phandle));
             return(4);
        }
        printf("Program installed with filter : %s\n",filter);

        if ( pcap_loop(phandle,NoofPacket,my_callback,NULL)==-1){
            fprintf(stderr, "pcap loop failed : %s\n",pcap_geterr(phandle));
             return(4);
        }
		return(0);
}
---------------------------------------------------------------------------
        Create shareMemory with given key and size
        1. If key is not specfied then it will ask OS
        2. It uses key to create shareMemory
        @param size : size of shareMemory
        @param key  : shareMemory identifier
---------------------------------------------------------------------------
void* shareMemory(size_t size ,int key = -1){
    int shmid;
    if(key==-1){
      shmid = shmget(IPC_PRIVATE,size,IPC_CREAT|0666);
    }
    else{
        shmid = shmget(key,size,IPC_CREAT|0666);
    }
    if(shmid < 0){
    	err_quit("shareMemory()");
    }
    return shmat(shmid,(void *)0,  0);
}








----------------------------------------------------------------------------------------------------------------------------------
				SHARE MEMORY (for an integer)
-----------------------------------------------------------------------------------------------------------------------------------

	int state=1;
	key_t h=ftok(".",state++);	// value of state should on every program where this share memory is used
 	int shmid=shmget(h,sizeof(int),IPC_CREAT|0666);
 	perror("\nshmget ");
 	int *share_memory=(int *)shmat(shmid,(const void*)0,0);
 	perror("\nshmat ");


---------------------------------------------------------------------------------------------------------------------------------- 	
 				SEMAPHORE
-----------------------------------------------------------------------------------------------------------------------------------
 	
	void sem_wait(int semid)
	{
		struct sembuf sb;
		sb.sem_num=0;
		sb.sem_op=-1;
		sb.sem_flg=0;
		if((semop(semid,&sb,1))==-1)
		{
			perror("\nFailed to acquire semaphore.");
			exit(0);
		}
	}

	void sem_try_wait(int semid)
	{
		struct sembuf sb;
		sb.sem_num=0;
		sb.sem_op=-1;
		sb.sem_flg=IPC_NOWAIT;;
		return semop(semid,&sb,1);
	}

	void sem_signal(int semid)
	{
		struct sembuf sb;
		sb.sem_num=0;
		sb.sem_op=1;
		sb.sem_flg=0;
		if((semop(semid,&sb,1))==-1)
		{
			perror("\nFailed to release semaphore.");
			exit(0);
		}
	}

	int state=1;
	key_t h=ftok(".",state++);	// value of state should on every program where this semaphore is used
	int sem_id;
	if((sem_id=semget(h,1,0666|IPC_CREAT))==-1)
 	{
		printf("error in creation semaphore\n");
		exit(0);
	}
	
	int semaphore_value=1;

	if((semctl(sem_id,0,SETVAL,semaphore_value))==-1)
	{
		printf("error to set value\n");
	}


	----------------------------------------------------------------------

	shared memory server

	#define MAX_BUF 20
#define MAX_CLIENT 20
#define MAX_GROUP 5


int shm_pid,shm_client,shm_group;
pid_t *pid_ptr,*group_ptr;;
char  *client_ptr;


int wfd[MAX_GROUP][MAX_CLIENT];
int num_of_groups=0;

struct group{
    int group_num;
    int num_of_clients;
};

struct message {
    char buf[MAX_BUF];
    int client_num;
    int group_num;
};

struct group grp[MAX_GROUP];

void process_sighandler(int sig);

int main()
{   
    struct message msg;
    char buffer[MAX_BUF]; 

    mkfifo("c2s_pipe",0666);   
    int rfd  = open("c2s_pipe",O_RDONLY | O_NONBLOCK);

    if((shm_pid=shmget(ftok(".",'p'),sizeof(pid_t),IPC_CREAT|0666)) == -1) perror("shmget()");
    else pid_ptr=shmat(shm_pid,NULL,0);

    if((shm_client=shmget(ftok(".",'c'),MAX_BUF,IPC_CREAT|0666)) == -1) perror("shmget()");
    else client_ptr=shmat(shm_client,NULL,SHM_RDONLY);

    if((shm_group=shmget(ftok(".",'g'),MAX_BUF,IPC_CREAT|0666)) == -1) perror("shmget()");
    else group_ptr=shmat(shm_group,NULL,SHM_RDONLY);

    *pid_ptr=getpid();
  
    signal(SIGUSR1,process_sighandler);
    int i,j;
    printf("pid of server : %d\n",*pid_ptr);
   
    while(1){
      
      while(read(rfd,&msg,sizeof(struct message)) <=0);
       printf("client %d typed from group %d \n",msg.client_num,msg.group_num);
            for(i=0;i< num_of_groups;i++){  
             if(grp[i].group_num == msg.group_num)
                break;
            }

            for(j=0;j<grp[i].num_of_clients;j++)
                write(wfd[i][j],&msg,sizeof(struct message));
        }

     
 shmdt(pid_ptr); 
 shmdt(client_ptr);
 shmdt(group_ptr);
    //unlink("c2s_pipe");   
return 0;
}

void process_sighandler(int sig){  
    if(sig == SIGUSR1){
         int j,flag=0,group_index;
         for(j=0;j<num_of_groups;j++){
             if(grp[j].group_num == *group_ptr)
                {flag =1 ; group_index =j;break;}
         }

        
        if(flag == 1) { // group already exists           
              grp[group_index].num_of_clients++;
        }
        else{      //group doesn't exist
            group_index=num_of_groups;
            grp[num_of_groups].group_num = *group_ptr;
            grp[num_of_groups++].num_of_clients=1;

        }

        //server to client pipe is opened in specific group
        wfd[group_index][grp[group_index].num_of_clients-1]=open(client_ptr,O_WRONLY);       
        memset(client_ptr,MAX_BUF,'\0');         
        }
        
  }



shared memory client  #include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/shm.h>
#include <signal.h>
#include <string.h>

#define MAX_BUF 20



int shm_pid,shm_client,shm_group;
pid_t *pid_ptr,*group_ptr;
char  *client_ptr;


struct message{
    char buf[MAX_BUF];
    int client_num;
    int group_num;
};

char client_name[2],group_name[2];
int  client_num=0,group_num=0;


int main()
{  
	printf("client_num < 1 - 20 > : ");
	scanf("%s",client_name);
    
    printf("Group_num <1 - 5 > : ");
	scanf("%s",group_name);

	client_num=atoi(client_name);
	group_num=atoi(group_name);

	printf("client_%d logged in group_%d \n",client_num,group_num);
    char buffer[MAX_BUF];     

    struct message msg;     
 

    if((shm_pid=shmget(ftok(".",'p'),sizeof(pid_t),IPC_CREAT|0666)) == -1) perror("shmget()");
    else pid_ptr=shmat(shm_pid,NULL,0);
    
    printf("Connected server pid : %d\n",*pid_ptr);

    if((shm_client=shmget(ftok(".",'c'),MAX_BUF,IPC_CREAT|0666)) == -1) perror("shmget()");
    else client_ptr=shmat(shm_client,NULL,0);

    if((shm_group=shmget(ftok(".",'g'),MAX_BUF,IPC_CREAT|0666)) == -1) perror("shmget()");
    else group_ptr=shmat(shm_group,NULL,0);
    
    *group_ptr=group_num;

    char s2cpipe[]="s2cpipe" ;
    strcat(s2cpipe,client_name);
    strcpy(client_ptr,s2cpipe); //storing the name of  server 2 client pipe created in shared memory
    mkfifo(s2cpipe,0666);

    int rfd_c,wfd_c;
      wfd_c=open("c2s_pipe",O_WRONLY);
      rfd_c=open(s2cpipe,O_RDONLY| O_NONBLOCK);
  
    kill(*pid_ptr,SIGUSR1);
 //fflush(stdout);
    
	int c=fork();

	if(c >0 ){
		//parent process -Writing to pipe
	      msg.client_num=client_num;
	      msg.group_num=group_num; 
		while(1){
           
			read(0,msg.buf,MAX_BUF);
		    write(wfd_c,&msg,sizeof(struct message));
	 
		}

	}
	else if( c==0 ){
        //child process -Reading from pipe
           msg.client_num=client_num;  
			while(1){
				
				 while(read(rfd_c,&msg,sizeof(struct message)) <= 0);                 

				if(msg.client_num != client_num)	  		 
	  		      printf("From %d : %s\n",msg.client_num,msg.buf);
	         
		     }
			
	}
	else
		perror("fork()");  

	

 shmdt(pid_ptr); 
 shmdt(client_ptr);
 shmdt(group_ptr);
	//unlink("c2s_pipe");	
	return 0;
}






----------------------------------------------------------------------------------------------------------------------------------
 				SELECT
----------------------------------------------------------------------------------------------------------------------------------
	fd_set readset;
	FD_ZERO(&readset);
	
	int max=-1;
	
	for(i=0;i<no_of_file_descriptors;i++)
	{
		FD_SET(fd[i], &readset);
		if(fd[i]>max)
		max=fd[i];		
	}
	
	
	struct timeval t;
	t.tv_sec=3;
	t.tv_usec=100;
	int rv = select(max + 1, &readset, NULL, NULL, &t);

	if (rv == -1) 
	{
		perror("select");
	}
	
	else if (rv == 0) 
	{
    		printf("Timeout occurred!\n");
	} 
	
	else 
	{
		int i;
		// check for events 
		for(i=0;i<no_of_file_descriptors;i++)
    		if (FD_ISSET(fd[i], &readset)) 
		{

    		}
	}



-------------------------------------------------------------------------------------------------------------------


Poll 


int main()
{  
	mkfifo("s2c_pipe1",0666);
	mkfifo("s2c_pipe2",0666);
	mkfifo("s2c_pipe3",0666);

	mkfifo("c2s_pipe1",0666);
	mkfifo("c2s_pipe2",0666);
	mkfifo("c2s_pipe3",0666);

    char buffer[MAX_BUF];	
    int rfd1,rfd2,rfd3,wfd1,wfd2,wfd3;
    
    rfd1=open("c2s_pipe1", O_RDONLY);
    rfd2=open("c2s_pipe2", O_RDONLY);
    rfd3=open("c2s_pipe3", O_RDONLY);

    wfd1=open("s2c_pipe1", O_WRONLY);
    wfd2=open("s2c_pipe2", O_WRONLY);
    wfd3=open("s2c_pipe3", O_WRONLY);


    struct pollfd fds[3];
    int timeout_msecs = 1000;
    int ret;

    fds[0].fd = rfd1;                 
    fds[0].events = POLLIN;  

    fds[1].fd = rfd2;                 
    fds[1].events = POLLIN;  

    fds[2].fd = rfd3;                 
    fds[2].events = POLLIN;  




while(1){
        ret=poll(fds,3,timeout_msecs);

       if(ret > 0) {
              
             if (fds[0].revents && POLLIN) {           
                 printf("client 1 typed..... \n");
                 read(rfd1,buffer,sizeof(buffer));
                 write(wfd2,buffer,sizeof(buffer));
                 write(wfd3,buffer,sizeof(buffer));
              }

    	
             if (fds[1].revents && POLLIN) {   
                printf("client 2 typed.....\n");
                read(rfd2,buffer,sizeof(buffer));
                write(wfd1,buffer,sizeof(buffer));
                write(wfd3,buffer,sizeof(buffer));
            }

            if (fds[2].revents && POLLIN) { 
             printf("client 3 typed.....\n");  
             read(rfd3,buffer,sizeof(buffer));
             write(wfd1,buffer,sizeof(buffer));
             write(wfd2,buffer,sizeof(buffer));
           }
    }

}


	//unlink("c2s_pipe");	
return 0;
}

---------------------------------------------------------------------------------------------------------------------------------- 	
				pthread
----------------------------------------------------------------------------------------------------------------------------------
 	
 	void do_thread_service(void *arg)
	{
		int *args= (int*)arg ;
 	
	}
	
	pthread_t t_service;
 	if(pthread_create(&t_service,NULL,(void*)&do_thread_service ,(void*)args)!=0)
	perror("\npthread_create ");
	
	
 	

----------------------------------RAW SOCKETS ALONG WITH TCP HEADERS----------------------------------------

struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};
 
/*
    Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr,int nbytes) 
{
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
 
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
     
    return(answer);
}
 
int main (void)
{
    //Create a raw socket
    int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
     
    if(s == -1)
    {
        //socket creation failed, may be because of non-root privileges
        perror("Failed to create socket");
        exit(1);
    }
     
    //Datagram to represent the packet
    char datagram[4096] , source_ip[32] , *data , *pseudogram;
     
    //zero out the packet buffer
    memset (datagram, 0, 4096);
     
    //IP header
    struct iphdr *iph = (struct iphdr *) datagram;
     
    //TCP header
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
    struct sockaddr_in sin;
    struct pseudo_header psh;
     
    //Data part
    data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
    strcpy(data , "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
     
    //some address resolution
    strcpy(source_ip , "192.168.1.2");
    sin.sin_family = AF_INET;
    sin.sin_port = htons(80);
    sin.sin_addr.s_addr = inet_addr ("1.2.3.4");
     
    //Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(data);
    iph->id = htonl (54321); //Id of this packet
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;      //Set to 0 before calculating checksum
    iph->saddr = inet_addr ( source_ip );    //Spoof the source ip address
    iph->daddr = sin.sin_addr.s_addr;
     
    //Ip checksum
    iph->check = csum ((unsigned short *) datagram, iph->tot_len);
     
    //TCP Header
    tcph->source = htons (1234);
    tcph->dest = htons (80);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;  //tcp header size
    tcph->fin=0;
    tcph->syn=1;
    tcph->rst=0;
    tcph->psh=0;
    tcph->ack=0;
    tcph->urg=0;
    tcph->window = htons (5840); /* maximum allowed window size */
    tcph->check = 0; //leave checksum 0 now, filled later by pseudo header
    tcph->urg_ptr = 0;
     
    /*
    //Now the TCP checksum
    psh.source_address = inet_addr( source_ip );
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data) );
     
    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
    pseudogram = malloc(psize);
     
    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) + strlen(data));
     
    tcph->check = csum( (unsigned short*) pseudogram , psize);
     */
     

    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
     
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        perror("Error setting IP_HDRINCL");
        exit(0);
    }
     
    //loop if you want to flood :)
    while (1)
    {
        //Send the packet
        if (sendto (s, datagram, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
        {
            perror("sendto failed");
        }
        //Data send successfully
        else
        {
            printf ("Packet Send. Length : %d \n" , iph->tot_len);
        }
        sleep(1);
    }
     
    return 0;
}


Device driver

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/usb.h>
 
static int pen_probe(struct usb_interface *interface, const struct usb_device_id *id)
{  
    printk(KERN_INFO "Dora..........Pen drive (%04X:%04X) plugged\n", id->idVendor, id->idProduct);
    return 0;
}
 
static void pen_disconnect(struct usb_interface *interface)
{
    printk(KERN_INFO "Dora ..........Pen drive removed\n");
}
 
static struct usb_device_id pen_table[] =
{   //USB_DEVICE(VENDOR_ID, PRODUCT_ID)
    { USB_DEVICE(0x058F, 0x6387) },
    {USB_DEVICE(0x0930, 0x6545) },
    {} /* Terminating entry */
};
MODULE_DEVICE_TABLE (usb, pen_table);
 
static struct usb_driver pen_driver =
{
    .name = "pen_driver",
    .id_table = pen_table,
    .probe = pen_probe,
    .disconnect = pen_disconnect,
};
 
static int __init pen_init(void)
{   
    return usb_register(&pen_driver);
}
 
static void __exit pen_exit(void)
{
    usb_deregister(&pen_driver);
}
 
module_init(pen_init);
module_exit(pen_exit);
 
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Devendra Dora");
MODULE_DESCRIPTION("Dora USB Driver");


Makefile


#sudo apt-get install linux-headers-3.11.0-26-generic
obj-m := usbdrive.o 
KDIR  := /lib/modules/$(shell uname -r)/build
PWD   := $(shell pwd)
default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
