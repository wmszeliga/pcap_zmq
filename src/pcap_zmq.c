#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <zmq.h>
#include <pcap.h>
#include "pcap_pipe.h"

void *responder;
long long t0 = 0;

void get_sample(const unsigned char buf[],int s,unsigned char *x) {
	int byte_offset = s/4;
	int samp_offset = 3-(s%4);
	*x = (buf[byte_offset] >> (2*samp_offset)) & 3;
}

/* Packet callback function */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	/*struct tm *ltime;
	time_t local_tv_sec;
	char timestr[16];*/
	unsigned char xi,xq;
	unsigned char buf[1920];
	long long timestamp,delta;
	int result;

	if (header->len != 1462) {
		fprintf(stderr,"Trouble Trouble Trouble: (header->len != 1462)\n");
		return;
	}
	/*
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr,sizeof(timestr),"%H:%M:%S",ltime);
	fprintf(stderr,"%s,%.6d\n",timestr,header->ts.tv_usec);*/

	/* Some timestamp foolishness */
	timestamp = ((long long)packet[14]<<56) |
		    ((long long)packet[15]<<48) |
		    ((long long)packet[16]<<40) |
		    ((long long)packet[17]<<32) |
		    ((long long)packet[18]<<24) |
		    ((long long)packet[19]<<16) |
		    ((long long)packet[20]<<8)  |
		    ((long long)packet[21]<<0);
	delta = timestamp - t0;
	if (t0 == 0) { 
		t0 = timestamp;
		return; 
	}
	if ((delta < 0) || ((delta%960) != 0)) {
		fprintf(stderr,"Trouble Trouble Trouble: (delta mod 960 != 0)\n");
		return;
	}
	if (delta != 960) {
		fprintf(stderr,"timestamp: %08llx t0: %08llx delta: %lld\n",timestamp,t0,delta);
		/* Write out some zeros */
		memset(buf,0,1920);
		while (delta > 960) {
			//write(fd_pipe,buf,1920);
			//fwrite(buf,1920,1,stdout);
			result = zmq_send(responder,buf,1920,ZMQ_DONTWAIT);
			if (result == -1) {
				fprintf(stderr,"zmq_send() error %s\n",strerror(errno));
			}
			delta -= 960;
		}
	}
        /* Write the actual data */	
	int chan = 1;
	for (int i=0;i<960;i++) {
		get_sample(&packet[22],6*i+2*(chan-1),&xi);
		get_sample(&packet[22],6*i+2*(chan-1)+1,&xq);
		xi = 2*xi - 3;
		xq = 2*xq - 3;
		buf[2*i] = xi;
		buf[2*i +1] = xq;
		//fprintf(stderr,"%d %d\n",xi,xq);
	}
	result = zmq_send(responder,buf,1920,ZMQ_DONTWAIT);
	if (result == -1) {
		fprintf(stderr,"zmq_send() error %s\n",strerror(errno));
	} 
	//write(fd_pipe,buf,1920);
	//fwrite(buf,1920,1,stdout);
	t0 = timestamp;
}


int main(int argc, char *argv[]) {
	char dev[15]; // The max interface name in the linux kernel is 15 characters
	//char dev[] = "en5";
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;		/* The compiled filter expression */
	char filter_exp[] = "ether proto 0x88b5";	/* The filter expression */
	bpf_u_int32 net;		/* The IP of our sniffing device */
	pcap_t *handle;
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */


	if (argc != 2) {
		fprintf(stderr,"%s <interface name>\n",argv[0]);
		return 1;
	}
	strncpy(dev,argv[1],15); // Copy the interface name from the command line arguments
	void *context = zmq_ctx_new();
	responder = zmq_socket(context,ZMQ_PUB);
	//int rc = zmq_bind(responder,"tcp://*:5555");
	int rc = zmq_bind(responder,"tcp://*:5555");
	if (rc != 0) {
		fprintf(stderr,"Couldn't open ZMQ socket:: %s\n",strerror(errno));
		return 1;
	}

	handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
	if (handle == NULL) {
		fprintf(stderr,"Couldn't open device %s: %s\n",dev,errbuf);
		return 2;
	}
	if (pcap_compile(handle,&fp,filter_exp,0,net) == -1) {
		fprintf(stderr,"Could not parse filter %s: %s\n",filter_exp,pcap_geterr(handle));
		return 2;
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return 2;
	}
	// -1 for continuous loop
	pcap_loop(handle,-1,&got_packet,NULL);
	//pcap_loop(handle,100000,&got_packet,NULL);
	pcap_close(handle);

	return 0;
}
