#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pcap.h>
#include "pcap_pipe.h"

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
			fwrite(buf,1920,1,stdout);
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
	fwrite(buf,1920,1,stdout);
	t0 = timestamp;
}

int main(int argc, char *argv[]) {
	char dev[15]; // The max interface name in the linux kernel is 15 characters
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;		/* The compiled filter expression */
	char filter_exp[] = "ether proto 0x88b5";	/* The filter expression */
	bpf_u_int32 net;		/* The IP of our sniffing device */
	pcap_t *handle;
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	struct pcap_stat stats;
	long long counter = 0;

	if (argc != 2) {
		fprintf(stderr,"%s <interface name>\n",argv[0]);
		return 1;
	}
	strncpy(dev,argv[1],15); // Copy the interface name from the command line arguments

	handle = pcap_create(dev,errbuf);
	// Need to set the buffer size before the we activate the handle
	int buffer_size = 50*1024*1024; // 50 Mb
	if (pcap_set_buffer_size(handle,buffer_size) != 0) {
		fprintf(stderr, "Couldn't set buffer size %d: %s\n", buffer_size, pcap_geterr(handle));
		return 2;
	}
	int snaplen = 65536;
	if (pcap_set_promisc(handle,1) != 0) {
		fprintf(stderr,"Could not set promiscuous mode%s\n",pcap_geterr(handle));
		return 2;
	}
	if (pcap_set_snaplen(handle,snaplen) != 0) {
		fprintf(stderr,"Could not set snapshot length%s\n",pcap_geterr(handle));
		return 2;
	}
	fprintf(stderr,"SnapLen size set to %d\n",snaplen);
	if (pcap_set_timeout(handle,1000) != 0) {
		fprintf(stderr,"Could not set timeout%s\n",pcap_geterr(handle));
		return 2;
	}
	if (pcap_activate(handle) != 0) {
		fprintf(stderr,"Could not activate handle %s\n",pcap_geterr(handle));
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

	while (1) {
		pcap_next_ex(handle,&header,&packet);
		got_packet(NULL,header,packet);
		/*if (counter % 1000000) {
			if (pcap_stats(handle,&stats) >= 0) {
				printf("%d packets received\n",stats.ps_recv);
				printf("%d packets dropped due to buffer size\n",stats.ps_drop);
				printf("%d packets dropped due to network interface\n",stats.ps_ifdrop);
			}
		}
		counter++;*/
	}
	pcap_close(handle);

	return 0;
}
