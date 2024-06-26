CC=gcc
CPPFLAGS=-I/opt/local/include
LDFLAGS=-L/opt/local/lib

all: pcap_zmq 

pcap_zmq: pcap_zmq.o
	$(CC) $(LDFLAGS) $^ -o $@ -lpcap -lzmq

.c.o:
	$(CC) $(CPPFLAGS) -c $<
