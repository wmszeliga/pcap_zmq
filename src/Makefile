CC=gcc
CPPFLAGS=-I/opt/local/include
LDFLAGS=-L/opt/local/lib

all: pcap_zmq pcap_stdout

pcap_zmq: pcap_zmq.o
	$(CC) $(LDFLAGS) $^ -o $@ -lpcap -lzmq

pcap_stdout: pcap_stdout.o
	$(CC) $(LDFLAGS) $^ -o $@ -lpcap 

.c.o:
	$(CC) $(CPPFLAGS) -c $<

clean:
	rm *.o
