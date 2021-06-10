include /usr/local/etc/PcapPlusPlus.mk

COMPILER_FLAGS = -std=c++17 -O3 -Wall

all: pcap-formatter

clean:
	rm -f pcap-formatter pcap-formatter.o

pcap-formatter: pcap-formatter.o
	g++ $(PCAPPP_LIBS_DIR) $(COMPILER_FLAGS) -o pcap-formatter pcap-formatter.o $(PCAPPP_LIBS)

pcap-formatter.o: pcap-formatter.cpp
	g++ $(PCAPPP_INCLUDES) $(COMPILER_FLAGS) -c -o pcap-formatter.o pcap-formatter.cpp
