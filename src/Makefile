CXX = g++
CXXFLAGS = -W -Wall -O2
OBJECTS = ./ip.o ./mac.o ./arphdr.o ./ethhdr.o ./arp-spoof.o ./main.o
TARGET = ../bin/arp-spoof
LIBS = -lpcap -pthread

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $(@) $(^) $(LIBS)

main.o: ./main.cpp
arp-spoof.o: ./arp-spoof.hpp ./arp-spoof.cpp
arphdr.o:  ./arphdr.hpp ./arphdr.cpp
ethhdr.o: ./ethhdr.hpp ./ethhdr.cpp
ip.o: ./ip.hpp ./ip.cpp
mac.o : ./mac.hpp ./mac.cpp

clean:
	rm -f $(TARGET)
	rm -f *.o

.PHONY: all clean
