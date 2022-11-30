CXX = g++
CXXFLAGS = -W -Wall -O2
OBJECTS = ./mac.o ./airodump.o ./main.o
TARGET = ../bin/arp-spoof
LIBS = -lpcap -pthread

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $(@) $(^) $(LIBS)

main.o: ./main.cpp
arp-airodump.o: ./airodump.cpp
mac.o : ./mac.hpp ./mac.cpp

clean:
	rm -f $(TARGET)
	rm -f *.o

.PHONY: all clean
