CXX = g++
CXXFLAGS = -W -Wall -O2
DEBUGFLAGS = -W -Wall -O0 -g
OBJECTS = ./mac.o ./airodump.o ./main.o
DOBJECTS = ./mac-test.o ./airodump-test.o ./main-test.o
TARGET = ../bin/airodump
DTARGET = ../bin/airodump-test
LIBS = -lpcap -pthread

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $(@) $(^) $(LIBS)

$(DTARGET): $(DOBJECTS)
	$(CXX) $(DEBUGFLAGS) -o $(@) $(^) $(LIBS)

main.o: ./main.cpp
arp-airodump.o: ./airodump.cpp
mac.o : ./mac.hpp ./mac.cpp

main-test.o: ./main.cpp
	$(CXX) -DDEBUG -c -o $(@) $(^)
airodump-test.o: ./airodump.cpp
	$(CXX) -DDEBUG -c -o $(@) $(^)
mac-test.o : ./mac.cpp
	$(CXX) -DDEBUG -c -o $(@) $(^)

clean:
	rm -f $(TARGET)
	rm -f *.o

.PHONY: all clean
