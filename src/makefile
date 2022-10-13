CXX = g++
CXXFLAGS = -W -Wall -O2
DEBUGFLAGS = -W -Wall -g -O0
OBJECTS = ./ip.o ./mac.o ./arphdr.o ./ethhdr.o ./arp-spoof.o ./main.o
DOBJECTS = ./ip-test.o ./mac-test.o ./arphdr-test.o ./ethhdr-test.o ./arp-spoof-test.o ./main-test.o
TARGET = ../bin/arp-spoof
DTARGET = ../bin/arp-spoof-test
LIBS = -lpcap -pthread

all: $(TARGET)
debug: $(DTARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $(@) $(^) $(LIBS)

$(DTARGET): $(DOBJECTS)
	$(CXX) $(DEBUGFLAGS) -o $(@) $(^) $(LIBS)

main.o: ./main.cpp
arp-spoof.o: ./arp-spoof.hpp ./arp-spoof.cpp
arphdr.o:  ./arphdr.hpp ./arphdr.cpp
ethhdr.o: ./ethhdr.hpp ./ethhdr.cpp
ip.o: ./ip.hpp ./ip.cpp
mac.o : ./mac.hpp ./mac.cpp

main-test.o: ./main.cpp
	$(CXX) -DDEBUG -c -o $(@) $(^)
arp-spoof-test.o: ./arp-spoof.cpp
	$(CXX) -DDEBUG -c -o $(@) $(^)
arphdr-test.o: ./arphdr.cpp
	$(CXX) -DDEBUG -c -o $(@) $(^)
ethhdr-test.o: ./ethhdr.cpp
	$(CXX) -DDEBUG -c -o $(@) $(^)
ip-test.o: ./ip.cpp
	$(CXX) -DDEBUG -c -o $(@) $(^)
mac-test.o : ./mac.cpp
	$(CXX) -DDEBUG -c -o $(@) $(^)

clean:
	rm -f $(TARGET)
	rm -f $(DTARGET)
	rm -f *.o

.PHONY: all clean

# use cmake for simpler code