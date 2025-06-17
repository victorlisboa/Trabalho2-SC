CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra
LDFLAGS = -lssl -lcrypto

.PHONY: all saes aes clean

all: saes aes

# S-AES implementation
saes: main_saes.o saes.o
	$(CXX) $(CXXFLAGS) -o $@ $^

main_saes.o: main_saes.cpp saes.h
	$(CXX) $(CXXFLAGS) -c $<

saes.o: saes.cpp saes.h
	$(CXX) $(CXXFLAGS) -c $<

# AES modes implementation
aes: main_aes.o aes_modes.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

main_aes.o: main_aes.cpp aes_modes.h
	$(CXX) $(CXXFLAGS) -c $<

aes_modes.o: aes_modes.cpp aes_modes.h
	$(CXX) $(CXXFLAGS) -c $<

clean:
	rm -f *.o saes aes 