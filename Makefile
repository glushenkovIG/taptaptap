SOURCES := $(wildcard *.cpp)

CXXFLAGS := -std=c++14 -Wpedantic -pedantic -fno-strict-aliasing -O2 -Wall -Wextra -Wno-unused-function -Wno-stringop-truncation
CPPFLAGS := -D_GNU_SOURCE

main: $(SOURCES)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(SOURCES) -o main
