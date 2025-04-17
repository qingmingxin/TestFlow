# Makefile for compiling server.cc

# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -libverbs -g -O0

# Libraries
LIBS = -libverbs -lrt

# Executable name
TARGET = test

# Source files
# SRCS = rdma_sxq.cc log.cc
SRCS = test.cc log.cc

# Object files
OBJS = $(SRCS:.cc=.o)

# Default rule
all: $(TARGET)

# Compile
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS)

# Clean
clean:
	rm -f $(TARGET) $(OBJS)