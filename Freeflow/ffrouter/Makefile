# Object files
OBJ = main.o ffrouter.o rdma_api.o shared_memory.o verbs_cmd.o shmem_pool.o

# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++11 -g -O0
LDFLAGS = -lrdmacm -libverbs -lpthread -lrt

# Target
TARGET = router

# Default target
all: $(TARGET)

# Link the target
$(TARGET): $(OBJ)
	$(CXX) -o $(TARGET) $(OBJ) $(LDFLAGS)

# Compile object files
main.o: main.cpp constant.h ffrouter.h rdma_api.h shared_memory.h log.h sxq_rdma.h shmem_pool.h
	$(CXX) $(CXXFLAGS) -c main.cpp

ffrouter.o: ffrouter.cpp
	$(CXX) $(CXXFLAGS) -c ffrouter.cpp

rdma_api.o: rdma_api.cpp
	$(CXX) $(CXXFLAGS) -c rdma_api.cpp

shared_memory.o: shared_memory.cpp
	$(CXX) $(CXXFLAGS) -c shared_memory.cpp

verbs_cmd.o: verbs_cmd.cpp
	$(CXX) $(CXXFLAGS) -c verbs_cmd.cpp

shmem_pool.o: shmem_pool.cc
	$(CXX) $(CXXFLAGS) -c shmem_pool.cc

# Clean up
clean:
	rm -f $(TARGET) $(OBJ)
