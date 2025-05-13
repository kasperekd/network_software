CXX = g++
COMMON_INC = ../common/src
CXXFLAGS = -std=c++11 -Wall -Wextra -pthread -I$(COMMON_INC) -I./src

LDFLAGS =

TARGET = dhcp_server
SRCS = src/server_main.cpp src/dhcp_server.cpp
OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.cpp src/dhcp_server.h $(COMMON_INC)/dhcp_common.h $(COMMON_INC)/common_config_parser.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: all clean