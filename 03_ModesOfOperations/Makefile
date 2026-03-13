CXX = g++
CXXFLAGS = -std=c++23 -Wall -Wextra -pedantic -Wno-deprecated-declarations

TARGET = aes_modes

SRC = main.cpp \
      crypto_utils.cpp \
      aes/aes_wrapper.cpp \
      modes/ecb.cpp \
      modes/cbc.cpp \
      modes/cfb.cpp \
      modes/ofb.cpp \
      modes/ctr.cpp

OBJ = $(SRC:.cpp=.o)

$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) $(OBJ) -lcrypto -o $(TARGET)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: clean