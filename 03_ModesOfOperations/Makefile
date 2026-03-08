CXX = g++
CXXFLAGS = -std=c++23 -Wall -Wextra -pedantic

TARGET = aes_modes

SRC = main.cpp \
      crypto_utils.cpp \
      aes/aes_wrapper.cpp \
      modes/ecb.cpp \
      modes/cbc.cpp \
      modes/cfb.cpp \
      modes/ofb.cpp \
      modes/ctr.cpp

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -lcrypto -o $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: clean