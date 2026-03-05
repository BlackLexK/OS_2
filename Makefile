CXX = g++
CXXFLAGS = -Wall -Wextra -pedantic -fPIC
LDFLAGS = -ldl

LIB = libcaesar.so
EXE = test

LIB_SRC = caesar.cpp
EXE_SRC = test.cpp

.PHONY: all install runtest clean

all: $(LIB) $(EXE)

$(LIB): $(LIB_SRC)
	$(CXX) $(CXXFLAGS) -shared -o $(LIB) $(LIB_SRC)

$(EXE): $(EXE_SRC)
	$(CXX) $(CXXFLAGS) -o $(EXE) $(EXE_SRC) $(LDFLAGS)

install:
	sudo cp $(LIB) /usr/local/lib/
	sudo ldconfig

runtest: all
	echo "HelloWorld" > input.txt
	./$(EXE) ./$(LIB) A input.txt encrypted.txt
	./$(EXE) ./$(LIB) A encrypted.txt restored.txt
	diff input.txt restored.txt && echo "Test passed"

clean:
	rm -f $(LIB) $(EXE) *.txt
