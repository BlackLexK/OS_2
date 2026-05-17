CC = g++
CFLAGS = -Wall -Wextra -pedantic -pthread

all: libcaesar.so secure_copy

# Сборка динамической библиотеки
libcaesar.so: caesar.cpp
	$(CC) -shared -fPIC -o $@ $^

# Сборка основной программы
secure_copy: secure_copy.cpp
	$(CC) $(CFLAGS) -o $@ $^ -ldl

# Установка библиотеки
install:
	sudo cp libcaesar.so /usr/local/lib/
	sudo ldconfig

# Тест
test: all
	@echo "=== Test ==="
	./secure_copy test_files/file1.txt test_files/file2.txt test_files/file3.txt output_test 42

clean:
	rm -f libcaesar.so secure_copy *.o *.txt
	rm -rf output_* output_test

.PHONY: all clean install test
