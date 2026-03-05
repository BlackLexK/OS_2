// test.cpp
#include <iostream>
#include <fstream>
#include <vector>
#include <dlfcn.h>

typedef void (*set_key_func)(char);
typedef void (*caesar_func)(void*, void*, int);

int main(int argc, char* argv[])
{
    if (argc != 5)
    {
        std::cout << "Usage: ./test <lib_path> <key> <src_file> <dst_file>\n";
        return 1;
    }

    const char* lib_path = argv[1];
    char key = argv[2][0];
    const char* src_file = argv[3];
    const char* dst_file = argv[4];

    // Динамическая загрузка
    void* handle = dlopen(lib_path, RTLD_LAZY);
    if (!handle)
    {
        std::cerr << "Cannot load library\n";
        return 1;
    }

    set_key_func set_key =
        (set_key_func)dlsym(handle, "set_key");

    caesar_func caesar =
        (caesar_func)dlsym(handle, "caesar");

    if (!set_key || !caesar)
    {
        std::cerr << "Cannot load functions\n";
        dlclose(handle);
        return 1;
    }

    std::ifstream in(src_file, std::ios::binary);
    if (!in)
    {
        std::cerr << "Cannot open source file\n";
        dlclose(handle);
        return 1;
    }

    std::vector<char> buffer(
        (std::istreambuf_iterator<char>(in)),
        std::istreambuf_iterator<char>());

    in.close();

    // Шифрование на месте
    set_key(key);
    caesar(buffer.data(), buffer.data(), buffer.size());

    std::ofstream out(dst_file, std::ios::binary);
    out.write(buffer.data(), buffer.size());
    out.close();

    dlclose(handle);

    std::cout << "Done. Processed "
              << buffer.size() << " bytes.\n";

    return 0;
}
