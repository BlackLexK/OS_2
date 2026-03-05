#include <cstddef>

static unsigned char c_key = 0;

extern "C" {

void set_key(char key)
{
    c_key = static_cast<unsigned char>(key);
}

void caesar(void* src, void* dst, int len)
{
    unsigned char* s = static_cast<unsigned char*>(src);
    unsigned char* d = static_cast<unsigned char*>(dst);

    for (int i = 0; i < len; ++i)
        d[i] = s[i] ^ c_key;
}

}
