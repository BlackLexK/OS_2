#include <cstddef>
#include <cstring>

static unsigned char c_key = 0;

extern "C" {

    void set_key(char key){
        c_key = static_cast<unsigned char>(key);
    }

    void caesar(void* src, void* dst, int len){
        unsigned char* s = static_cast<unsigned char*>(src);
        unsigned char* d = static_cast<unsigned char*>(dst);

        for (int i = 0; i < len; ++i)
            d[i] = s[i] ^ c_key;
    }
}


// RC4 состояние (256 байт S-box + индексы)
struct RC4_State {
    unsigned char S[256];
    int i, j;
};

// Инициализация RC4 (Key Scheduling Algorithm)
extern "C" void rc4_init(RC4_State* state, const unsigned char* key, int keylen) {
    if (!state || !key || keylen <= 0) return;
    
    for (int k = 0; k < 256; k++) {
        state->S[k] = (unsigned char)k;
    }
    
    int j = 0;
    for (int k = 0; k < 256; k++) {
        j = (j + state->S[k] + key[k % keylen]) % 256;
        unsigned char temp = state->S[k];
        state->S[k] = state->S[j];
        state->S[j] = temp;
    }
    
    state->i = 0;
    state->j = 0;
}

// Шифрование/дешифрование (одна функция)
extern "C" void rc4_crypt(RC4_State* state, const unsigned char* src, unsigned char* dst, int len) {
    if (!state || !src || !dst || len <= 0) return;
    
    for (int k = 0; k < len; k++) {
        state->i = (state->i + 1) % 256;
        state->j = (state->j + state->S[state->i]) % 256;
        
        unsigned char temp = state->S[state->i];
        state->S[state->i] = state->S[state->j];
        state->S[state->j] = temp;
        
        unsigned char keystream = state->S[(state->S[state->i] + state->S[state->j]) % 256];
        dst[k] = src[k] ^ keystream;
    }
}

// Затирание состояния (безопасность)
extern "C" void rc4_cleanup(RC4_State* state) {
    if (state) {
        memset(state, 0, sizeof(RC4_State));
    }
}
