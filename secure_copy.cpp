#include <iostream>
#include <fstream>
#include <vector>
#include <queue>
#include <pthread.h>
#include <signal.h>
#include <dlfcn.h>
#include <cstring>
#include <unistd.h>

#define BLOCK_SIZE 8192
#define MAX_BLOCKS 4   // ограничение очереди

volatile sig_atomic_t keep_running = 1;

void handle_sigint(int)
{
    keep_running = 0;
}

typedef void (*set_key_func)(char);
typedef void (*caesar_func)(void*, void*, int);

// Общая очередь (но НЕ глобальная!)
struct SharedQueue {
    std::queue<std::vector<char>> queue;
    bool finished = false;

    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
};

struct ThreadArgs {
    std::ifstream* in;
    std::ofstream* out;
    set_key_func set_key;
    caesar_func caesar;
    char key;
    SharedQueue* shared;
};

void* producer(void* arg)
{
    ThreadArgs* args = (ThreadArgs*)arg;
    std::vector<char> buffer(BLOCK_SIZE);

    args->set_key(args->key);

    while (keep_running)
    {
        args->in->read(buffer.data(), BLOCK_SIZE);
        std::streamsize bytes = args->in->gcount();

        if (bytes <= 0)
            break;

        args->caesar(buffer.data(), buffer.data(), bytes);

        std::vector<char> block(buffer.begin(), buffer.begin() + bytes);

        pthread_mutex_lock(&args->shared->mutex);

        while (args->shared->queue.size() >= MAX_BLOCKS && keep_running)
            pthread_cond_wait(&args->shared->not_full,
                              &args->shared->mutex);

        args->shared->queue.push(block);

        pthread_cond_signal(&args->shared->not_empty);
        pthread_mutex_unlock(&args->shared->mutex);
    }

    pthread_mutex_lock(&args->shared->mutex);
    args->shared->finished = true;
    pthread_cond_signal(&args->shared->not_empty);
    pthread_mutex_unlock(&args->shared->mutex);

    return nullptr;
}

void* consumer(void* arg)
{
    ThreadArgs* args = (ThreadArgs*)arg;

    while (keep_running)
    {
        pthread_mutex_lock(&args->shared->mutex);

        while (args->shared->queue.empty() &&
               !args->shared->finished &&
               keep_running)
        {
            pthread_cond_wait(&args->shared->not_empty,
                              &args->shared->mutex);
        }

        if (!args->shared->queue.empty())
        {
            std::vector<char> block =
                args->shared->queue.front();

            args->shared->queue.pop();

            pthread_cond_signal(&args->shared->not_full);
            pthread_mutex_unlock(&args->shared->mutex);

            args->out->write(block.data(), block.size());
        }
        else
        {
            pthread_mutex_unlock(&args->shared->mutex);
            break;
        }
    }

    return nullptr;
}

int main(int argc, char* argv[])
{
    if (argc != 4)
    {
        std::cout << "Usage: ./secure_copy <src> <dst> <key>\n";
        return 1;
    }

    signal(SIGINT, handle_sigint);

    std::ifstream in(argv[1], std::ios::binary);
    if (!in)
    {
        std::cerr << "Source file not found\n";
        return 1;
    }

    std::ofstream out(argv[2], std::ios::binary);
    if (!out)
    {
        std::cerr << "Cannot open destination file\n";
        return 1;
    }

    void* handle = dlopen("./libcaesar.so", RTLD_LAZY);
    if (!handle)
    {
        std::cerr << "Cannot load libcaesar.so\n";
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

    SharedQueue shared;
    pthread_mutex_init(&shared.mutex, nullptr);
    pthread_cond_init(&shared.not_empty, nullptr);
    pthread_cond_init(&shared.not_full, nullptr);

    ThreadArgs args;
    args.in = &in;
    args.out = &out;
    args.set_key = set_key;
    args.caesar = caesar;
    args.key = argv[3][0];
    args.shared = &shared;

    pthread_t prod, cons;

    pthread_create(&prod, nullptr, producer, &args);
    pthread_create(&cons, nullptr, consumer, &args);

    pthread_join(prod, nullptr);
    pthread_join(cons, nullptr);

    pthread_mutex_destroy(&shared.mutex);
    pthread_cond_destroy(&shared.not_empty);
    pthread_cond_destroy(&shared.not_full);

    dlclose(handle);

    in.close();
    out.close();

    if (!keep_running)
    {
        std::cout << "Операция прервана пользователем\n";
        remove(argv[2]);  // удаляем частичный файл
    }
    else
    {
        std::cout << "Готово\n";
    }

    return 0;
}
