#include <iostream>
#include <fstream>
#include <vector>
#include <pthread.h>
#include <dlfcn.h>
#include <ctime>
#include <sys/stat.h>
#include <unistd.h>
#include <cstdio>
#include <csignal>
#include <sys/stat.h>
#include <libgen.h>

#define BLOCK_SIZE 8192

volatile sig_atomic_t keep_running = 1;

void handle_sigint(int)
{
    keep_running = 0;
}

int file_count;
char** files;
char* output_dir;
char key;
int current_index = 0;
int copied_count = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

typedef void (*set_key_func)(char);
typedef void (*caesar_func)(void*, void*, int);

struct ThreadArgs {
    set_key_func set_key;
    caesar_func caesar;
};

void log_action(const std::string& filename, const std::string& status)
{
    pthread_mutex_lock(&mutex);

    FILE* log = fopen("log.txt", "a");
    if (log)
    {
        time_t now = time(nullptr);
        char timebuf[64];
        strftime(timebuf, sizeof(timebuf),
                 "%Y-%m-%d %H:%M:%S",
                 localtime(&now));

        pid_t pid = getpid();
        pthread_t tid = pthread_self();

        fprintf(log, "%s (%d %lu) %s %s\n",
                timebuf, pid, tid,
                filename.c_str(),
                status.c_str());

        fclose(log);
    }

    pthread_mutex_unlock(&mutex);
}

void* worker(void* arg)
{
    ThreadArgs* args = (ThreadArgs*)arg;
    args->set_key(key);

    while (keep_running)
    {
        timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 5;

        if (pthread_mutex_timedlock(&mutex, &ts) == ETIMEDOUT)
        {
            std::cout << "Deadlock warning: thread "
                      << pthread_self() << " waited >5 sec\n";
            continue;
        }

        if (current_index >= file_count)
        {
            pthread_mutex_unlock(&mutex);
            break;
        }

        int index = current_index++;
        pthread_mutex_unlock(&mutex);

        char* filename = files[index];

        struct stat st;
        if (stat(filename, &st) != 0 || S_ISDIR(st.st_mode)) {
            std::cerr << "Skipping non-file: " << filename << "\n";
            continue;
        }

        std::ifstream in(filename, std::ios::binary);
        if (!in)
        {
            log_action(filename, "ERROR");
            continue;
        }
        
        char* base = basename(filename);
        std::string out_path = std::string(output_dir) + "/" + base;
        //std::string out_path = std::string(output_dir) + "/" + basename(filename);
        std::ofstream out(out_path, std::ios::binary);
        if (!out)
        {
            log_action(filename, "ERROR");
            in.close();
            continue;
        }

        std::vector<char> buffer(BLOCK_SIZE);
        while (in)
        {
            in.read(buffer.data(), BLOCK_SIZE);
            std::streamsize bytes = in.gcount();
            if (bytes <= 0) break;

            args->caesar(buffer.data(), buffer.data(), bytes);
            out.write(buffer.data(), bytes);
        }

        in.close();
        out.close();

        log_action(filename, "SUCCESS");

        pthread_mutex_lock(&mutex);
        copied_count++;
        pthread_mutex_unlock(&mutex);
    }

    return nullptr;
}

int main(int argc, char* argv[])
{
    if (argc < 4)
    {
        std::cout << "Usage: ./secure_copy file1 [file2 ...] output_dir key\n";
        return 1;
    }

    signal(SIGINT, handle_sigint);

    key = argv[argc - 1][0];
    output_dir = argv[argc - 2];
    file_count = argc - 3;       
    files = &argv[1];

    mkdir(output_dir, 0777);

    void* handle = dlopen("./libcaesar.so", RTLD_LAZY);
    if (!handle)
    {
        std::cerr << "Cannot load libcaesar.so\n";
        return 1;
    }

    set_key_func set_key = (set_key_func)dlsym(handle, "set_key");
    caesar_func caesar = (caesar_func)dlsym(handle, "caesar");

    if (!set_key || !caesar)
    {
        std::cerr << "Cannot load functions from libcaesar.so\n";
        dlclose(handle);
        return 1;
    }

    ThreadArgs args;
    args.set_key = set_key;
    args.caesar = caesar;

    pthread_t threads[3];
    for (int i = 0; i < 3; i++)
        pthread_create(&threads[i], nullptr, worker, &args);

    for (int i = 0; i < 3; i++)
        pthread_join(threads[i], nullptr);

    dlclose(handle);

    std::cout << "All files processed. Total copied: " << copied_count << "\n";

    return 0;
}
