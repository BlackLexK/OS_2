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
#include <libgen.h>
#include <iomanip>

#define BLOCK_SIZE 8192
#define MAX_WORKERS 4

enum Mode { AUTO, SEQUENTIAL, PARALLEL };
Mode current_mode = AUTO;

volatile sig_atomic_t keep_running = 1;

void handle_sigint(int) { keep_running = 0; }

// Глобальные переменные
int file_count = 0;
char** files = nullptr;
char* output_dir = nullptr;
char key = 0;
int current_index = 0;
int copied_count = 0;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef void (*set_key_func)(char);
typedef void (*caesar_func)(void*, void*, int);

struct ThreadArgs {
    set_key_func set_key;
    caesar_func caesar;
};

struct FileStats {
    std::string filename;
    double time_ms;
};
std::vector<FileStats> all_stats;

void log_action(const std::string& filename, const std::string& status) {
    pthread_mutex_lock(&mutex);
    FILE* log = fopen("log.txt", "a");
    if (log) {
        time_t now = time(nullptr);
        char timebuf[64];
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", localtime(&now));
        fprintf(log, "%s (%d %lu) %s %s\n", timebuf, getpid(), (unsigned long)pthread_self(), filename.c_str(), status.c_str());
        fclose(log);
    }
    pthread_mutex_unlock(&mutex);
}

double process_file(const char* filename, const char* out_dir, set_key_func set_key, caesar_func caesar_func, char key_char) {
    if (std::string(filename).rfind("--mode=", 0) == 0) {
        std::cout << "Skipping non-file: " << filename << std::endl;
        return 0.0;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    set_key(key_char);

    struct stat st;
    if (stat(filename, &st) != 0 || S_ISDIR(st.st_mode)) {
        std::cerr << "Skipping: " << filename << std::endl;
        return 0.0;
    }

    std::string base = basename(const_cast<char*>(filename));
    std::string out_path = std::string(out_dir) + "/" + base;

    std::ifstream in(filename, std::ios::binary);
    std::ofstream out(out_path, std::ios::binary);
    if (!in || !out) {
        log_action(filename, "ERROR");
        return 0.0;
    }

    std::vector<char> buffer(BLOCK_SIZE);
    while (in) {
        in.read(buffer.data(), BLOCK_SIZE);
        std::streamsize bytes = in.gcount();
        if (bytes <= 0) break;
        caesar_func(buffer.data(), buffer.data(), static_cast<int>(bytes));
        out.write(buffer.data(), bytes);
    }

    in.close();
    out.close();
    log_action(filename, "SUCCESS");

    clock_gettime(CLOCK_MONOTONIC, &end);
    double time_ms = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1000000.0;

    pthread_mutex_lock(&stats_mutex);
    all_stats.push_back({filename, time_ms});
    pthread_mutex_unlock(&stats_mutex);

    return time_ms;
}

void* parallel_worker(void* arg) {
    ThreadArgs* args = (ThreadArgs*)arg;
    while (keep_running) {
        pthread_mutex_lock(&mutex);
        if (current_index >= file_count) {
            pthread_mutex_unlock(&mutex);
            break;
        }
        int index = current_index++;
        pthread_mutex_unlock(&mutex);

        double t = process_file(files[index], output_dir, args->set_key, args->caesar, key);
        if (t > 0) {
            pthread_mutex_lock(&mutex);
            copied_count++;
            pthread_mutex_unlock(&mutex);
        }
    }
    return nullptr;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage:\n"
                  << "  ./secure_copy [--mode=sequential|parallel] file1 [file2 ...] output_dir key\n";
        return 1;
    }

    signal(SIGINT, handle_sigint);

    int files_start = 1;
    current_mode = AUTO;

    if (argc > 1 && std::string(argv[1]).rfind("--mode=", 0) == 0) {
        std::string m = argv[1];
        if (m == "--mode=sequential") current_mode = SEQUENTIAL;
        else if (m == "--mode=parallel") current_mode = PARALLEL;
        else {
            std::cerr << "Unknown mode!\n";
            return 1;
        }
        files_start = 2;
    }

    key = argv[argc-1][0];
    output_dir = argv[argc-2];
    file_count = argc - files_start - 2;

    if (file_count < 1) {
        std::cerr << "Error: No input files\n";
        return 1;
    }

    files = &argv[files_start];

    std::cout << "Mode: " << (current_mode == SEQUENTIAL ? "SEQUENTIAL" : current_mode == PARALLEL ? "PARALLEL" : "AUTO") 
              << " | Files: " << file_count << std::endl;

    mkdir(output_dir, 0777);

    void* handle = dlopen("./libcaesar.so", RTLD_LAZY);
    if (!handle) { std::cerr << "dlopen failed\n"; return 1; }

    auto set_key = (set_key_func)dlsym(handle, "set_key");
    auto caesar_f = (caesar_func)dlsym(handle, "caesar");

    if (!set_key || !caesar_f) {
        std::cerr << "dlsym failed\n";
        dlclose(handle);
        return 1;
    }

    ThreadArgs args = {set_key, caesar_f};

    struct timespec total_start, total_end;
    clock_gettime(CLOCK_MONOTONIC, &total_start);

    current_index = 0;
    copied_count = 0;

    if (current_mode == SEQUENTIAL || (current_mode == AUTO && file_count < 5)) {
        std::cout << "[SEQUENTIAL MODE]\n";
        for (int i = 0; i < file_count && keep_running; ++i) {
            process_file(files[i], output_dir, set_key, caesar_f, key);
            copied_count++;
        }
    } else {
        std::cout << "[PARALLEL MODE] " << MAX_WORKERS << " threads\n";
        pthread_t threads[MAX_WORKERS];
        for (int i = 0; i < MAX_WORKERS; ++i)
            pthread_create(&threads[i], nullptr, parallel_worker, &args);
        for (int i = 0; i < MAX_WORKERS; ++i)
            pthread_join(threads[i], nullptr);
    }

    clock_gettime(CLOCK_MONOTONIC, &total_end);
    double total_time = (total_end.tv_sec - total_start.tv_sec)*1000.0 + (total_end.tv_nsec - total_start.tv_nsec)/1000000.0;

    // Статистика
    std::cout << "\n=== STATISTICS ===\n";
    
    std::string mode_str;
    if (current_mode == SEQUENTIAL) mode_str = "SEQUENTIAL";
    else if (current_mode == PARALLEL) mode_str = "PARALLEL";
    else mode_str = "AUTO (SEQUENTIAL)";

    std::cout << "Mode: " << mode_str << "\n";
    std::cout << "Files processed: " << copied_count << " / " << file_count << "\n";
    std::cout << "Total time: " << std::fixed << std::setprecision(2) << total_time << " ms\n";
    if (copied_count > 0)
        std::cout << "Avg time per file: " << (total_time / copied_count) << " ms\n";

    dlclose(handle);
    return 0;
}
