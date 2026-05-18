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
#include <sys/mman.h>
#include <errno.h>
#include <cstring>

#define BLOCK_SIZE 8192
#define MAX_WORKERS 4

// Прототипы функций для защищённой памяти
bool init_secure_key();
bool set_secure_key(char key_char);
char get_secure_key();
void cleanup_secure_key();


// Режимы работы
enum Mode { AUTO, SEQUENTIAL, PARALLEL };
Mode current_mode = AUTO;

volatile sig_atomic_t keep_running = 1;

void handle_sigint(int) {
    keep_running = 0;
}

// Защищённая память для ключа
void* secure_key_mem = nullptr;
const size_t KEY_SIZE = 16;

// Инициализация защищённой памяти под ключ
bool init_secure_key() {
    secure_key_mem = mmap(NULL, KEY_SIZE, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (secure_key_mem == MAP_FAILED) {
        std::cerr << "mmap failed: " << strerror(errno) << std::endl;
        return false;
    }
    return true;
}

// Установка ключа в защищённую память
bool set_secure_key(char key_char) {
    if (!secure_key_mem) return false;

    if (mprotect(secure_key_mem, KEY_SIZE, PROT_READ | PROT_WRITE) != 0) {
        std::cerr << "mprotect (RW) failed\n";
        return false;
    }

    memcpy(secure_key_mem, &key_char, 1);

    if (mprotect(secure_key_mem, KEY_SIZE, PROT_READ) != 0) {
        std::cerr << "mprotect (RO) failed\n";
        return false;
    }
    return true;
}

// Получение копии ключа для использования
char get_secure_key() {
    if (!secure_key_mem) return 0;

    mprotect(secure_key_mem, KEY_SIZE, PROT_READ | PROT_WRITE);
    char k = ((char*)secure_key_mem)[0];
    mprotect(secure_key_mem, KEY_SIZE, PROT_READ);
    return k;
}

// Очистка защищённой памяти
void cleanup_secure_key() {
    if (secure_key_mem) {
        mprotect(secure_key_mem, KEY_SIZE, PROT_READ | PROT_WRITE);
        memset(secure_key_mem, 0, KEY_SIZE);
        munmap(secure_key_mem, KEY_SIZE);
        secure_key_mem = nullptr;
    }
}

// Теперь обработчик может использовать cleanup_secure_key()
void segfault_handler(int /*sig*/, siginfo_t* info, void* /*ucontext*/) {
    std::cerr << "\n[SECURITY ERROR] Segmentation fault! Attempted write to protected key memory.\n";
    std::cerr << "Address: " << info->si_addr << std::endl;
    cleanup_secure_key();
    exit(2);
}



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

// Логирование
void log_action(const std::string& filename, const std::string& status) {
    pthread_mutex_lock(&mutex);
    FILE* log = fopen("log.txt", "a");
    if (log) {
        time_t now = time(nullptr);
        char timebuf[64];
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", localtime(&now));
        fprintf(log, "%s (%d %lu) %s %s\n",
                timebuf, getpid(), (unsigned long)pthread_self(),
                filename.c_str(), status.c_str());
        fclose(log);
    }
    pthread_mutex_unlock(&mutex);
}

// Обработка одного файла
double process_file(const char* filename, const char* out_dir,
                   set_key_func set_key, caesar_func caesar_func, char /*key_char*/) {
    
    if (std::string(filename).rfind("--mode=", 0) == 0) {
        std::cout << "Skipping non-file: " << filename << std::endl;
        return 0.0;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    set_key(get_secure_key());   // используем защищённый ключ

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
    double time_ms = (end.tv_sec - start.tv_sec) * 1000.0 +
                     (end.tv_nsec - start.tv_nsec) / 1000000.0;

    pthread_mutex_lock(&stats_mutex);
    all_stats.push_back({filename, time_ms});
    pthread_mutex_unlock(&stats_mutex);

    return time_ms;
}

// Рабочий поток
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
                  << " ./secure_copy [--mode=sequential|parallel] file1 [file2 ...] output_dir key\n";
        return 1;
    }

    signal(SIGINT, handle_sigint);

    // Установка обработчика SIGSEGV
    struct sigaction sa = {};
    sa.sa_sigaction = segfault_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);

    int files_start = 1;
    current_mode = AUTO;

    // Парсинг режима
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

    std::cout << "Mode: "
              << (current_mode == SEQUENTIAL ? "SEQUENTIAL" :
                 (current_mode == PARALLEL ? "PARALLEL" : "AUTO"))
              << " | Files: " << file_count << std::endl;

    mkdir(output_dir, 0777);

    // Загрузка библиотеки
    void* handle = dlopen("./libcaesar.so", RTLD_LAZY);
    if (!handle) {
        std::cerr << "dlopen failed\n";
        return 1;
    }

    auto set_key = (set_key_func)dlsym(handle, "set_key");
    auto caesar_f = (caesar_func)dlsym(handle, "caesar");

    if (!set_key || !caesar_f) {
        std::cerr << "dlsym failed\n";
        dlclose(handle);
        return 1;
    }

    ThreadArgs args = {set_key, caesar_f};

    // Инициализация защищённого ключа
    if (!init_secure_key() || !set_secure_key(key)) {
        std::cerr << "Failed to initialize secure key\n";
        dlclose(handle);
        return 1;
    }
    key = 0;
    //((char*)secure_key_mem)[0] = 'X';

    struct timespec total_start, total_end;
    clock_gettime(CLOCK_MONOTONIC, &total_start);

    current_index = 0;
    copied_count = 0;

    // Выбор режима
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
    double total_time = (total_end.tv_sec - total_start.tv_sec)*1000.0 +
                        (total_end.tv_nsec - total_start.tv_nsec)/1000000.0;

    // Статистика
    std::cout << "\n=== STATISTICS ===\n";
 
    std::string mode_str;
    if (current_mode == SEQUENTIAL)
        mode_str = "SEQUENTIAL";
    else if (current_mode == PARALLEL)
        mode_str = "PARALLEL";
    else
        mode_str = (file_count < 5 ? "AUTO (SEQUENTIAL)" : "AUTO (PARALLEL)");

    std::cout << "Mode: " << mode_str << "\n";
    std::cout << "Files processed: " << copied_count << " / " << file_count << "\n";
    std::cout << "Total time: " << std::fixed << std::setprecision(2) << total_time << " ms\n";
    if (copied_count > 0)
        std::cout << "Avg time per file: " << (total_time / copied_count) << " ms\n";

    // Очистка защищённой памяти
    cleanup_secure_key();
    dlclose(handle);
    return 0;
}
