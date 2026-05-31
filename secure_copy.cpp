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
#include <dirent.h>
#include <sys/types.h>
#include <random>
#include <string>
#include <filesystem>
#include <thread>
#include <mutex>
#include <algorithm>

#define BLOCK_SIZE 8192
#define MAX_WORKERS 5
#define CHUNK_SIZE (64 * 1024)   // 64 КБ — размер чанка для шифрования по кусочкам

// Прототипы функций для защищённой памяти
bool init_secure_key();
bool set_secure_key(char key_char);
char get_secure_key();
void cleanup_secure_key();

//прототипы для 6
void collect_files(const std::string& path, const std::string& base_dir, std::vector<std::pair<std::string,std::string>>& files);

void add_file_to_image(std::ofstream& img, const std::string& real_path, const std::string& stored_name, const std::string& master_key);
void handle_add(int argc, char* argv[]);
void handle_list(const std::string& image_path);
void handle_get(int argc, char* argv[]);
int handle_secure_container_mode(int argc, char* argv[]);

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

// Инициализация защищённой памяти под ключэ
//Выделяет 16 байт анонимной памяти с правами чтения+записи.
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
//Временно снимает защиту, записывает ключ, снова ставит только чтение.
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
//Временно снимает защиту, читает ключ, снова защищает.
char get_secure_key() {
    if (!secure_key_mem) return 0;

    mprotect(secure_key_mem, KEY_SIZE, PROT_READ | PROT_WRITE);
    char k = ((char*)secure_key_mem)[0];
    mprotect(secure_key_mem, KEY_SIZE, PROT_READ);
    return k;
}

// Очистка защищённой памяти
//Затирает ключ нулями и освобождает память.
void cleanup_secure_key() {
    if (secure_key_mem) {
        mprotect(secure_key_mem, KEY_SIZE, PROT_READ | PROT_WRITE);
        memset(secure_key_mem, 0, KEY_SIZE);
        munmap(secure_key_mem, KEY_SIZE);
        secure_key_mem = nullptr;
    }
}

// Теперь обработчик может использовать cleanup_secure_key()
//Обработчик ошибки сегментации. Если кто-то попробует записать в защищённую память — программа красиво завершится.
void segfault_handler(int /*sig*/, siginfo_t* info, void* /*ucontext*/) {
    std::cerr << "\n[SECURITY ERROR] Segmentation fault! Attempted write to protected key memory.\n";
    std::cerr << "Address: " << info->si_addr << std::endl;
    cleanup_secure_key();
    exit(2);
}



//  ЗАЩИЩЁННОЕ СОСТОЯНИЕ RC4 (S-box) 
struct RC4_State {
    unsigned char S[256];
    int i, j;
};

// Выделение защищённой памяти под состояние RC4
RC4_State* create_secure_rc4_state() {
    RC4_State* state = (RC4_State*)mmap(NULL, sizeof(RC4_State),
                                        PROT_READ | PROT_WRITE,
                                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (state == MAP_FAILED) {
        std::cerr << "mmap для RC4_State failed\n";
        return nullptr;
    }
    return state;
}

// Перевод S-box в режим "только чтение"
bool protect_rc4_state(RC4_State* state) {
    if (!state) return false;
    return mprotect(state, sizeof(RC4_State), PROT_READ) == 0;
}

// Временное разрешение записи (для шифрования)
bool unprotect_rc4_state(RC4_State* state) {
    if (!state) return false;
    return mprotect(state, sizeof(RC4_State), PROT_READ | PROT_WRITE) == 0;
}

// Очистка и освобождение памяти
void destroy_secure_rc4_state(RC4_State* state) {
    if (state) {
        unprotect_rc4_state(state);        // сначала разрешаем запись
        memset(state, 0, sizeof(RC4_State)); // затираем
        munmap(state, sizeof(RC4_State));   // освобождаем
    }
}






typedef void (*set_key_func)(char);
typedef void (*caesar_func)(void*, void*, int);

typedef void (*rc4_init_func)(void*, const unsigned char*, int);
typedef void (*rc4_crypt_func)(void*, const unsigned char*, unsigned char*, int);
typedef void (*rc4_cleanup_func)(void*);




// Глобальные переменные
int file_count = 0;
char** files = nullptr;
char* output_dir = nullptr;
char key = 0;
int current_index = 0;
int copied_count = 0;

//volatile int keep_running = 1;
void* lib_handle = nullptr;
set_key_func p_set_key = nullptr;
caesar_func p_caesar = nullptr;
std::mutex image_mutex;

// RC4 указатели
rc4_init_func p_rc4_init = nullptr;
rc4_crypt_func p_rc4_crypt = nullptr;
rc4_cleanup_func p_rc4_cleanup = nullptr;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;





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
    if (argc < 2) {
        std::cout << "Использование:\n"
                  << "  Старый режим: ./secure_copy [files...] output_dir key\n"
                  << "  Новый режим (задание 6):\n"
                  << "    ./secure_copy -add -key \"secret\" -image disk.img file1 dir1/\n"
                  << "    ./secure_copy -list -image disk.img\n"
                  << "    ./secure_copy -get -key \"secret\" -image disk.img -out out.txt file_name\n";
        return 1;
    }

    std::string first_arg = argv[1];
    if (first_arg == "-add" || first_arg == "-list" || first_arg == "-get") {
        return handle_secure_container_mode(argc, argv);  
    }
    
    //old
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








// Рекурсивный сбор файлов
void collect_files(const std::string& path,
                   const std::string& base_dir,
                   std::vector<std::pair<std::string,std::string>>& files)
{
    namespace fs = std::filesystem;
    try {
        if (fs::is_regular_file(path)) {
            std::string relative;

            // ← ИСПРАВЛЕНИЕ: специальная обработка одиночного файла
            if (fs::equivalent(path, base_dir) || path == base_dir) {
                // Если добавляется один файл — берём только его имя
                relative = fs::path(path).filename().string();
            } else {
                // Если файл внутри директории — вычисляем относительный путь
                relative = fs::relative(path, base_dir).string();
            }

            files.emplace_back(path, relative);
            return;
        }

        // Если это директория — рекурсивно обходим
        if (fs::is_directory(path)) {
            for (const auto& entry : fs::recursive_directory_iterator(path)) {
                if (entry.is_regular_file()) {
                    std::string relative = fs::relative(entry.path(), base_dir).string();
                    files.emplace_back(entry.path().string(), relative);
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Ошибка обхода " << path << ": " << e.what() << std::endl;
    }
}





// Запись одного файла в образ (с защитой S-box и по кусочкам)
void add_file_to_image(std::ofstream& img, 
                       const std::string& real_path, 
                       const std::string& stored_name,
                       const std::string& master_key) {
    std::ifstream file(real_path, std::ios::binary);
    if (!file) {
        std::cerr << "Ошибка открытия файла: " << real_path << std::endl;
        return;
    }

    // Генерация соли
    unsigned char salt[16] = {0};
    std::random_device rd;
    for (int i = 0; i < 16; i++) {
        salt[i] = rd() % 256;
    }

    // Полный ключ = master_key + salt
    std::string full_key = master_key;
    full_key.append(reinterpret_cast<char*>(salt), 16);

    // Создаём защищённое состояние RC4
    RC4_State* state = create_secure_rc4_state();
    if (!state) return;

    unprotect_rc4_state(state);                    // разрешаем запись
    p_rc4_init(state, (const unsigned char*)full_key.data(), full_key.size());
    protect_rc4_state(state);                      // снова защищаем

    // Записываем заголовок
    file.seekg(0, std::ios::end);
    uint32_t len_data = static_cast<uint32_t>(file.tellg());
    file.seekg(0, std::ios::beg);

    uint32_t len_name = static_cast<uint32_t>(stored_name.length());

    img.write(reinterpret_cast<char*>(&len_data), 4);
    img.write(reinterpret_cast<char*>(&len_name), 4);
    img.write(reinterpret_cast<char*>(salt), 16);
    img.write(stored_name.c_str(), len_name);

    // Шифрование ПО КУСОЧКАМ
    std::vector<unsigned char> buffer(CHUNK_SIZE);
    while (true) {
        file.read(reinterpret_cast<char*>(buffer.data()), CHUNK_SIZE);
        size_t bytes_read = file.gcount();
        if (bytes_read == 0) break;

        unprotect_rc4_state(state);
        p_rc4_crypt(state, buffer.data(), buffer.data(), static_cast<int>(bytes_read));
        protect_rc4_state(state);

        img.write(reinterpret_cast<char*>(buffer.data()), bytes_read);
    }

    destroy_secure_rc4_state(state);   // очистка + munmap

    std::cout << "Добавлен файл: " << stored_name << " (" << len_data << " байт)" << std::endl;
}


// Поточная функция
void threaded_add(
    const std::string& image_path,
    const std::string& real_path,
    const std::string& stored_name,
    const std::string& key)
{
    std::lock_guard<std::mutex> lock(image_mutex);

    // Открываем файл с флагом app И create (чтобы создавался, если не существует)
    std::ofstream img(image_path, std::ios::binary | std::ios::app | std::ios::out);
    
    if (!img) {
        std::cerr << "Ошибка открытия/создания образа: " << image_path << std::endl;
        return;
    }

    add_file_to_image(img, real_path, stored_name, key);
}





// Обработка -add
void handle_add(int argc, char* argv[]) {

    std::string key;
    std::string image_path;
    std::vector<std::string> input_paths;

    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-key" && i + 1 < argc) {
            key = argv[++i];
        }
        else if (arg == "-image" && i + 1 < argc) {
            image_path = argv[++i];
        }
        else {
            input_paths.push_back(arg);
        }
    }

    if (key.empty() || image_path.empty() || input_paths.empty()) {
        std::cerr << "Недостаточно параметров\n";
        return;
    }

    // Важно: создаём файл, если его нет
    {
        std::ofstream test(image_path, std::ios::app);
        if (!test) {
            std::cerr << "Не удалось создать файл образа: " << image_path << std::endl;
            return;
        }
    }

    std::vector<std::pair<std::string,std::string>> all_files;

    for (const auto& p : input_paths) {
        collect_files(p, p, all_files);
    }

    if (all_files.empty()) {
        std::cout << "Не найдено файлов для добавления\n";
        return;
    }

    std::vector<std::thread> threads;
    for (const auto& f : all_files) {
        threads.emplace_back(threaded_add, image_path, f.first, f.second, key);

        if (threads.size() >= MAX_WORKERS) {
            for (auto& t : threads) t.join();
            threads.clear();
        }
    }

    for (auto& t : threads) t.join();

    std::cout << "Добавлено файлов: " << all_files.size() << std::endl;
}



// -list
void handle_list(const std::string& image_path) {
    std::ifstream img(image_path, std::ios::binary);

    if (!img) {
        std::cerr << "Не удалось открыть образ\n";
        return;
    }

    std::vector<std::pair<std::string, uint32_t>> files;

    while (true) {
        uint32_t len_data = 0;
        uint32_t len_name = 0;

        if (!img.read(reinterpret_cast<char*>(&len_data), 4))
            break;

        if (!img.read(reinterpret_cast<char*>(&len_name), 4))
            break;

        // Проверка повреждённого контейнера
        if (len_name > 4096 || len_data > 1024 * 1024 * 1024) {
            std::cerr << "Повреждённый контейнер\n";
            return;
        }

        unsigned char salt[16];
        img.read(reinterpret_cast<char*>(salt), 16);

        std::string name(len_name, '\0');
        img.read(name.data(), len_name);
        if (!img) {
            std::cerr << "Ошибка чтения образа\n";
            return;
        }

        img.seekg(len_data, std::ios::cur);

        files.push_back({name, len_data});
    }

    std::sort(files.begin(), files.end());

    for (const auto& f : files) {
        std::cout << f.first
                  << " (" << f.second << " байт)\n";
    }
}



// -get
void handle_get(int argc, char* argv[]) {
    std::string key, image_path, out_file, target_name;
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-key" && i+1 < argc) key = argv[++i];
        else if (arg == "-image" && i+1 < argc) image_path = argv[++i];
        else if (arg == "-out" && i+1 < argc) out_file = argv[++i];
        else if (target_name.empty()) target_name = argv[i];
    }

    if (key.empty() || image_path.empty() || out_file.empty() || target_name.empty()) {
        std::cerr << "Ошибка параметров -get\n";
        return;
    }

    std::ifstream img(image_path, std::ios::binary);
    if (!img) {
        std::cerr << "Не удалось открыть образ\n";
        return;
    }

    bool found = false;
    while (true) {
        uint32_t len_data = 0, len_name = 0;
        if (!img.read(reinterpret_cast<char*>(&len_data), 4)) break;
        img.read(reinterpret_cast<char*>(&len_name), 4);

        unsigned char salt[16];
        img.read(reinterpret_cast<char*>(salt), 16);

        std::string name(len_name, '\0');
        img.read(name.data(), len_name);

        if (name == target_name) {
            found = true;

            std::string full_key = key;
            full_key.append(reinterpret_cast<char*>(salt), 16);

            RC4_State* state = create_secure_rc4_state();
            if (!state) {
                std::cerr << "Не удалось создать состояние RC4\n";
                break;
            }

            unprotect_rc4_state(state);
            p_rc4_init(state, (const unsigned char*)full_key.data(), full_key.size());
            protect_rc4_state(state);

            std::ofstream out(out_file, std::ios::binary);
            if (!out) {
                std::cerr << "Ошибка создания выходного файла\n";
                destroy_secure_rc4_state(state);
                break;
            }

            std::vector<unsigned char> buffer(CHUNK_SIZE);
            uint32_t remaining = len_data;

            while (remaining > 0) {
                size_t to_read = std::min(static_cast<size_t>(CHUNK_SIZE), 
                                         static_cast<size_t>(remaining));
                
                img.read(reinterpret_cast<char*>(buffer.data()), to_read);
                size_t bytes_read = img.gcount();

                if (bytes_read == 0) break;

                unprotect_rc4_state(state);
                p_rc4_crypt(state, buffer.data(), buffer.data(), static_cast<int>(bytes_read));
                protect_rc4_state(state);

                out.write(reinterpret_cast<char*>(buffer.data()), bytes_read);
                remaining -= bytes_read;
            }

            destroy_secure_rc4_state(state);
            std::cout << "Файл успешно извлечён: " << out_file 
                      << " (" << len_data << " байт)\n";
            break;
        } 
        else {
            img.seekg(len_data, std::ios::cur);
        }
    }

    if (!found) {
        std::cerr << "Файл '" << target_name << "' не найден.\n";
    }
}


// Главная новая функция
int handle_secure_container_mode(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Недостаточно аргументов\n";
        return 1;
    }

    lib_handle = dlopen("./libcaesar.so", RTLD_LAZY);
    if (!lib_handle) {
        std::cerr << "dlopen failed: " << dlerror() << std::endl;
        return 1;
    }

    p_rc4_init = (rc4_init_func)dlsym(lib_handle, "rc4_init");
    p_rc4_crypt = (rc4_crypt_func)dlsym(lib_handle, "rc4_crypt");
    p_rc4_cleanup = (rc4_cleanup_func)dlsym(lib_handle, "rc4_cleanup");

    if (!p_rc4_init || !p_rc4_crypt || !p_rc4_cleanup) {
        std::cerr << "dlsym RC4 failed\n";
        dlclose(lib_handle);
        return 1;
    }

    std::string mode = argv[1];

    if (mode == "-add") {
        handle_add(argc, argv);
    } 
    else if (mode == "-list") {
        if (argc > 3) handle_list(argv[3]);  // -image ...
        else std::cerr << "Укажите -image\n";
    } 
    else if (mode == "-get") {
        handle_get(argc, argv);
    }

    if (lib_handle) dlclose(lib_handle);
    return 0;
}



