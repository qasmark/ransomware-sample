#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <unistd.h>

#define SALT_FILE "salt.salt"
#define BUFFER_SIZE 1024

unsigned char *generate_salt(int size) {
    unsigned char *salt = (unsigned char *)malloc(size);
    if (RAND_bytes(salt, size) != 1) {
        fprintf(stderr, "Ошибка при генерации соли\n");
        ERR_print_errors_fp(stderr);
        free(salt);
        return NULL;
    }
    return salt;
}

unsigned char *load_salt(int *salt_size) {
    FILE *file = fopen(SALT_FILE, "rb");
    if (file == NULL) {
        fprintf(stderr, "Ошибка при открытии файла соли\n");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    *salt_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *salt = (unsigned char *)malloc(*salt_size);
    if (fread(salt, 1, *salt_size, file) != *salt_size) {
        fprintf(stderr, "Ошибка при чтении файла соли\n");
        free(salt);
        fclose(file);
        return NULL;
    }

    fclose(file);
    return salt;
}

int save_salt(const unsigned char *salt, int salt_size) {
    FILE *file = fopen(SALT_FILE, "wb");
    if (file == NULL) {
        fprintf(stderr, "Ошибка при открытии файла для сохранения соли\n");
        return -1;
    }

    if (fwrite(salt, 1, salt_size, file) != salt_size) {
        fprintf(stderr, "Ошибка при записи соли в файл\n");
        fclose(file);
        return -1;
    }

    fclose(file);
    return 0;
}

char *get_password() {
    char *password = getpass("Введите пароль: ");
    if (password == NULL) {
        fprintf(stderr, "Ошибка при вводе пароля\n");
        return NULL;
    }
    return strdup(password);
}

// Генерации ключа из пароля и соли
unsigned char *derive_key(const unsigned char *salt, int salt_size, const char *password, int key_length) {
    unsigned char *key = (unsigned char *)malloc(key_length);

    if (PKCS5_PBKDF2_HMAC(password, strlen(password), salt, salt_size, 10000, EVP_sha256(), key_length, key) != 1) {
        fprintf(stderr, "Ошибка при генерации ключа\n");
        ERR_print_errors_fp(stderr);
        free(key);
        return NULL;
    }
    return key;
}

int encrypt_file(const char *filename, const unsigned char *key, int key_length) {
    FILE *infile, *outfile;
    unsigned char iv[EVP_MAX_IV_LENGTH];
    unsigned char in_buf[BUFFER_SIZE], out_buf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int in_len, out_len;
    EVP_CIPHER_CTX *ctx;

    infile = fopen(filename, "rb");
    if (!infile) {
        perror("Ошибка открытия файла для чтения");
        return -1;
    }

    char outfilename[256];
    strcpy(outfilename, filename);
    strcat(outfilename, ".enc");

    outfile = fopen(outfilename, "wb");
    if (!outfile) {
        perror("Ошибка открытия файла для записи");
        fclose(infile);
        return -1;
    }

    // Генерируем случайный IV
    if (RAND_bytes(iv, EVP_CIPHER_iv_length(EVP_aes_256_cbc())) != 1) {
        fprintf(stderr, "Ошибка при генерации IV\n");
        fclose(infile);
        fclose(outfile);
        return -1;
    }

    // Записываем IV в начало зашифрованного файла
    fwrite(iv, 1, EVP_CIPHER_iv_length(EVP_aes_256_cbc()), outfile);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Ошибка при создании контекста шифрования\n");
        fclose(infile);
        fclose(outfile);
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "Ошибка при инициализации шифрования\n");
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        fclose(infile);
        fclose(outfile);
        return -1;
    }

    while ((in_len = fread(in_buf, 1, BUFFER_SIZE, infile)) > 0) {
        if (EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, in_len) != 1) {
            fprintf(stderr, "Ошибка при шифровании\n");
            ERR_print_errors_fp(stderr);
            EVP_CIPHER_CTX_free(ctx);
            fclose(infile);
            fclose(outfile);
            return -1;
        }
        fwrite(out_buf, 1, out_len, outfile);
    }

    if (EVP_EncryptFinal_ex(ctx, out_buf, &out_len) != 1) {
        fprintf(stderr, "Ошибка при завершении шифрования\n");
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        fclose(infile);
        fclose(outfile);
        return -1;
    }
    fwrite(out_buf, 1, out_len, outfile);

    EVP_CIPHER_CTX_free(ctx);
    fclose(infile);
    fclose(outfile);

    if (remove(filename) != 0) {
        perror("Ошибка при удалении исходного файла");
        return -1;
    }

    printf("Файл '%s' успешно зашифрован. Зашифрованная версия сохранена как '%s'\n", filename, outfilename);

    return 0;
}

int decrypt_file(const char *filename, const unsigned char *key, int key_length) {
    FILE *infile, *outfile;
    unsigned char iv[EVP_MAX_IV_LENGTH];
    unsigned char in_buf[BUFFER_SIZE], out_buf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int in_len, out_len;
    EVP_CIPHER_CTX *ctx;

    infile = fopen(filename, "rb");
    if (!infile) {
        perror("Ошибка открытия файла для чтения");
        return -1;
    }

    // Файл имеет расширение .enc
    const char *ext = strrchr(filename, '.');
    if (!ext || strcmp(ext, ".enc") != 0) {
        fprintf(stderr, "Ошибка: Файл не имеет расширения .enc\n");
        fclose(infile);
        return -1;
    }

    char outfilename[256];
    strncpy(outfilename, filename, strlen(filename) - 4); // Копируем имя файла без .enc
    outfilename[strlen(filename) - 4] = '\0';

    outfile = fopen(outfilename, "wb");
    if (!outfile) {
        perror("Ошибка открытия файла для записи");
        fclose(infile);
        return -1;
    }

    // Считываем IV из начала файла
    if (fread(iv, 1, EVP_CIPHER_iv_length(EVP_aes_256_cbc()), infile) != EVP_CIPHER_iv_length(EVP_aes_256_cbc())) {
        fprintf(stderr, "Ошибка чтения IV из файла\n");
        fclose(infile);
        fclose(outfile);
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Ошибка при создании контекста дешифрования\n");
        fclose(infile);
        fclose(outfile);
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "Ошибка при инициализации дешифрования\n");
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        fclose(infile);
        fclose(outfile);
        return -1;
    }

    while ((in_len = fread(in_buf, 1, BUFFER_SIZE, infile)) > 0) {
        if (EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, in_len) != 1) {
            fprintf(stderr, "Ошибка при дешифровании\n");
            ERR_print_errors_fp(stderr);
            EVP_CIPHER_CTX_free(ctx);
            fclose(infile);
            fclose(outfile);
            return -1;
        }
        fwrite(out_buf, 1, out_len, outfile);
    }

    if (EVP_DecryptFinal_ex(ctx, out_buf, &out_len) != 1) {
        fprintf(stderr, "Ошибка при завершении дешифрования (возможно, неверный пароль или поврежденные данные)\n");
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        fclose(infile);
        fclose(outfile);
        return -1;
    }
    fwrite(out_buf, 1, out_len, outfile);

    EVP_CIPHER_CTX_free(ctx);
    fclose(infile);
    fclose(outfile);

    // Удаляем исходный зашифрованный файл после успешного дешифрования
    if (remove(filename) != 0) {
        perror("Ошибка при удалении исходного файла");
        return -1;
    }

    printf("Файл '%s' успешно дешифрован. Дешифрованная версия сохранена как '%s'\n", filename, outfilename);

    return 0;
}

int encrypt_folder(const char *foldername, const unsigned char *key, int key_length) {
    DIR *dir;
    struct dirent *entry;
    struct stat path_stat;

    dir = opendir(foldername);
    if (dir == NULL) {
        perror("Ошибка открытия папки");
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", foldername, entry->d_name);

        if (stat(path, &path_stat) != 0) {
            perror("Ошибка получения информации о файле");
            continue;
        }

        if (S_ISDIR(path_stat.st_mode)) {
            encrypt_folder(path, key, key_length);
        } else if (S_ISREG(path_stat.st_mode)) {
            encrypt_file(path, key, key_length);
        }
    }

    closedir(dir);
    return 0;
}

int decrypt_folder(const char *foldername, const unsigned char *key, int key_length) {
    DIR *dir;
    struct dirent *entry;
    struct stat path_stat;

    dir = opendir(foldername);
    if (dir == NULL) {
        perror("Ошибка открытия папки");
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", foldername, entry->d_name);

        if (stat(path, &path_stat) != 0) {
            perror("Ошибка получения информации о файле");
            continue;
        }

        if (S_ISDIR(path_stat.st_mode)) {
            decrypt_folder(path, key, key_length);
        } else if (S_ISREG(path_stat.st_mode)) {
            decrypt_file(path, key, key_length);
        }
    }

    closedir(dir);
    return 0;
}

int main(int argc, char *argv[]) {
     if (argc < 3) {
        fprintf(stderr, "Использование: %s [-e|-d] <путь> [-s <размер_соли>]\n", argv[0]);
        return 1;
    }

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    int mode_encrypt = 0;
    int salt_size = 16; // Размер соли по умолчанию

    // Парсинг аргументов командной строки
    int opt;
    while ((opt = getopt(argc, argv, "eds:")) != -1) {
        switch (opt) {
            case 'e':
                mode_encrypt = 1;
                break;
            case 'd':
                mode_encrypt = 0;
                break;
            case 's':
                salt_size = atoi(optarg);
                if (salt_size <= 0) {
                    fprintf(stderr, "Размер соли должен быть положительным числом.\n");
                    return 1;
                }
                break;
            default:
                fprintf(stderr, "Использование: %s [-e|-d] <путь> [-s <размер_соли>]\n", argv[0]);
                return 1;
        }
    }

    // Проверяем, что указан путь
    if (optind >= argc) {
        fprintf(stderr, "Необходимо указать путь к файлу или папке.\n");
        fprintf(stderr, "Использование: %s [-e|-d] <путь> [-s <размер_соли>]\n", argv[0]);
        return 1;
    }

    const char *path = argv[optind];
    char *password = get_password();
    if (password == NULL) {
        return 1;
    }

    unsigned char *salt = NULL;

    if (mode_encrypt) {
        // Генерируем новую соль и сохраняем её
        salt = generate_salt(salt_size);
        if (salt == NULL) {
            free(password);
            return 1;
        }
        if (save_salt(salt, salt_size) != 0) {
            free(password);
            free(salt);
            return 1;
        }
    } else {
        // Загружаем соль из файла
        salt = load_salt(&salt_size);
        if (salt == NULL) {
            fprintf(stderr, "Ошибка при загрузке соли из файла.\n");
            free(password);
            return 1;
        }
    }

    int key_length = 32; // Длина ключа в байтах (256 бит для AES-256)

    unsigned char *key = derive_key(salt, salt_size, password, key_length);
    if (key == NULL) {
        free(password);
        free(salt);
        return 1;
    }

    struct stat path_stat;
    if (stat(path, &path_stat) != 0) {
        perror("Ошибка получения информации о пути");
        free(password);
        free(salt);
        free(key);
        return 1;
    }

    if (mode_encrypt) {
        if (S_ISDIR(path_stat.st_mode)) {
            encrypt_folder(path, key, key_length);
        } else if (S_ISREG(path_stat.st_mode)) {
            encrypt_file(path, key, key_length);
        } else {
            fprintf(stderr, "Указанный путь не является ни файлом, ни папкой.\n");
        }
    } else {
        if (S_ISDIR(path_stat.st_mode)) {
            decrypt_folder(path, key, key_length);
        } else if (S_ISREG(path_stat.st_mode)) {
            decrypt_file(path, key, key_length);
        } else {
            fprintf(stderr, "Указанный путь не является ни файлом, ни папкой.\n");
        }
    }

    free(password);
    free(salt);
    free(key);

    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
