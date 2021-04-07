#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <malloc.h>
#include <libgen.h>
#include <errno.h>
#include <stdint.h>


/*Написать программу подсчета хэша для каждого файла заданного каталога и его подкаталогов.
 * Пользователь задаёт имя каталога. Для хэша можно использовать любой алгоритм,
 * дающий приемлемые результаты. Главный процесс открывает каталоги и запускает для каждого
 * файла каталога отдельный процесс подсчета хэша. Каждый процесс выводит на экран свой pid,
 * полный путь к файлу, общее число просмотренных байт и хэш файла. Число одновременно работающих
 * процессов не должно превышать N (вводится пользователем). Проверить работу программы для каталога /etc.*/

void find_files(char *root_path);

char *get_full_path(char *parent, char *name);

void print_error(const char *s_name, const char *msg, const char *desc);

int isNumber(const char *str);

void get_hash(char *path);

unsigned short crc16(char *data_p, long length);

char *program_name;

int max_am_of_proc;
int am_of_processes = 0;


/*
 * Simple MD5 implementation
 *
 * Compile with: gcc -o md5 md5.c
 */


// Constants are the integer part of the sines of integers (in radians) * 2^32.
const uint32_t k[64] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee ,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501 ,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be ,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 ,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa ,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8 ,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed ,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a ,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c ,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70 ,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05 ,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665 ,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039 ,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1 ,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1 ,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

// r specifies the per-round shift amounts
const uint32_t r[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                      5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

// leftrotate function definition
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

void to_bytes(uint32_t val, uint8_t *bytes)
{
    bytes[0] = (uint8_t) val;
    bytes[1] = (uint8_t) (val >> 8);
    bytes[2] = (uint8_t) (val >> 16);
    bytes[3] = (uint8_t) (val >> 24);
}

uint32_t to_int32(const uint8_t *bytes)
{
    return (uint32_t) bytes[0]
           | ((uint32_t) bytes[1] << 8)
           | ((uint32_t) bytes[2] << 16)
           | ((uint32_t) bytes[3] << 24);
}

void md5(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest)
{

    // These vars will contain the hash
    uint32_t h0, h1, h2, h3;

    // Message (to prepare)
    uint8_t *msg = NULL;

    size_t new_len, offset;
    uint32_t w[16];
    uint32_t a, b, c, d, i, f, g, temp;

    // Initialize variables - simple count in nibbles:
    h0 = 0x67452301;
    h1 = 0xefcdab89;
    h2 = 0x98badcfe;
    h3 = 0x10325476;

    //Pre-processing:
    //append "1" bit to message
    //append "0" bits until message length in bits ≡ 448 (mod 512)
    //append length mod (2^64) to message

    for (new_len = initial_len + 1; new_len % (512/8) != 448/8; new_len++)
        ;

    msg = malloc(new_len + 8);
    memcpy(msg, initial_msg, initial_len);
    msg[initial_len] = 0x80; // append the "1" bit; most significant bit is "first"
    for (offset = initial_len + 1; offset < new_len; offset++)
        msg[offset] = 0; // append "0" bits

    // append the len in bits at the end of the buffer.
    to_bytes(initial_len*8, msg + new_len);
    // initial_len>>29 == initial_len*8>>32, but avoids overflow.
    to_bytes(initial_len>>29, msg + new_len + 4);

    // Process the message in successive 512-bit chunks:
    //for each 512-bit chunk of message:
    for(offset=0; offset<new_len; offset += (512/8)) {

        // break chunk into sixteen 32-bit words w[j], 0 ≤ j ≤ 15
        for (i = 0; i < 16; i++)
            w[i] = to_int32(msg + offset + i*4);

        // Initialize hash value for this chunk:
        a = h0;
        b = h1;
        c = h2;
        d = h3;

        // Main loop:
        for(i = 0; i<64; i++) {

            if (i < 16) {
                f = (b & c) | ((~b) & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | ((~d) & c);
                g = (5*i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3*i + 5) % 16;
            } else {
                f = c ^ (b | (~d));
                g = (7*i) % 16;
            }

            temp = d;
            d = c;
            c = b;
            b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]);
            a = temp;

        }

        // Add this chunk's hash to result so far:
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;

    }

    // cleanup
    free(msg);

    //var char digest[16] := h0 append h1 append h2 append h3 //(Output is in little-endian)
    to_bytes(h0, digest);
    to_bytes(h1, digest + 4);
    to_bytes(h2, digest + 8);
    to_bytes(h3, digest + 12);
}

int main(int argc, char *argv[]) {
    program_name = basename(argv[0]);
    if (argc < 3) {
        print_error(program_name, "Incorrect amount of arguments.", 0);
        return 1;
    }
    char *dir_name = realpath(argv[1], NULL);
    if (dir_name == NULL) {
        print_error(program_name, "Error opening directory:", argv[1]);
        return 1;
    }
    if (!isNumber(argv[2])) {
        print_error(program_name, "Incorrect amount of processes.", NULL);
        return 1;
    }
    max_am_of_proc = atoi(argv[2]);
    if (max_am_of_proc < 1) {
        print_error(program_name, "Incorrect amount of processes.", NULL);
        return 1;
    }
    max_am_of_proc--;
    find_files(dir_name);
    while (wait(NULL) != - 1) {}
    return 0;

}

int isNumber(const char *str) {
    for (int i = 0; str[i]; i++) {
        if (str[i] < '0' || str[i] > '9')
            return 0;
    }
    return 1;
}

void find_files(char *root_path) {
    struct dirent *struct_dirent;
    char *path;
    errno = 0;
    pid_t pid = -1;
    DIR *curr_dir;
    if ((curr_dir = opendir(root_path)) == NULL) {
        print_error(program_name, strerror(errno), NULL);
        return;
    }
    while ((struct_dirent = readdir(curr_dir))) {
        path = get_full_path(root_path, struct_dirent->d_name);
        if (struct_dirent->d_type == DT_DIR &&
            strcmp(".", struct_dirent->d_name) && strcmp("..", struct_dirent->d_name)) {
            find_files(path);
        } else if (struct_dirent->d_type == DT_REG) {
            if (am_of_processes >= max_am_of_proc) {
                wait(0);
                am_of_processes--;
            }
            do {
                pid = fork();
                if (pid == -1) {
                    print_error(program_name, strerror(errno), NULL);
                    errno = 0;
                } else if (pid == 0) {
                    get_hash(path);
                    exit(0);
                } else if (pid > 0) {
                    am_of_processes++;
                }
            } while (pid == -1);
        }
        errno = 0;
    }
    if (errno != 0)
        print_error(program_name, strerror(errno), NULL);
    if (closedir(curr_dir) == -1) {
        print_error(program_name, strerror(errno), NULL);
    }
}

void get_hash(char *path) {
    FILE *file = fopen(path, "r");
    if (!file) {
        print_error(program_name, strerror(errno), NULL);
        errno = 0;
        return;
    }
    struct stat *buf = (struct stat *) calloc(1, sizeof(struct stat));
    if (fstat(file->_fileno, buf) == -1) {
        print_error(program_name, strerror(errno), NULL);
        errno = 0;
        return;
    }
    char *data = (char *) calloc(buf->st_size, sizeof(char));
    size_t am_of_bytes = fread(data, sizeof(char), buf->st_size, file);
    if (fclose(file)) {
        print_error(program_name, strerror(errno), NULL);
        errno = 0;
    }

    uint8_t result[16];

    md5((uint8_t*) data, am_of_bytes, result);
    printf("%d: %s %ld ", getpid(), path, am_of_bytes);

    int i;
    for (i = 0; i < 16; i++)
        printf("%2.2X", result[i]);
    puts("");
}

char *get_full_path(char *parent, char *name) {
    char *full_path = (char *) calloc
            (strlen(parent) + strlen(name) + 2, sizeof(char));
    strcpy(full_path, parent);
    strcat(full_path, "/");
    strcat(full_path, name);
    return full_path;
}

void print_error(const char *s_name, const char *msg, const char *desc) {
    fprintf(stderr, "%s: %s %s\n", s_name, msg, (desc) ? desc : "");
}
