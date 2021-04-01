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

#define POLY 0x8408

void find_files(char *root_path);

char *get_full_path(char *parent, char *name);

void print_error(const char *s_name, const char *msg, const char *desc);

int isNumber(const char *str);

void get_hash(char *path);

unsigned short crc16(char *data_p, long length);

char *program_name;

int max_am_of_proc;
int am_of_processes = 0;

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
    find_files(dir_name);
    while (wait(0) != - 1) {}
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
            while (pid == -1) {
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
            }
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
    unsigned short hash = crc16(data, am_of_bytes);
    printf("%d: %s %ld %d\n", getpid(), path, am_of_bytes, hash);
}

unsigned short crc16(char *data_p, long length) {
    unsigned char i;
    unsigned int data;
    unsigned int crc = 0xffff;

    if (length == 0)
        return (~crc);

    do {
        for (i = 0, data = (unsigned int) 0xff & *data_p++;
             i < 8;
             i++, data >>= 1) {
            if ((crc & 0x0001) ^ (data & 0x0001))
                crc = (crc >> 1) ^ POLY;
            else crc >>= 1;
        }
    } while (--length);

    crc = ~crc;
    data = crc;
    crc = (crc << 8) | (data >> 8 & 0xff);

    return (crc);
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