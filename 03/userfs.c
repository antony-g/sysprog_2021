#include "userfs.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef TARGET_OS_MAC
#define _XOPEN_SOURCE
#endif

#define handle_error(msg) \
    do { perror(msg); exit(EXIT_FAILURE); } while (0)

#define TRUE 1
#define FALSE 0

enum {
	BLOCK_SIZE = 512,
	MAX_FILE_SIZE = 1024 * 1024 * 1024
};

/** Код ошибки для отладки. */
static enum ufs_error_code ufs_error_code = UFS_ERR_NO_ERR;
enum ufs_error_code ufs_errno()
{
	return ufs_error_code;
}

/** Класс блока данных. */
typedef struct block {
	/** Память. */
	char* memory;
	/** Занято. */
	int occupied;
	/** Следующий блок данных. */
	struct block* next;
	/** Предыдущий блок данных. */
	struct block* prev;
} block_t;

/** Класс файла. */
typedef struct file {
	/** Имя файла. */
	const char* name;
	/** Размер блока. */
	int size;
	/** Открытые файловые дескрипторы. */
	int refs;
	/** Двусвязный список блока данных. */
	block_t* block_list;
	struct file* next;
	struct file* prev;
	/** Последний блок (для доступа к концу файла). */
	block_t* last_block;
} file_t;

/** Класс дескриптора файла. */
typedef struct filedesc {
	file_t *file;
	int id, offset;
	int FLAG;
} filedesc_t;

/** Инициализация массива данных. */
static file_t* file_list;
static filedesc_t** file_descriptors;
static int file_descriptor_count;
static int file_descriptor_capacity;

/** Создание блока данных. */
static block_t* block_create() {
	block_t* block = malloc(sizeof(block_t));
	if (!block) {
		handle_error("malloc");
	}
	else {
		block->memory = malloc(BLOCK_SIZE);
	}
	if (!block->memory) {
		handle_error("malloc");
	}
	else {
		block->occupied = 0;
		block->next = NULL;
		block->prev = NULL;
	}
	return block;
}

/** Освобождение памяти. */
static void free_block(block_t* head) {
	block_t* next;
	while (head != NULL) {
		next = head->next;
		free(head->memory);
		free(head);
		head = next;
	}
}

/** Создание файлового дескриптора. */
static filedesc_t* create_fd(file_t* file) {
	filedesc_t* fd = malloc(sizeof(filedesc_t));
	if (!fd) {
		handle_error("malloc");
	}
	else {
		fd->file = file;
		fd->offset = 0;
	}
	int id = 0;
	for (int i = 0; i < file_descriptor_count; i++) {
		if (file_descriptors[i]) {
			id++;
			continue;
		} 
		break;
	}
	fd->id = id;
	if (file_descriptor_count == id) {
		if (file_descriptor_count >= file_descriptor_capacity) { 
			int capacity = (file_descriptor_capacity + 1) * 2;
			int size = capacity * sizeof(filedesc_t*);
			filedesc_t** filedesc = realloc(file_descriptors, size);
			if (!filedesc) {
				handle_error("malloc");
			}
			else {
				file_descriptor_capacity = capacity;
				file_descriptors = filedesc;
			}
		}
		file_descriptor_count++;
	}
	file_descriptors[id] = fd;
	return fd;
}

/** Поиск файлового дескриптора. */
static filedesc_t* fd_find(int fd) {
	for (int i = 0; i < file_descriptor_count; i++) {
		if (file_descriptors[i] && file_descriptors[i]->id == fd) {
			return file_descriptors[i]; 
		}
	}
	return NULL;
}

/** Создание файла. */
static file_t* file_create(const char* path) {
	file_t* file = malloc(sizeof(file_t));
	if (!file) {
		handle_error("malloc");
	}
	else {
		file->block_list = NULL;
		file->last_block = NULL;
	}
	file->refs = 0;
	char* name = malloc(strlen(path) + 1);
	if (!name) {
		handle_error("malloc");
	}
	else {
		memcpy(name, path, strlen(path) + 1);
		file->name = name;
		file->prev = NULL;
	}
	if (!file_list) {
		file->next = NULL;
	}
	else {
		file->next = file_list;
		file_list->prev = file;
	}
	file->size = 0;
	file_list = file;
	return file;
}

/** Проверка существования файла. */
_Bool file_exists(file_t* file) {
	file_t* cur = file_list;
	while (cur) {
		if (cur == file) {
			return TRUE;
		}
		cur = cur->next;
	}
	return FALSE;
}

/** Поиск файла. */
static file_t* file_find(const char* name) {
	file_t* node = file_list;
	while (node) {
		if (strcmp(node->name, name) == 0) {
			return node;
		}
		node = node->next;
	}
	return node;
}

/** Освобождение памяти. */
static void file_free(file_t* file) {
	block_t* block = file->block_list;
	free_block(block);
	free((char*) file->name);
	free(file);
}

/** Открытие файла. */
int ufs_open(const char *filename, int flags)
{
	file_t* file = file_find(filename);
	if (!file) {
		if (flags == UFS_CREATE) {
			file = file_create(filename);
			if (!file) {
				return -1;
			}
		}
		else {
			ufs_error_code = UFS_ERR_NO_FILE;
			return -1;
		}
	}
	filedesc_t* fd = create_fd(file);
	if (!fd) {
		return -1;
	}
	else {
		fd->FLAG = !flags ? UFS_READ_WRITE : flags;
		file->refs++;
	}
	return fd->id;
}

/** Чтение данных. */
static ssize_t read_recursively(block_t* block, int offset, char* buf, size_t size) {
	if (!block) {
		return 0;
	}
	int block_size = block->occupied - offset;
	if (block_size >= size) {
		memcpy(buf, block->memory + offset, size);
		return size;
	}
	memcpy(buf, block->memory + offset, block_size);
	if (block->occupied == BLOCK_SIZE) {
		int bytes_left = size - block_size;
		return block_size + read_recursively(block->next, 0, buf + block_size, bytes_left);
	}
	return block_size;
}

/** Запись данных. */
static ssize_t write_recursively(block_t* block, file_t* file, int offset, const char* buf, size_t size) {
	if (size <= 0) {
		return 0;
	}
	else if (offset == MAX_FILE_SIZE) {
		ufs_error_code = UFS_ERR_NO_MEM; 
		return -1; 
	}
	int memory_left = BLOCK_SIZE - offset % BLOCK_SIZE;
	if (memory_left < size) {
		memcpy(block->memory + offset % BLOCK_SIZE, buf, memory_left);
		file->size += memory_left;
		block->occupied = BLOCK_SIZE;
		int next_size = size - memory_left;
		if (!block->next) {
			block_t* next_block = block_create();
			block->next = next_block;
			next_block->prev = block;
			block = next_block;
			file->last_block = block;
		}
		else {
			block = block->next;
		}
		return memory_left + write_recursively(block, file, offset + memory_left, buf + memory_left, next_size);
	}
	memcpy(block->memory + offset % BLOCK_SIZE, buf, size);
	file->size += size;
	if (block->occupied < offset % BLOCK_SIZE + size) {
		block->occupied = offset % BLOCK_SIZE + size;
	}
	return size;
}

/** Реализация режимов открытия файла. */
ssize_t ufs_read(int fd, char *buf, size_t size)
{
	filedesc_t* filedesc = fd_find(fd); 
	if (!filedesc) {
		ufs_error_code = UFS_ERR_NO_FILE;
		return -1; 
	}
	if ((filedesc->FLAG & (UFS_CREATE | UFS_READ_ONLY | UFS_READ_WRITE)) == 0) {
		ufs_error_code = UFS_ERR_NO_PERMISSION;
		return -1;
	}
	file_t* file = filedesc->file;
	block_t* block = file->block_list;
	int offset = filedesc->offset % BLOCK_SIZE;
	int block_id = filedesc->offset/BLOCK_SIZE;
	for (int i = 0; i < block_id && block != 0; i++) {
		block = block->next;
	}
	if (!block) {
		return 0;
	}
	ssize_t bytes_read = read_recursively(block, offset, buf, size);
	if (bytes_read > 0) {
		filedesc->offset += bytes_read;
	}
	return bytes_read;
}

/** Реализация режимов записи в файл. */
ssize_t ufs_write(int fd, const char *buf, size_t size)
{
	filedesc_t* filedesc = fd_find(fd); 
	if (!filedesc) {
		ufs_error_code = UFS_ERR_NO_FILE;
		return -1; 
	}
	if ((filedesc->FLAG & (UFS_CREATE | UFS_WRITE_ONLY | UFS_READ_WRITE)) == 0) {
		ufs_error_code = UFS_ERR_NO_PERMISSION;
		return -1;
	}
	file_t* file = filedesc->file;
	int offset = filedesc->offset;
	int block_id = filedesc->offset/BLOCK_SIZE;
	if (!file->block_list) {
		block_t* block = block_create();
		file->block_list = block;
		file->last_block = block;
	}
	block_t* block = file->block_list;
	for (int i = 0; i < block_id && block != 0; i++) {
		block = block->next; 
	}
	if (!block) {
		block = block_create();
		block->prev = file->last_block;
		file->last_block->next = block;
		file->last_block = block;
	}
	ssize_t bytes_write = write_recursively(block, file, offset, buf, size); 
	if (bytes_write != -1) {
		filedesc->offset += bytes_write;
	}
	return bytes_write;
}

/** Сдвиг файловых дескрипторов. */
static void fd_offset(file_t* file) {
	int size = file->size;
	filedesc_t* fd = NULL;
	for (int i = 0; i < file_descriptor_count; i++) {
		fd = file_descriptors[i];
		if (fd && fd->file == file) {
			fd->offset = fd->offset > size ? size : fd->offset;
		}
	}
}

/** Закрытие файла. */
int ufs_close(int fd)
{
	for (int i = 0; i < file_descriptor_count; i++) {
		if (file_descriptors[i] && file_descriptors[i]->id == fd) {
			file_t* file = file_descriptors[i]->file;
			if(file->refs-- == 0 && !file_exists(file)) {
				file_free(file); 
			}
			free(file_descriptors[i]);
			return 0;
		}
	}
	ufs_error_code = UFS_ERR_NO_FILE;
	return -1;
}

/** Удаление файла. */
int ufs_delete(const char *filename)
{
	file_t* file = file_find(filename);
	if (file) {
		if (file->next)
			file->next->prev = file->prev;
		if (file->prev)
			file->prev->next = file->next;
		if (file == file_list)
			file_list = file->next;
		if (!file->refs)
			file_free(file);
		return 0;
	}
	else {
		ufs_error_code = UFS_ERR_NO_FILE;
		return -1;
	}
}

/** Изменение размера файла (resize). */
int ufs_resize(int fd, size_t size) {
	if (size < 0) {
		return -1;
	}
	filedesc_t* file_desc = fd_find(fd);
	if (!file_desc) {
		ufs_error_code = UFS_ERR_NO_FILE;
		return -1;
	}
	file_t* file = file_desc->file;
	int new_block = size/BLOCK_SIZE - file->size/BLOCK_SIZE;
	int offset = size % BLOCK_SIZE;
	block_t* block = file->last_block;
	if (new_block > 0) {
		for (int i = 0; i < new_block; i++) {
			block_t* next_block = block_create();
			next_block->prev = block;
			block->next = next_block;
			block = next_block;
			file->size += BLOCK_SIZE;
		}
		file->last_block = block;
		return 0;
	} 
	for (int i = -1; i > new_block && block; i--) { 
		block = block->prev;
		file->size -= BLOCK_SIZE;
	}
	if (block) {
		block->occupied = offset;
		file->size += offset - BLOCK_SIZE;
		fd_offset(file);
	}
	file->last_block = block;
	return 0;
}
