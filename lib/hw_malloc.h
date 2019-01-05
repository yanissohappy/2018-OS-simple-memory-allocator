#ifndef HW_MALLOC_H
#define HW_MALLOC_H

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/mman.h>
#include <malloc.h>

typedef struct chunk_header *chunk_ptr_t ;

struct chunk_info_t {
    unsigned int pre_chunk_size:31;
    unsigned int allocated_flag:1;
    unsigned int cur_chunk_size:31;
    unsigned int mmap_flag:1;
};

struct chunk_header {
    chunk_ptr_t prev;
    chunk_ptr_t next;
    struct chunk_info_t size_and_flag;
};

void *hw_malloc(size_t bytes);
int hw_free(void *mem);
void *get_start_sbrk(void);
void bin_choose_and_add_in(struct chunk_header *new);
void print_mmap();
void print_bin(int index);
int best_fit(size_t chunk_size);
void split(struct chunk_header *target, unsigned int chunk_size);
struct chunk_header *next_header(struct chunk_header *chunk);
struct chunk_header *prev_header(struct chunk_header *chunk);
struct chunk_header *regular(struct chunk_header *const chunk);
void *delete_chunk(struct chunk_header *chunk);
void *shift(void *const chunk, const long long size);
struct chunk_header *find_chunk(int index, size_t size);
void merge(struct chunk_header *prev, struct chunk_header *next);
int is_free(struct chunk_header *chunk);
int is_header(struct chunk_header *const chunk);
void add_mmap_list(struct chunk_header *head,struct chunk_header *new);
struct chunk_header *find_mmap_and_delete(struct chunk_header *address);
int find_mmap(struct chunk_header *address);

#endif
