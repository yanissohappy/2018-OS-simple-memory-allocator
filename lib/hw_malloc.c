#include "hw_malloc.h"
#include <assert.h>

#define ALLOCATED 1
#define FREE 0

void *start_addr=NULL;
struct chunk_header bin[11] = {0};
struct chunk_header *mmap_head=NULL;
int initialized=0;

void bin_choose_and_add_in(struct chunk_header *new)
{
    int bin_index=0;

    if(new->size_and_flag.cur_chunk_size<=32)//2^5 between header ~ 2^5
        bin_index=0;
    else if(new->size_and_flag.cur_chunk_size>32 && new->size_and_flag.cur_chunk_size<=64) {
        bin_index=1;
    } else if(new->size_and_flag.cur_chunk_size>64 && new->size_and_flag.cur_chunk_size<=128) {
        bin_index=2;
    } else if(new->size_and_flag.cur_chunk_size>128 && new->size_and_flag.cur_chunk_size<=256) {
        bin_index=3;
    } else if(new->size_and_flag.cur_chunk_size>256 && new->size_and_flag.cur_chunk_size<=512) {
        bin_index=4;
    } else if(new->size_and_flag.cur_chunk_size>512 && new->size_and_flag.cur_chunk_size<=1024) {
        bin_index=5;
    } else if(new->size_and_flag.cur_chunk_size>1024 && new->size_and_flag.cur_chunk_size<=2048) {
        bin_index=6;
    } else if(new->size_and_flag.cur_chunk_size>2048 && new->size_and_flag.cur_chunk_size<=4096) {
        bin_index=7;
    } else if(new->size_and_flag.cur_chunk_size>4096 && new->size_and_flag.cur_chunk_size<=8192) {
        bin_index=8;
    } else if(new->size_and_flag.cur_chunk_size>8192 && new->size_and_flag.cur_chunk_size<=16384) {
        bin_index=9;
    } else if(new->size_and_flag.cur_chunk_size>16384 && new->size_and_flag.cur_chunk_size<=32768) {//2^15
        bin_index=10;
    }

    struct chunk_header *ptr = bin[bin_index].prev;

    new->prev = ptr; //add it into bin
    new->next = ptr->next;
    new->prev->next = new;
    new->next->prev = new;

}

int best_fit(size_t chunk_size)
{
    int best_fit_size=0; //get 2^n this n.

    if(chunk_size>24 && chunk_size<=32)//2^5 between header ~ 2^5
        best_fit_size=32; // b[0]
    else if(chunk_size>32 && chunk_size<=64) {
        best_fit_size=64;
    } else if(chunk_size>64 && chunk_size<=128) {
        best_fit_size=128;
    } else if(chunk_size>128 && chunk_size<=256) {
        best_fit_size=256;
    } else if(chunk_size>256 && chunk_size<=512) {
        best_fit_size=512;
    } else if(chunk_size>512 && chunk_size<=1024) {
        best_fit_size=1024;
    } else if(chunk_size>1024 && chunk_size<=2048) {
        best_fit_size=2048;
    } else if(chunk_size>2048 && chunk_size<=4096) {
        best_fit_size=4096;
    } else if(chunk_size>4096 && chunk_size<=8192) {
        best_fit_size=8192;
    } else if(chunk_size>8192 && chunk_size<=16384) {
        best_fit_size=16384;
    } else if(chunk_size>16384 && chunk_size<=32768) {//2^15
        best_fit_size=32768;// b[10]
    } else if(chunk_size>32768 && chunk_size<=65536) {//2^16
        best_fit_size=65536;// it will be half in the future.
    }

    return best_fit_size;
}

void split(struct chunk_header *target, unsigned int chunk_size)//chunk_size will be the "best fit size".
{
    int total_power_chunk=0;
    int total_power_target=0;
    int corresponding_chunk_size=chunk_size;
    int corresponding_target_size=target->size_and_flag.cur_chunk_size;
    int remain_needed_cut=0;//need to cut times.
    while(corresponding_chunk_size!=1) {
        corresponding_chunk_size/=2;
        total_power_chunk++;
    }

    while(corresponding_target_size!=1) {
        corresponding_target_size/=2;
        total_power_target++;
    }

    corresponding_chunk_size=chunk_size;
    corresponding_target_size=target->size_and_flag.cur_chunk_size;
    remain_needed_cut=total_power_target-total_power_chunk;

    if(chunk_size==65536) { // will cut it half.
        struct chunk_header *remain = shift(target, 32768);

        remain->size_and_flag.cur_chunk_size = 32768;
        remain->size_and_flag.allocated_flag = FREE; // not very sure!!!!!!
        remain->size_and_flag.pre_chunk_size = 32768;
        remain->size_and_flag.mmap_flag=0;
        remain->next = NULL;
        remain->prev = NULL;
        next_header(remain)->size_and_flag.pre_chunk_size = remain->size_and_flag.cur_chunk_size;

        target->size_and_flag.cur_chunk_size = 32768;
        target->size_and_flag.pre_chunk_size = 32768;
        target->size_and_flag.allocated_flag = FREE;
        target->size_and_flag.mmap_flag=0;

        bin_choose_and_add_in(remain);
        return;
    } else {
        if(target->size_and_flag.cur_chunk_size == chunk_size) { //don't need to split.
            return;
        } else {
            if(remain_needed_cut!=0) {
                struct chunk_header *remain = shift(target, target->size_and_flag.cur_chunk_size/2);

                remain->size_and_flag.cur_chunk_size = target->size_and_flag.cur_chunk_size/2;
                remain->size_and_flag.allocated_flag = FREE;
                remain->size_and_flag.pre_chunk_size = target->size_and_flag.cur_chunk_size/2;
                remain->size_and_flag.mmap_flag=0;
                remain->next = NULL;
                remain->prev = NULL;
                next_header(remain)->size_and_flag.pre_chunk_size = remain->size_and_flag.cur_chunk_size;

                target->size_and_flag.cur_chunk_size = target->size_and_flag.cur_chunk_size/2;
                target->size_and_flag.mmap_flag=0;
                bin_choose_and_add_in(remain);
                corresponding_chunk_size/=2;
                split(target, chunk_size);
            } else {
                return ;
            }
        }
    }
}

void *delete_chunk(struct chunk_header *chunk)
{
    chunk->next->prev = chunk->prev;
    chunk->prev->next = chunk->next;
    chunk->next = NULL;
    chunk->prev = NULL;

    return chunk;
}

struct chunk_header *find_chunk(int index, size_t size)//will return a ptr if find a chunk.
{
    struct chunk_header *ret = NULL;

    struct chunk_header *ptr = bin[index].prev;
    while (ptr != &bin[index]) {
        // assert(ptr->size_and_flag.cur_chunk_size >= size);
        if (ret == NULL || ptr < ret) {
            ret = ptr;
        }
        ptr = ptr->prev;
    }

    if (ret && ret->size_and_flag.cur_chunk_size >= size) {
        delete_chunk(ret);
        return ret;
    } else {
        return NULL;
    }
}

struct chunk_header *find_mmap_and_delete(struct chunk_header *address)//will return a ptr if find a chunk.
{
    struct chunk_header *original_ptr = address;
    struct chunk_header *ptr = address->prev;

    while (ptr != original_ptr) {
        if (ptr == address) {
            break;
        }
        ptr = ptr->prev;
    }
    delete_chunk(ptr);

    return ptr;
}

int find_mmap(struct chunk_header *address)
{
    int if_found=0;
    struct chunk_header *ptr = mmap_head->next;
    while (ptr != mmap_head) {
        if (ptr == address) {
            if_found=1;
            break;
        }
        ptr = ptr->next;
    }

    if(if_found==1)
        return 1;
    else
        return 0;
}

void *shift(void *const chunk, const long long size)
{
    return chunk + size;
}

struct chunk_header *regular(struct chunk_header *const chunk)
{
    if ((void *)chunk < (void *)get_start_sbrk()) {
        return shift(chunk, (65536));
    } else if ((void *)chunk >= (void *)get_start_sbrk() + (65536)) {
        return shift(chunk, -((65536)));
    } else {
        return chunk;
    }
}

struct chunk_header *prev_header(struct chunk_header *const chunk)
{
    return regular(shift(chunk, -(chunk->size_and_flag.pre_chunk_size)));
}

struct chunk_header *next_header(struct chunk_header *const chunk)
{
    return regular(shift(chunk, chunk->size_and_flag.cur_chunk_size));
}

void add_mmap_list(struct chunk_header *head,struct chunk_header *new)
{
    struct chunk_header *ptr = head->prev;

    while (ptr != head) {
        if (ptr->size_and_flag.cur_chunk_size <= new->size_and_flag.cur_chunk_size) {
            break;
        }
        ptr = ptr->prev;
    }
    new->prev = ptr;
    new->next = ptr->next;
    new->prev->next = new;
    new->next->prev = new;

}

void *hw_malloc(size_t bytes)
{
    size_t chunk_size= 24+bytes;
    unsigned int best_fit_size=best_fit(chunk_size);
    struct chunk_header *this_is_the_chunk_i_want=NULL;

    if (bytes < 0)
        return NULL;
    if (initialized==0) { // first initialization
        start_addr=sbrk(64 * 1024);
        for (int i = 0; i < 11; i++) {//initialize bin
            bin[i].prev = &bin[i];
            bin[i].next = &bin[i];
            bin[i].size_and_flag.pre_chunk_size = 0;
            bin[i].size_and_flag.cur_chunk_size = 0;
            bin[i].size_and_flag.allocated_flag = ALLOCATED;
            bin[i].size_and_flag.mmap_flag = 0; //If yes,1;no, 0.But it's not so vital.
        }

        struct chunk_header *total_heap = start_addr;
        total_heap->next = NULL;
        total_heap->prev = NULL;
        total_heap->size_and_flag.cur_chunk_size = 64 * 1024;
        total_heap->size_and_flag.pre_chunk_size = 64 * 1024;
        total_heap->size_and_flag.allocated_flag = FREE;

        mmap_head=(struct chunk_header*)malloc(sizeof(struct chunk_header));
        mmap_head->prev= mmap_head;
        mmap_head->next= mmap_head;

        split(total_heap,best_fit(65536));
        bin_choose_and_add_in(total_heap);
        initialized=1; // and it won't enter again.
    }

    if(chunk_size > 32768) { //mmap allocation method //has problem...
        struct chunk_header *p = mmap (0, chunk_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        p->size_and_flag.cur_chunk_size=chunk_size;
        p->size_and_flag.mmap_flag=1;
        add_mmap_list(mmap_head, p);

        return p;

    } else {//heap allocation method
        for (int i = 0; i < 11; i++) {
            if ((this_is_the_chunk_i_want = find_chunk(i, best_fit_size))) {
                break;
            }
        }

        if (!this_is_the_chunk_i_want) {
            return NULL;
        }

        split(this_is_the_chunk_i_want, best_fit_size);//If "this_is_the_chunk_i_want" is too big,split it.
        this_is_the_chunk_i_want->size_and_flag.allocated_flag = ALLOCATED;
        this_is_the_chunk_i_want->size_and_flag.mmap_flag = 0;

        return shift(this_is_the_chunk_i_want, sizeof(struct chunk_header));
    }

    return NULL;//if no any
}

void merge(struct chunk_header *prev, struct chunk_header *next)
{
    if(prev->size_and_flag.cur_chunk_size==next->size_and_flag.cur_chunk_size && prev->size_and_flag.cur_chunk_size!=32768 && next->size_and_flag.cur_chunk_size!=32768) {
        delete_chunk(prev);
        delete_chunk(next);
        prev->size_and_flag.cur_chunk_size = prev->size_and_flag.cur_chunk_size + next->size_and_flag.cur_chunk_size;
        next_header(prev)->size_and_flag.pre_chunk_size = prev->size_and_flag.cur_chunk_size;
        bin_choose_and_add_in(prev);

        if (prev_header(prev) < prev && is_free(prev_header(prev))) { //lower address has higher priority to merge
            merge(prev_header(prev), prev);
        }

        if (next_header(prev) > prev && is_free(next_header(prev))) {
            merge(prev, next_header(prev));
        }
    }
}

int is_header(struct chunk_header *const chunk)
{
    void *bound = shift(start_addr, 65536);
    struct chunk_header *ptr = start_addr;

    while ((void *)ptr < bound && ptr <= chunk) {//try to find chunk from the bottom.
        if (ptr == chunk) {
            return 1;
        }
        ptr = shift(ptr, ptr->size_and_flag.cur_chunk_size);
    }

    return 0;
}

int is_free(struct chunk_header *chunk)
{
    if ((chunk)->size_and_flag.allocated_flag == FREE) {
        return 1;
    }
    return 0;
}

int hw_free(void *mem)
{
    struct chunk_header *header = shift(mem, -sizeof(struct chunk_header));
    if(find_mmap(header)) {
        if(header->size_and_flag.mmap_flag==1) {
            header->size_and_flag.mmap_flag = 0;
            find_mmap_and_delete(header);
            int r=munmap(header, header->size_and_flag.cur_chunk_size);

            if(r==0)
                return 1;
            else
                return 0;
            // }
        }
    } else if(!find_mmap(header)) {
        if (!is_header(header)) {
            return 0;
        }
        if(header->size_and_flag.cur_chunk_size<= 32 * 1024) {
            if (!is_header(header)) {
                return 0;
            }

            if(is_free(header)) {
                return 0;
            }

            header->size_and_flag.allocated_flag = FREE;
            bin_choose_and_add_in(header);

            if (prev_header(header) < header && is_free(prev_header(header))) { //lower address has higher priority to merge
                merge(prev_header(header), header);
            }
            if (next_header(header) > header && is_free(next_header(header))) {
                merge(header, next_header(header));
            }


            return 1;
        }
    }
    return 0; // if find no any.
}

void *get_start_sbrk(void)
{
    return start_addr;
}

void print_bin(int index)
{
    struct chunk_header *ptr = bin[index].next;
    while (ptr != &bin[index]) {
        if((void *)ptr == start_addr)
            printf("0x000000000000--------%u\n", ptr->size_and_flag.cur_chunk_size);
        else
            printf("0x%012lx--------%u\n", (void *)ptr - start_addr, ptr->size_and_flag.cur_chunk_size);
        ptr = ptr->next;
    }

}

void print_mmap()
{
    struct chunk_header *ptr = mmap_head->next;
    while (ptr != mmap_head) {
        printf("0x%012lx--------%u\n", (long unsigned int)ptr, ptr->size_and_flag.cur_chunk_size);
        ptr = ptr->next;
    }
}
