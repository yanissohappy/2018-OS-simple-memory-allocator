#include "lib/hw_malloc.h"
#include "hw4_mm_test.h"

char firstword[100]= {}; //alloc,free,print XX
char secondword[100]= {};//find BIN or mmap_alloc_list
//char data_address[1000]= {};
//char alloc_number[1000]= {};

void parse_string(char *input)
{
    char *catch = NULL;
    catch = strtok(input, " ");
    strcpy(firstword, catch);
    catch = strtok(NULL, " ");
    strcpy(secondword, catch);
}

int main(int argc, char *argv[])
{
    char input[100]= {};

    // printf("size:%ld",sizeof(chunk_ptr_t));//test.
    // printf("size:%ld",sizeof(chunk_size_t));//test.
    // printf("size:%ld",sizeof(struct chunk_info_t));//test.
    // printf("size:%ld",sizeof(struct chunk_header));//test.
    // printf("size:%ld",sizeof(struct chunk_header*));//test.
    // printf("size:%ld",sizeof(uint1_t));//test.
    // printf("start address:%p\n",get_start_sbrk());//test.

    while(fgets(input, sizeof(input), stdin) !=NULL) {
        parse_string(input);

        if(!strncmp(firstword, "alloc", 5)) { //the same
            char *address;
            address = hw_malloc(atoi(secondword));
            // printf("%12p\n", (void *)hw_malloc((size_t)(atoi(secondword)))-(unsigned long long)get_start_sbrk());
            if(atoi(secondword)> (32*1024-24))
                printf("0x%012lx\n", (long unsigned int)address+24);
            else
                printf("0x%012x\n", (unsigned int)(address - (char *)get_start_sbrk()));
            // printf("size:%ld\n",sizeof(struct chunk_header));
        } else if(!strncmp(firstword, "free", 5)) {
            void *data_address;
            sscanf(secondword, "%p", &data_address);
            unsigned long long make_sure_mmap_or_heap=(unsigned long long)data_address>>32;
            // printf("test :%lld\n",for_num);
            //printf("%llx\n",(unsigned long long)data_address);    //test.
            if(make_sure_mmap_or_heap>0) { // mmap
                if (hw_free(data_address)) {
                    printf("success\n");
                } else {
                    printf("fail\n");
                }
            } else { // heap
                if (hw_free((void *)get_start_sbrk() + (unsigned long long)data_address)) {
                    printf("success\n");
                } else {
                    printf("fail\n");
                }
            }
        } else if(!strncmp(firstword, "print", 5)) {
            if(secondword[0]=='b') { // BIN
                int bin_num;
                char *catch = NULL; //catch==index in the bin!
                catch = strtok(secondword, "[");
                catch = strtok(NULL, "]");
                if(catch==NULL)
                        continue;
                sscanf(catch, "%d", &bin_num);
                //printf("bin[%d]",bin_num); //test.
                print_bin(bin_num);
            } else if(secondword[0]=='m') { // mmap_alloc_list
                print_mmap();
            }
        }
    }
    return 0;
}
