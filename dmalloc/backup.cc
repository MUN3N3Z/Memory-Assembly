#define M61_DISABLE 1
#include "dmalloc.hh"
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cassert>
#include <stdbool.h>

// You may write code here.
// (Helper functions, types, structs, macros, globals, etc.)
const char* canary_value = "NaIroBi";
#define MAGIC_NUMBER 0xdeadbeef
#define FREE_NUMBER 0xfeed

// Global statistics struct
struct dmalloc_statistics global_stats;

// Malloc header 
typedef struct header
{
    const char* file_name;
    long file_line;
    size_t size;
    long long magic_number;
    void* payload;
    struct header* next;
    struct header* prev;
}header;

// Linked list meta data
typedef struct dmalloc_list
{
    header* head;
    header* tail;
    size_t size;
}dmalloc_list;

// Heavy hitter struct
typedef struct hitter_symbol{
    const char* file;
    long line;
    size_t size;
    size_t eliminated_bytes;
}hitter_symbol;

//Global linked list
dmalloc_list global_list; 
// Global heavy hitter list
hitter_symbol hhitter_array[5];
size_t hhitter_count;
size_t hhitter_total;


/**
 * My compare function for qsort
*/
int comparator(const void *p, const void *q) 
{
    int l = (int) (((hitter_symbol *)p)->size + ((hitter_symbol *)p)->eliminated_bytes);
    int r = (int) (((hitter_symbol *)q)->size + ((hitter_symbol *)q)->eliminated_bytes);
    return (r - l);
}
// Linked list functions
/*
 * Insert a node into linked list
*/
void list_push(header* node){
    // List is empty
    if (global_list.size == 0)
    {
        global_list.head = node;
        global_list.tail = node;
        node->prev = NULL;
        node->next = NULL;
    }
    else
    {
        // Connect last node to the new node
        global_list.tail->next = node;
        node->prev = global_list.tail;
        node->next = NULL;
        // Set new tail
        global_list.tail = node;
    }
    // Account for new node
    global_list.size ++; 
}

/**
 * Remove node form linked list
*/
void list_pop(header* node){
    // Node is last in list
    if (node->prev != NULL && node->next == NULL)
    {
        // Cut node from rest of the list
        node->prev->next = NULL;
        // Update tail pointer
        global_list.tail = node->prev;
    }
    // Node is first in list
    else if (node->prev == NULL && node->next != NULL)
    {
        // Cut off node from rest of list
        node->next->prev = NULL;
        // Update head pointer
        global_list.head = node->next;
    }
    // Node is middle in list
    else if (node->prev != NULL && node->next != NULL)
    {
        // Link previous node to next node
        node->prev->next = node->next;
        node->next->prev = node->prev;
    }
    // Node is the only node in list
    else
    {
        global_list.head = NULL;
        global_list.tail = NULL;
    }
    // Account for deleted node
    global_list.size --;    
}

/**
 * Insert a heavy hitter into the heavy hitter list
*/
void heavy_hitter_push(hitter_symbol* symbol){
    // Incremement size of symbol if already in array
    size_t counter = 0;
    while(counter < hhitter_count)
    {
        // Get array symbol details
        const char* file_name = hhitter_array[counter].file;
        long long file_line = hhitter_array[counter].line;
        if((strcmp(file_name, symbol->file) == 0) && (file_line == symbol->line))
        {
            hhitter_array[counter].size += symbol->size;
            hhitter_total += symbol->size;
            return;
        }
        counter ++;
    }
    // Insert symbol if not in array
    // Array is not full
    if(hhitter_count < 5)
    {
        hhitter_array[hhitter_count].file = symbol->file;
        hhitter_array[hhitter_count].line = symbol->line;
        hhitter_array[hhitter_count].size = symbol->size;
        hhitter_count ++; // Account for new symbol
        hhitter_total += symbol->size;
    }
    // Array is full
    else
    {
        size_t smallest = SIZE_MAX;
        size_t counter2 = 0;
        size_t smallest_index = 0; // Index of smallest region on hhitter_array
        // Get smallest sized element in array
        while(counter2 < hhitter_count)
        {
            if (hhitter_array[counter2].size < smallest)
            {
                smallest = hhitter_array[counter2].size;
                smallest_index = counter2;
            }
            counter2 ++;
        }
        // Subtract new_symbol size from rest of symbols in array if new_symbol size is smallest (NEW_SYMBOL NOT INSERTED)
        if (symbol->size <= smallest)
        {
            for (size_t k = 0; k < hhitter_count; k++)
            {
                hhitter_array[k].size = hhitter_array[k].size - symbol->size;
                // Update # eliminated bytes
                hhitter_array[k].eliminated_bytes+= symbol->size;
            }
        }
        else //(NEW_SYMBOL IS INSERTED)
        {
            // Subtract from each element the value of the smallest size in the array
            for (size_t j = 0; j < hhitter_count; j++)
            {
                hhitter_array[j].size = hhitter_array[j].size - smallest;
                // Update # eliminated bytes
                hhitter_array[j].eliminated_bytes+= smallest;
            }
            // Replace smallest element with new symbol
            hhitter_array[smallest_index].file = symbol->file;
            hhitter_array[smallest_index].line = symbol->line;
            hhitter_array[smallest_index].size = (symbol->size - smallest);
            hhitter_total += symbol->size;
        }
    }
}
/**
 * Initialize newly allocated space with underflow and overflow canaries
 * @return a pointer to the payload
*/
void* dmalloc_init(void* new_space, size_t sz, const char* file, long long line){
    // Set underflow canary
    char* underflow_canary = (char*)(((uintptr_t)new_space) + sizeof(header));
    strcpy(underflow_canary, canary_value);
    // Set overflow canary
    char* overflow_canary = (underflow_canary + (sizeof(canary_value)) + sz);
    strcpy(overflow_canary, canary_value);
    // Initialize malloc size
    header* head = ((header*) new_space);
    head->size = sz;
    head->magic_number = MAGIC_NUMBER;
    // Get payload address (offset underflow_canary and header)
    void* payload = (void*)(((uintptr_t)new_space) + sizeof(header) + (sizeof(canary_value)));
    // Other initializations
    head->file_name = file;
    head->file_line = line;
    head->payload = (void*)(((uintptr_t) new_space) + sizeof(header) + sizeof(canary_value));
    head->next = NULL;
    head->prev = NULL;

    return payload;
}

/**
 * Catch buffer overflows and underflows using a canary
*/
bool check_canary(void* new_space, size_t sz){
    // Detect overflow
    char* underflow_canary = (char*)(((char*)new_space) - (sizeof(canary_value)));
    char* overflow_canary = (char*)(((char*)new_space) + sz);
    if ((strcmp(underflow_canary, canary_value)) != 0 || (strcmp(overflow_canary, canary_value)) != 0)
    {
        return false;
    }
    // Canaries all in place
    return true;
}
/// dmalloc_malloc(sz, file, line)
///    Return a pointer to `sz` bytes of newly-allocated dynamic memory.
///    The memory is not initialized. If `sz == 0`, then dmalloc_malloc must
///    return a unique, newly-allocated pointer value. The allocation
///    request was at location `file`:`line`.

void* dmalloc_malloc(size_t sz, const char* file, long line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
    // Your code here.
    
    void* new_space = base_malloc((sizeof(header)) + sz + (2 * (sizeof(canary_value))));
    // Count failed mallocs
    if (new_space == NULL)
    {
        // Number of failed allocations
        global_stats.nfail ++;
        // Number of bytes in failed alloc attempts
        global_stats.fail_size += sz;
        return new_space;
    }
    else
    {
        void* payload = dmalloc_init(new_space, sz, file, line);
        // Check for overflow
        if (!(check_canary(payload, sz)))
        {
            global_stats.nfail ++;
            global_stats.fail_size = sz;
            base_free(new_space);
            return NULL;
        }
        global_stats.active_size += sz;
        uintptr_t lower_limit = ((uintptr_t) payload);
        uintptr_t upper_limit = ((uintptr_t) payload) + sz;
        // Smallest & largest allocated address
        if (global_stats.ntotal == 0)
        {
            global_stats.heap_max = upper_limit;
            global_stats.heap_min = lower_limit;
        }
        else
        {
            // Check if smallest allocated address
            if (lower_limit < global_stats.heap_min)
            {
                global_stats.heap_min = lower_limit;
            }
            // Check if largest allocated address
            if (upper_limit > global_stats.heap_max)
            {
                global_stats.heap_max = upper_limit;
            }
        }
        // Number of total allocations
        global_stats.ntotal ++;
        // Number of bytes in total allocations
        global_stats.total_size += sz;
        // Number of active allocations
        global_stats.nactive ++;
        // Push new alloc to linked-list
        list_push(((header*) new_space));
        // Push new alloc to heavy_hitters array
        hitter_symbol symbol;
        symbol.file = (const char*) file;
        symbol.line = (long) line;
        symbol.size = sz;
        heavy_hitter_push(&symbol);
        return payload;
    }
}


/// dmalloc_free(ptr, file, line)
///    Free the memory space pointed to by `ptr`, which must have been
///    returned by a previous call to dmalloc_malloc. If `ptr == NULL`,
///    does nothing. The free was called at location `file`:`line`.

void dmalloc_free(void* ptr, const char* file, long line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings

    // NUll pointer
    if(ptr == NULL)
    {
        return;
    }
    // Catch pointers to memory blocks not in the heap
    if ((((uintptr_t) ptr) < global_stats.heap_min) || (((uintptr_t) ptr) > global_stats.heap_max))  // Pointer not in heap
    {
        fprintf(stderr, "MEMORY BUG: %s:%li: invalid free of pointer %p, not in heap\n", ((char*) file), ((long) line), ptr);
        exit(1);
    }
    // Catch invalid pointers in the heap
    // Get head of memory block
    header* head = (header*)(((uintptr_t) ptr) - sizeof(canary_value) - sizeof(header));
    if ((head->magic_number != MAGIC_NUMBER)) 
    {
        if (head->magic_number == FREE_NUMBER) // Already freed block
        {
            fprintf(stderr, "MEMORY BUG: %s:%li: invalid free of pointer %p, double free\n", ((char*) file), ((long) line), ptr);
        }
        else // Block was never allocated
        {
            fprintf(stderr, "MEMORY BUG: %s:%li: invalid free of pointer %p, not allocated\n", ((char*) file), ((long) line), ptr);
        }

        // Find originally-allocated memory block
        header* temp = global_list.head;
        while (temp != NULL)
        {
            // Get end of payload of that memory
            uintptr_t payload_start = ((uintptr_t) temp) + sizeof(canary_value) + sizeof(header);
            uintptr_t payload_end = payload_start + (temp->size);
            long org_line = temp->file_line;
            if (((uintptr_t) ptr) >= (payload_start) && ((uintptr_t) ptr) <= payload_end)
            {
                size_t block_size = ((uintptr_t) ptr) - payload_start;
                fprintf(stderr, "  %s:%li: %p is %zu bytes inside a %zu byte region allocated here\n", ((char*) file), org_line, ptr, block_size, temp->size);
            }
            temp = temp->next;
        }
        exit(1);
    }
    // Free valid memory block
    if (head->magic_number == MAGIC_NUMBER)
    {
        // Ensure no overflow or underflow
        size_t size = head->size;
        if (!(check_canary(ptr, size)))
        {
            fprintf(stderr, "MEMORY BUG: %s:%li: detected wild write during free of pointer %p\n", ((char*) file), ((long) line), ptr);
            exit(1);
        }
        // Number of active allocations
        global_stats.nactive --;
        // Update number of bytees in  active allocations
        global_stats.active_size = (global_stats.active_size - size);
        // Update magic number to 0xfreed
        head->magic_number = FREE_NUMBER;
        // Delete node from linked list
        list_pop(head);
        base_free(head);
        return;
    }
}


/// dmalloc_calloc(nmemb, sz, file, line)
///    Return a pointer to newly-allocated dynamic memory big enough to
///    hold an array of `nmemb` elements of `sz` bytes each. If `sz == 0`,
///    then must return a unique, newly-allocated pointer value. Returned
///    memory should be initialized to zero. The allocation request was at
///    location `file`:`line`.

void* dmalloc_calloc(size_t nmemb, size_t sz, const char* file, long line) {
    // Your code here (to fix test014).
    if (nmemb > (SIZE_MAX / sz)) // Detect integer overflow
    {
        global_stats.nfail ++;
        global_stats.fail_size = (nmemb * sz);
        return NULL;
    }
    void* ptr = dmalloc_malloc(nmemb * sz, file, line);
    if (ptr) {
        memset(ptr, 0, nmemb * sz);
    }
    // Check for overflow or underflow
    if (!(check_canary(ptr, (nmemb * sz))))
    {
        // Update dmalloc_statistics in the case of an overflow or underflow
        global_stats.nfail ++;
        global_stats.fail_size = (nmemb * sz);
        // Zero out rest of statistics
        global_stats.nactive --;
        global_stats.active_size = global_stats.active_size - (nmemb * sz);
        global_stats.ntotal --;
        global_stats.total_size = global_stats.total_size - (nmemb * sz);
        void* head = (((char*) ptr) - sizeof(canary_value) - (sizeof(header)));
        base_free(head);
        return NULL;
    }
    return ptr;
}


/// dmalloc_get_statistics(stats)
///    Store the current memory statistics in `*stats`.

void dmalloc_get_statistics(dmalloc_statistics* stats) {
    // Stub: set all statistics to enormous numbers
    memset(stats, 255, sizeof(dmalloc_statistics));
    // Your code here.
    stats->nactive = global_stats.nactive;
    stats->active_size = global_stats.active_size;
    stats->ntotal = global_stats.ntotal;
    stats->total_size = global_stats.total_size;
    stats->nfail = global_stats.nfail;
    stats->fail_size = global_stats.fail_size;
    stats->heap_min = global_stats.heap_min;
    stats->heap_max = global_stats.heap_max;
}


/// dmalloc_print_statistics()
///    Print the current memory statistics.

void dmalloc_print_statistics() {
    dmalloc_statistics stats;
    dmalloc_get_statistics(&stats);

    printf("alloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("alloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}


/// dmalloc_print_leak_report()
///    Print a report of all currently-active allocated blocks of dynamic
///    memory.

void dmalloc_print_leak_report() {
    header* ptr = global_list.head;
    while(ptr != NULL)
    {
        printf("LEAK CHECK: %s:%li: allocated object %p with size %zu\n", ptr->file_name, ptr->file_line, ptr->payload, ptr->size);
        ptr = ptr->next;
    }
}


/// dmalloc_print_heavy_hitter_report()
///    Print a report of heavily-used allocation locations.

void dmalloc_print_heavy_hitter_report() {
    // Sort array based on size
    qsort(hhitter_array, hhitter_count, sizeof(hitter_symbol), &comparator);
    for (size_t i = 0; i < hhitter_count; i++)
    {
        const char* file_name = hhitter_array[i].file;
        long file_line  = hhitter_array[i].line;
        size_t size = (hhitter_array[i].size + hhitter_array[i].eliminated_bytes);
        double percentage = (size / ((double)hhitter_total)) * 100;
        printf("HEAVY HITTER: %s:%li: %zu bytes (~%0.1lf%%)\n", file_name, file_line, size, percentage);
    }
}
