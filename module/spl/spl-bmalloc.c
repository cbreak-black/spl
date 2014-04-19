/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * Copyright 2014 Brendon Humphrey (brendon.humphrey@mac.com)
 
 * CDDL HEADER END
 */

#ifdef _KERNEL
#define IN_KERNEL 1
#else
#undef IN_KERNEL
#endif

#include <stdint.h>
#include <string.h>

#ifdef IN_KERNEL
    #include <sys/list.h>
#else
    #include <stdlib.h>
    #include <sys/time.h>
    #include <stdio.h>
    #include "list.h"
    #include "pthread.h"
#endif

// ============================================================================================
// Base Types
// ============================================================================================

typedef uint64_t sa_size_t;
typedef uint8_t sa_byte_t;
typedef uint8_t sa_bool_t;
typedef uint64_t sa_hrtime_t;
typedef uint32_t large_offset_t;
typedef uint16_t small_offset_t;

#ifdef IN_KERNEL
typedef kmutex_t osif_mutex;
#else
typedef pthread_mutex_t osif_mutex;
#endif

#define SA_TRUE (sa_bool_t)1;
#define SA_FALSE (sa_bool_t)0;

#define SA_NSEC_PER_SEC  1000000000;
#define SA_NSEC_PER_USEC  1000;

typedef enum {SMALL_BLOCK, LARGE_BLOCK} block_size_t;

typedef struct {
    sa_hrtime_t time_freed;
    list_node_t memory_block_link_node;
} memory_block_t;

typedef struct {
    sa_size_t  count;
    list_t     blocks;
    osif_mutex mutex;
} memory_block_list_t;

typedef struct {
    sa_size_t           amount_allocated;
    memory_block_list_t large_blocks;
    memory_block_list_t small_blocks;
} memory_pool_t;

typedef struct small_allocatable_row {
    small_offset_t slice_offset;
    small_offset_t next_offset;
    // FIXME - these should not be needed
    // and are present because of an issue
    // somewhere in the small slice
    // path.
    small_offset_t pad1;
    small_offset_t pad2;
} small_allocatable_row_t;

typedef struct allocatable_row {
    large_offset_t slice_offset;
    large_offset_t next_offset;
} allocatable_row_t;

typedef union {
    small_allocatable_row_t* small;
    allocatable_row_t* large;
} free_list_t;

// This stucture describes the header of a slice_t.
typedef struct slice {
    free_list_t  free_list;
    sa_size_t    allocation_size;
    sa_size_t    num_allocations;
    sa_size_t    alloc_count;
    sa_hrtime_t  time_freed;
    block_size_t block_size;
    list_node_t  slice_link_node;
} slice_t;

typedef struct {
    list_t       free;
    list_t       partial;
    list_t       full;
    block_size_t block_size;
    sa_size_t    max_alloc_size;        /*  Max alloc size for slice */
    sa_size_t    num_allocs_per_buffer; /* Number of rows to be allocated in the Slices */
    osif_mutex   mutex;
} slice_allocator_t;

// ============================================================================================
// Constants
// ============================================================================================

// Low water mark for amount of memory to be retained in the block lists
// when garbage collecting.
const sa_size_t RETAIN_MEMORY_SIZE = 10 * 1024 * 1024;   // bytes

// Block size and free block count for the large_blocks list
const sa_size_t LARGE_BLOCK_SIZE = (512 * 1024) + 8192;  // bytes
const sa_size_t LARGE_FREE_MEMORY_BLOCK_COUNT =
RETAIN_MEMORY_SIZE / LARGE_BLOCK_SIZE;

// Block size and free block count for the small_blocks list
const sa_size_t SMALL_BLOCK_SIZE = 64 * 1024;            // bytes
const sa_size_t SMALL_FREE_MEMORY_BLOCK_COUNT =
RETAIN_MEMORY_SIZE / SMALL_BLOCK_SIZE;

// Length of time that memory will be retained in the block_lists
// before returning to the underlying allocator.
const sa_hrtime_t MAX_FREE_MEM_AGE = 60 * SA_NSEC_PER_SEC;     // 60 seconds

// Slices of memory that have no allocations in them will
// be returned to the memory pool for use by other slice
// allocators SA_MAX_FREEMEM_AGE nanoseconds after
// the last allocation from the slice is freed.
const sa_hrtime_t SA_MAX_FREE_MEM_AGE = 30 * SA_NSEC_PER_SEC;

// These buckets of up to SMALL_ALLOCATOR_MAX_SIZE are all
// allocated from more space efficient small allocation slices.
const sa_size_t SMALL_ALLOCATOR_MAX_SIZE = 0; //2048; 

// Sizes of various slices that are used by zfs
// This table started out as a naive ^2 table,
// and more slice sizes were added as a result
// of instrumenting allocations. In terms of allocator
// efficiency its beneficial to closely match allocation
// requests to slice size.

const sa_size_t ALLOCATOR_SLICE_SIZES[] = {
    16,
    32,
    48,
    64,
    80,
    96,
    128,
    144,
    160,
    196,
    224,
    256,
    320,
    384,
    448,
    512,
    856,
    944,
    1024,
    1920,
    2048,
    4096,
    6144,
    7168,
    8192,
    12288,
    16384,
    32768,
    36864,
    40960,
    49152,
    57344,
    65536,
    81920,
    90112,
    98304,
    106496,
    114688,
    122880,
    131072
};

const long NUM_ALLOCATORS = sizeof(ALLOCATOR_SLICE_SIZES)/sizeof(sa_size_t);

// ============================================================================================
// Variables
// ============================================================================================

// Blocks of memory allocated from the underlying allocator, but not
// yet used as a slice by one of the slice allocators.
memory_pool_t pool;

// Collection of slice allocators
slice_allocator_t* allocators = 0;

// Allocation size to slice allocator lookup table
slice_allocator_t** allocator_lookup_table = 0;

// Indicates if the allocator has been initialised.
int initalised = 0;

// ============================================================================================
// OS Compatability interface
// ============================================================================================

#ifdef IN_KERNEL

extern vm_map_t kernel_map;

extern kern_return_t kernel_memory_allocate(vm_map_t       map,
                                            vm_offset_t   *addrp,
                                            vm_size_t      size,
                                            vm_offset_t    mask,
                                            int            flags);

extern void kmem_free(vm_map_t map, vm_offset_t addr, vm_size_t size);

extern int              vm_pool_low(void);

#endif

static inline void* osif_malloc(sa_size_t size)
{
#ifdef IN_KERNEL
    
    void *tr;
    kern_return_t kr;
    
    kr = kernel_memory_allocate(
                                kernel_map,
                                &tr,
                                size,
                                0,
                                0);
    
    if (kr == KERN_SUCCESS) {
        return tr;
    } else {
        return NULL;
    }
    
#else
    
    return (void*)malloc(size);
    
#endif
}

static inline void osif_free(void* buf, sa_size_t size)
{
#ifdef IN_KERNEL
    kmem_free(kernel_map, buf, size);
#else
    free(buf);
#endif
}

static inline void osif_zero_memory(void* buf, sa_size_t size)
{
#ifdef IN_KERNEL
    bzero(buf, size);
#else
    memset(buf, 0, size);
#endif
}

static inline void osif_mutex_init(osif_mutex* mutex)
{
#ifdef IN_KERNEL
    mutex_init(mutex, "bmalloc", MUTEX_DEFAULT, NULL);
#else
    pthread_mutex_init(mutex, 0);
#endif
}

static inline void osif_mutex_enter(osif_mutex* mutex)
{
#ifdef IN_KERNEL
    mutex_enter(mutex);
#else
    pthread_mutex_lock(mutex);
#endif
}

static inline void osif_mutex_exit(osif_mutex* mutex)
{
#ifdef IN_KERNEL
    mutex_exit(mutex);
#else
    pthread_mutex_unlock(mutex);
#endif
}

static inline void osif_mutex_destroy(osif_mutex* mutex)
{
#ifdef IN_KERNEL
    mutex_destroy(mutex);
#else
    pthread_mutex_destroy(mutex);
#endif
}

static inline  int osif_memory_pressure()
{
#ifdef IN_KERNEL
    return vm_pool_low();
#else
    return 0;
#endif
}

static inline sa_hrtime_t osif_gethrtime()
{
#ifdef IN_KERNEL
    return gethrtime();
#else
    struct timeval t;
    struct timezone zone;
    
    gettimeofday(&t, &zone);
    
    return (t.tv_sec * 1000000000) + (t.tv_usec * 1000);
#endif
}

// ============================================================================================
// Memory Pool
// ============================================================================================

void memory_pool_block_list_init(memory_block_list_t* list)
{
    list->count = 0;
    osif_mutex_init(&list->mutex);
    list_create(&list->blocks, sizeof(memory_block_t),
                offsetof(memory_block_t, memory_block_link_node));
}

void memory_pool_block_list_fini(memory_block_list_t* list)
{
    list_destroy(&list->blocks);
    // FIXME - seems to panic
    // osif_mutex_destroy(list->mutex);
}

void memory_pool_init()
{
    pool.amount_allocated = 0;
    memory_pool_block_list_init(&pool.large_blocks);
    memory_pool_block_list_init(&pool.small_blocks);
}

memory_block_t* memory_pool_create_block(block_size_t size)
{
    sa_size_t allocation_size = (size == SMALL_BLOCK) ? SMALL_BLOCK_SIZE : LARGE_BLOCK_SIZE;
    
    pool.amount_allocated += allocation_size;
    memory_block_t* block = (memory_block_t*)osif_malloc(allocation_size);
    return block;
}

void memory_pool_destroy_block(block_size_t size, memory_block_t* block)
{
    sa_size_t allocation_size = (size == SMALL_BLOCK) ? SMALL_BLOCK_SIZE : LARGE_BLOCK_SIZE;
    
    pool.amount_allocated -= allocation_size;
    osif_free((void*)block, allocation_size);
}

sa_size_t memory_pool_claim_size(block_size_t size)
{
    return (size == SMALL_BLOCK) ? SMALL_BLOCK_SIZE : LARGE_BLOCK_SIZE;
}

void memory_pool_release_memory_from(block_size_t size, memory_block_list_t* list)
{
    osif_mutex_enter(&list->mutex);
    
    while(!list_is_empty(&list->blocks)) {
        memory_block_t* block = list_head(&list->blocks);
        list_remove_head(&list->blocks);
        list->count--;
        
        memory_pool_destroy_block(size, block);
    }
    
    osif_mutex_exit(&list->mutex);
}

void memory_pool_release_memory()
{
    memory_pool_release_memory_from(LARGE_BLOCK, &pool.large_blocks);
    memory_pool_release_memory_from(SMALL_BLOCK, &pool.small_blocks);
}

void memory_pool_garbage_collect_from(block_size_t size, memory_block_list_t* list)
{
    osif_mutex_enter(&list->mutex);
    
    sa_hrtime_t stale_time = osif_gethrtime() - MAX_FREE_MEM_AGE;
    sa_size_t num_blocks_to_retain = (size == SMALL_BLOCK) ? SMALL_FREE_MEMORY_BLOCK_COUNT : LARGE_FREE_MEMORY_BLOCK_COUNT;
    
    int done = 0;
    
    do {
        if (list->count <= num_blocks_to_retain) {
            done = 1;
        } else {
            memory_block_t* block = list_tail(&list->blocks);
            if(block->time_freed <= stale_time) {
                list_remove_tail(&list->blocks);
                list->count--;
                memory_pool_destroy_block(size, block);
            } else {
                done = 1;
            }
        }
    } while (!done);
    
    osif_mutex_exit(&list->mutex);
}

void memory_pool_garbage_collect()
{
    memory_pool_garbage_collect_from(LARGE_BLOCK, &pool.large_blocks);
    memory_pool_garbage_collect_from(SMALL_BLOCK, &pool.small_blocks);
}

void* memory_pool_claim(block_size_t size)
{
    memory_block_t* block = 0;
    memory_block_list_t* list =
    (size == SMALL_BLOCK) ? &pool.small_blocks : &pool.large_blocks;
    
    osif_mutex_enter(&list->mutex);
    
    if (!list_is_empty(&list->blocks)) {
        block = list_tail(&list->blocks);
        list_remove_tail(&list->blocks);
        list->count--;
    } else {
        block = memory_pool_create_block(size);
    }
    
    osif_mutex_exit(&list->mutex);
    
    return (void*)block;
}

void memory_pool_return(block_size_t size, void* memory)
{
    memory_block_t* block = (memory_block_t*)(memory);
    memory_block_list_t* list =
    (size == SMALL_BLOCK) ? &pool.small_blocks : &pool.large_blocks;
    
    list_link_init(&block->memory_block_link_node);
    block->time_freed = osif_gethrtime();
    
    osif_mutex_enter(&list->mutex);
    list_insert_head(&list->blocks, block);
    list->count++;
    osif_mutex_exit(&list->mutex);
}

void memory_pool_fini()
{
    memory_pool_release_memory();
    memory_pool_block_list_fini(&pool.large_blocks);
    memory_pool_block_list_fini(&pool.small_blocks);
}

// ============================================================================================
// Slice
// ============================================================================================

sa_size_t slice_row_size_bytes(slice_t* slice)
{
    if (slice->block_size == SMALL_BLOCK) {
        return slice->allocation_size + sizeof(small_allocatable_row_t);
    } else {
        return slice->allocation_size + sizeof(allocatable_row_t);
    }
}

static inline void set_slice_small(small_allocatable_row_t* row, slice_t* slice)
{
    row->slice_offset = (small_offset_t)((sa_byte_t*)(&(row->slice_offset)) - (sa_byte_t*)(slice));
}

static inline slice_t* get_slice_small(small_allocatable_row_t* row)
{
    return (slice_t*)((sa_byte_t*)(&row->slice_offset) - row->slice_offset);
}

static inline void set_slice(allocatable_row_t* row, slice_t* slice)
{
    row->slice_offset = (large_offset_t)((sa_byte_t*)(&(row->slice_offset)) - (sa_byte_t*)(slice));
}

static inline slice_t* get_slice(allocatable_row_t* row)
{
    return (slice_t*)((sa_byte_t*)(&row->slice_offset) - row->slice_offset);
}

static inline void set_next_small(small_allocatable_row_t* row, slice_t* base_addr, small_allocatable_row_t* next)
{
    if(!next) {
        row->next_offset = 0;
    } else {
        row->next_offset = (small_offset_t)((sa_byte_t*)(next) - (sa_byte_t*)(base_addr));
    }
}

static inline small_allocatable_row_t* get_next_small(small_allocatable_row_t* row, slice_t* base_addr)
{
    if(row->next_offset > 0) {
        return (small_allocatable_row_t*)((sa_byte_t*)(base_addr) + row->next_offset);
    } else {
        return 0;
    }
}

static inline void set_next(allocatable_row_t* row, slice_t* base_addr, allocatable_row_t* next)
{
    if(!next) {
        row->next_offset = 0;
    } else {
        row->next_offset = (large_offset_t)((sa_byte_t*)(next) - (sa_byte_t*)(base_addr));
    }
}

static inline allocatable_row_t* get_next(allocatable_row_t* row, slice_t* base_addr)
{
    if(row->next_offset > 0) {
        return (allocatable_row_t*)((sa_byte_t*)(base_addr) + row->next_offset);
    } else {
        return 0;
    }
}

small_allocatable_row_t* slice_get_row_address_small(slice_t* slice, int index)
{
    sa_byte_t* p = (sa_byte_t*)slice;
    p = p + sizeof(slice_t) + (index * slice_row_size_bytes(slice));
    
    return (small_allocatable_row_t*)(p);
}

allocatable_row_t* slice_get_row_address(slice_t* slice, int index)
{
    sa_byte_t* p = (sa_byte_t*)slice;
    p = p + sizeof(slice_t) + (index * slice_row_size_bytes(slice));
    
    return (allocatable_row_t*)(p);
}

void slice_insert_free_row_small(slice_t* slice, small_allocatable_row_t* row)
{
    small_allocatable_row_t* curr_free = slice->free_list.small;
    slice->free_list.small = row;
    set_next_small(slice->free_list.small, slice, curr_free);
}

void slice_insert_free_row(slice_t* slice, allocatable_row_t* row)
{
    allocatable_row_t* curr_free = slice->free_list.large;
    slice->free_list.large = row;
    set_next(slice->free_list.large, slice, curr_free);
}

small_allocatable_row_t* slice_get_row_small(slice_t* slice)
{
    if (slice->free_list.small == 0) {
        return 0;
    } else {
        small_allocatable_row_t* row = slice->free_list.small;
        slice->free_list.small = get_next_small(row, slice);
        return row;
    }
}

allocatable_row_t* slice_get_row(slice_t* slice)
{
    if (slice->free_list.large == 0) {
        return 0;
    } else {
        allocatable_row_t* row = slice->free_list.large;
        slice->free_list.large = get_next(row, slice);
        return row;
    }
}

void slice_init(slice_t* slice,
                block_size_t size,
                sa_size_t allocation_size,
                sa_size_t num_allocations)
{
    // Copy parameters
    osif_zero_memory(slice, sizeof(slice_t));
    list_link_init(&slice->slice_link_node);
    slice->num_allocations = num_allocations;
    slice->allocation_size = allocation_size;
    slice->block_size = size;
    
    // Add all rows to the free list. Set pointers to the slice.
    if(slice->block_size == SMALL_BLOCK) {
        for(int i=0; i < slice->num_allocations; i++) {
            small_allocatable_row_t* row = slice_get_row_address_small(slice, i);
            set_slice_small(row, slice);
            slice_insert_free_row_small(slice, row);
        }
    } else {
        for(int i=0; i < slice->num_allocations; i++) {
            allocatable_row_t* row = slice_get_row_address(slice, i);
            set_slice(row, slice);
            slice_insert_free_row(slice, row);
        }
    }
}

void slice_fini(slice_t* slice)
{
}

static inline int slice_is_full(slice_t* slice)
{
    if (slice->block_size == SMALL_BLOCK) {
        return (slice->free_list.small == 0);
    } else {
        return (slice->free_list.large == 0);
    }
}

static inline int slice_is_empty(slice_t* slice)
{
    return (slice->alloc_count == 0);
}

void* slice_alloc(slice_t* slice, sa_size_t size)
{
    if(slice->block_size == SMALL_BLOCK) {
        small_allocatable_row_t* row = slice_get_row_small(slice);
        if(row) {
            slice->alloc_count++;
            row++;
            return (void*)(row);
        } else {
            return (void*)0;
        }
    } else {
        allocatable_row_t* row = slice_get_row(slice);
        if(row) {
            slice->alloc_count++;
            row++;
            return (void*)(row);
        } else {
            return (void*)0;
        }
    }
}

void slice_free(slice_t* slice, void* buf)
{
    if (slice->block_size == SMALL_BLOCK) {
        slice->alloc_count--;
        small_allocatable_row_t* row = (small_allocatable_row_t*)(buf);
        row--;
        slice_insert_free_row_small(slice, row);
    } else {
        slice->alloc_count--;
        allocatable_row_t* row = (allocatable_row_t*)(buf);
        row--;
        slice_insert_free_row(slice, row);
    }
}

slice_t* slice_get_slice_small(void* buf)
{
    small_allocatable_row_t* row = (small_allocatable_row_t*)(buf);
    row--;
    return get_slice_small(row);
}

slice_t* slice_get_slice(void* buf)
{
    allocatable_row_t* row = (allocatable_row_t*)(buf);
    row--;
    return get_slice(row);
}

// ============================================================================================
// Slice Allocator
// ============================================================================================

static inline slice_t* slice_allocator_create_slice(slice_allocator_t* sa)
{
    slice_t* slice = (slice_t*)memory_pool_claim(sa->block_size);
    slice_init(slice, sa->block_size, sa->max_alloc_size, sa->num_allocs_per_buffer);
    return slice;
}

static inline void slice_allocator_destroy_slice(slice_allocator_t* sa, slice_t* slice)
{
    memory_pool_return(sa->block_size, slice);
}

void slice_allocator_empty_list(slice_allocator_t* sa, list_t* list)
{
    while(!list_is_empty(list)) {
        slice_t* slice = list_head(list);
        list_remove_head(list);
        slice_allocator_destroy_slice(sa, slice);
    }
}

void slice_allocator_init(slice_allocator_t* sa, sa_size_t max_alloc_size)
{
    osif_zero_memory(sa, sizeof(slice_allocator_t));
    
    // Create lists for tracking the state of the slices as memory is allocated
    list_create(&sa->free, sizeof(slice_t), offsetof(slice_t, slice_link_node));
    list_create(&sa->partial, sizeof(slice_t), offsetof(slice_t, slice_link_node));
    list_create(&sa->full, sizeof(slice_t), offsetof(slice_t, slice_link_node));
    
    // Set Block size based om allocation size
    sa->block_size =
    (max_alloc_size <= SMALL_ALLOCATOR_MAX_SIZE) ? SMALL_BLOCK : LARGE_BLOCK;
    
    sa->max_alloc_size = max_alloc_size;
    
    // Calculate the number of allocations that will fit into a standard
    // memory_pool block
    if (sa->block_size == SMALL_BLOCK) {
        sa->num_allocs_per_buffer = (memory_pool_claim_size(SMALL_BLOCK) - sizeof(slice_t))/(sizeof(small_allocatable_row_t) + max_alloc_size);
    } else {
        sa->num_allocs_per_buffer = (memory_pool_claim_size(LARGE_BLOCK) - sizeof(slice_t))/(sizeof(allocatable_row_t) + max_alloc_size);
    }
    
    osif_mutex_init(&sa->mutex);
}

void slice_allocator_fini(slice_allocator_t* sa)
{
    slice_allocator_empty_list(sa, &sa->free);
    slice_allocator_empty_list(sa, &sa->partial);
    slice_allocator_empty_list(sa, &sa->full);
    
    list_destroy(&sa->free);
    list_destroy(&sa->partial);
    list_destroy(&sa->full);
}

sa_size_t slice_allocator_get_allocation_size(slice_allocator_t* sa)
{
    return sa->max_alloc_size;
}

void* slice_allocator_alloc(slice_allocator_t* sa, sa_size_t size)
{
    slice_t* slice = 0;
    
    osif_mutex_enter(&sa->mutex);
    
    // Locate a slice with residual capacity, first check for a partially
    // full slice, use some more of its capacity. Next, look to see if we
    // have a ready to go empty slice. If not finally go to underlying
    // allocator for a new slice.
    if(!list_is_empty(&sa->partial)) {
        slice = list_head(&sa->partial);
    } else if (!list_is_empty(&sa->free)) {
        slice = list_tail(&sa->free);
        list_remove_tail(&sa->free);
        list_insert_head(&sa->partial, slice);
    } else {
        slice = slice_allocator_create_slice(sa);
        list_insert_head(&sa->partial, slice);
    }
    
    // FIXME: we might crash here if slice_allocator_create_slice returns null.
    
    // Grab memory from the slice
    void *p = slice_alloc(slice, size);
    
    // Check to see if the slice buffer has become
    // full. If it has, then move it into the
    // full list so that we no longer keep
    // trying to allocate from it.
    if(slice_is_full(slice)) {
        list_remove(&sa->partial, slice);
        list_insert_head(&sa->full, slice);
    }
    
    osif_mutex_exit(&sa->mutex);
    
    return p;
}

void slice_allocator_free(slice_allocator_t* sa, void* buf)
{
    osif_mutex_enter(&sa->mutex);
    
    // Locate the slice buffer that the allocation lives within
    slice_t* slice;
    if (sa->block_size == SMALL_BLOCK) {
        slice = slice_get_slice_small(buf);
    } else {
        slice = slice_get_slice(buf);
    }
    
    // If the slice was previously full remove it from the free list
    // and place in the available list
    if(slice_is_full(slice)) {
        list_remove(&sa->full, slice);
        list_insert_head(&sa->partial, slice);
    }
    
    slice_free(slice, buf);
    
    if(slice_is_empty(slice)) {
        list_remove(&sa->partial, slice);
        slice->time_freed = osif_gethrtime();
        list_insert_head(&sa->free, slice);
    }
    
    osif_mutex_exit(&sa->mutex);
}

void slice_allocator_release_memory(slice_allocator_t* sa)
{
    osif_mutex_enter(&sa->mutex);
    slice_allocator_empty_list(sa, &sa->free);
    osif_mutex_exit(&sa->mutex);
}

void slice_allocator_garbage_collect(slice_allocator_t* sa)
{
    osif_mutex_enter(&sa->mutex);
    
    sa_hrtime_t stale_time = osif_gethrtime() - SA_MAX_FREE_MEM_AGE;
    
    int done = 0;
    
    do {
        if (!list_is_empty(&sa->free)) {
            slice_t* slice = list_tail(&sa->free);
            if(slice->time_freed <= stale_time) {
                list_remove_tail(&sa->free);
                slice_allocator_destroy_slice(sa, slice);
            } else {
                done = 1;
            }
        } else {
            done = 1;
        }
    } while (!done);
    
    osif_mutex_exit(&sa->mutex);
}

// ============================================================================================
// Public Interface
// ============================================================================================

static inline sa_size_t bmalloc_allocator_array_size()
{
    return NUM_ALLOCATORS * sizeof(slice_allocator_t);
}

slice_allocator_t* bmalloc_allocator_for_size(sa_size_t size)
{
    for(int i=0; i<NUM_ALLOCATORS; i++) {
      if (slice_allocator_get_allocation_size(&allocators[i]) >= size) {
        return &allocators[i];
      }
    }
    
    return (void*)0;
}

static inline sa_size_t bmalloc_allocator_lookup_table_size(sa_size_t max_allocation_size)
{
    return max_allocation_size * sizeof(slice_allocator_t*);
}

void bmalloc_init()
{
    printf("[SPL] bmalloc slice allocator initialised\n");

    sa_size_t max_allocation_size = ALLOCATOR_SLICE_SIZES[NUM_ALLOCATORS - 1];

    // Initialise the memory pool
    memory_pool_init();
    
    // Create the slice allocators
    sa_size_t array_size = NUM_ALLOCATORS * sizeof(slice_allocator_t);
    allocators = (slice_allocator_t*)osif_malloc(array_size);
    osif_zero_memory(allocators, array_size);
    
    for(int i=0; i<NUM_ALLOCATORS; i++) {
        slice_allocator_init(&allocators[i], ALLOCATOR_SLICE_SIZES[i]);
    }
    
    // Create the allocator lookup array
    allocator_lookup_table = osif_malloc(bmalloc_allocator_lookup_table_size(ALLOCATOR_SLICE_SIZES[NUM_ALLOCATORS - 1]));
    
    for(int i=1; i<=max_allocation_size; i++) {
        allocator_lookup_table[i-1] = bmalloc_allocator_for_size(i);
    }
    
    initalised = 1;
}

void bmalloc_fini()
{
    // Clean up the allocators
    for(int i=0; i<NUM_ALLOCATORS; i++) {
        slice_allocator_fini(&allocators[i]);
    }
    
    // Free local resources
    osif_free(allocators, bmalloc_allocator_array_size());
    osif_free(allocator_lookup_table,
              bmalloc_allocator_lookup_table_size(ALLOCATOR_SLICE_SIZES[NUM_ALLOCATORS - 1]));
    
    // Clean up the memory pool
    memory_pool_fini();
    
    initalised = 0;
}

void* bmalloc(sa_size_t size)
{
    void* p = 0;
    
    if(size <= ALLOCATOR_SLICE_SIZES[NUM_ALLOCATORS - 1]) {
        p = slice_allocator_alloc(allocator_lookup_table[size-1], size);
    } else {
        p = osif_malloc(size);
    }
    
    return p;
}

void bfree(void* buf, sa_size_t size)
{
    if(size <= ALLOCATOR_SLICE_SIZES[NUM_ALLOCATORS - 1]) {
        slice_allocator_free(allocator_lookup_table[size-1], buf);
    } else {
        osif_free(buf, size);
    }
}

void bmalloc_release_memory()
{
    for(int i=0; i<NUM_ALLOCATORS; i++) {
        slice_allocator_release_memory(&allocators[i]);
    }

    memory_pool_release_memory();
}

void bmalloc_garbage_collect()
{
    for(int i=0; i<NUM_ALLOCATORS; i++) {
        slice_allocator_garbage_collect(&allocators[i]);
    }

    memory_pool_garbage_collect();
}
