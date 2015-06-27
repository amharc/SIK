#include "event_heap.h"

#define PARENT(x) (((x) - 1)/2)
#define LEFT(x) (2 * (x) + 1)
#define RIGHT(x) (2 * (x) + 2)

struct heap_event {
    uint64_t when;
    void (*fun)(void*);
    void *data;
};

struct heap_event *heap;
size_t heap_size, heap_capacity;

pthread_mutex_t mutex;
pthread_cond_t cond;

void heap_swap(size_t i, size_t j) {
    struct heap_event tmp = heap[i];
    heap[i] = heap[j];
    heap[j] = tmp;
}

void heap_down() {
    size_t i = 0, j = 0;

    do {
        i = j;
        if(LEFT(i) < heap_size && heap[LEFT(i)].when < heap[j].when)
            j = LEFT(i);
        if(RIGHT(i) < heap_size && heap[RIGHT(i)].when < heap[j].when)
            j = RIGHT(i);
        heap_swap(i, j);
    } while(i != j);
}

void heap_up(size_t i) {
    while(i > 0 && heap[PARENT(i)].when > heap[i].when) {
        heap_swap(i, PARENT(i));
        i = PARENT(i);
    }
}

void heap_init() {
    int r;

    r = pthread_mutex_init(&mutex, NULL);
    if(r != 0)
        die("Unable to create the heap mutex: %d: %s", r, strerror(r));

    
    r = pthread_cond_init(&cond, NULL);
    if(r != 0)
        die("Unable to create the heap condition variable: %d: %s", r, strerror(r));
}

void heap_push(uint64_t when, void (*fun)(void*), void *data) {
    if(heap_size == heap_capacity) {
        heap_capacity = 2 * heap_capacity + 1;
        heap = realloc(heap, heap_capacity * sizeof(struct heap_event));
        if(!heap)
            die("Unable to allocate memory");
    }
    
    int r;
    r = pthread_mutex_lock(&mutex);
    if(r != 0)
        die("Unable to lock the heap mutex: %d", r);

    uint64_t last = UINT64_MAX;
    if(heap_size > 0)
        last = heap[0].when;

    heap[heap_size].when = when;
    heap[heap_size].fun = fun;
    heap[heap_size].data = data;

    ++heap_size;
    heap_up(heap_size - 1);

    if(heap_size == 1 || heap[0].when < last) {
        r = pthread_cond_signal(&cond);
        if(r != 0)
            die("Unable to signal on the heap condition variable: %d: %s", r, strerror(r));
    }

    r = pthread_mutex_unlock(&mutex);
    if(r != 0)
        die("Unable to unlock the heap mutex: %d (%s)", r, strerror(r));
}

_Noreturn void* start_heap_runner(void *ignored) {
    (void) ignored;

    int r;
    while(true) {
        r = pthread_mutex_lock(&mutex);
        if(r != 0)
            die("Unable to lock the heap mutex: %d: %s", r, strerror(r));

        while(heap_size == 0) {
           r = pthread_cond_wait(&cond, &mutex);
           if(r != 0)
               die("Unable to wait on the heap condition variable: %d: %s", r, strerror(r));
        }

        while(heap[0].when > gettime()) {
            struct timespec tv = {
                .tv_sec = heap[0].when / (1000 * 1000),
                .tv_nsec = (heap[0].when % (1000 * 1000)) * 1000
            };

            r = pthread_cond_timedwait(&cond, &mutex, &tv);
            if(r != 0 && r != ETIMEDOUT)
                die("Unable to wait (with a timeout) on the heap condition variable: %d: %s", r, strerror(r));
        }

        void (*fun)(void*) = heap[0].fun;
        void* data = heap[0].data;

        heap_size--;
        heap_swap(0, heap_size);
        heap_down();

        r = pthread_mutex_unlock(&mutex);
        if(r != 0)
            die("Unable to unlock the heap mutex: %d: %s", r, strerror(r));

        fun(data);
    }
}
