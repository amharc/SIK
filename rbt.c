#include "rbt.h"
#include "common.h"

struct rb_node {
    struct host data;
    struct rb_node *left, *right;
    bool red;
};

static struct rb_node *rb_root;
static size_t rb_counter;
static pthread_rwlock_t rwlock;

static struct rb_node *make(const struct host *data) {
    struct rb_node *node = calloc(1, sizeof(struct rb_node));
    if(!node)
        die("Unable to allocate memory for a red-black tree node");

    node->data = *data;
    node->red = true;
    return node;
}

struct host* rb_find(const struct in_addr *addr) {
    struct rb_node *node = rb_root;
    while(node) {
        int r = memcmp(addr, &node->data.addr, sizeof(struct in_addr));
        if(r < 0)
            node = node->left;
        else if(r > 0)
            node = node->right;
        else
            return &node->data;
    }
    return NULL;
}

static inline bool is_red(const struct rb_node *node) {
    return node && node->red;
}

static inline struct rb_node* rotate_left(struct rb_node *node) {
    struct rb_node *aux = node->right;
    node->right = aux->left;
    aux->left = node;
    aux->red = node->red;
    node->red = true;
    return aux;
}

static inline struct rb_node* rotate_right(struct rb_node *node) {
    struct rb_node *aux = node->left;
    node->left = aux->right;
    aux->right = node;
    aux->red = node->red;
    node->red = true;
    return aux;
}

static inline void colour_flip(struct rb_node *node) {
    node->red = !node->red;
    node->left->red = !node->left->red;
    node->right->red = !node->right->red;
}

static inline struct rb_node* move_red_right(struct rb_node *node) {
    colour_flip(node);

    if(is_red(node->left->left)) {
        node = rotate_right(node);
        colour_flip(node);
    }

    return node;
}

static inline struct rb_node* move_red_left(struct rb_node *node) {
    colour_flip(node);

    if(is_red(node->right->left)) {
        node->right = rotate_right(node->right);
        node = rotate_left(node);
        colour_flip(node);
    }

    return node;
}

static struct rb_node* fixup(struct rb_node *node) {
    if(is_red(node->right))
        node = rotate_left(node);
    
    if(is_red(node->left) && is_red(node->left->left))
        node = rotate_right(node);
    
    if(is_red(node->left) && is_red(node->right))
        colour_flip(node);

    return node;
}

static struct rb_node* unlink_min(struct rb_node *node) {
    if(!node->left)
        return NULL;

    if(!is_red(node->left) && !is_red(node->left->left))
        node = move_red_left(node);

    node->left = unlink_min(node->left);

    return fixup(node);
}

static struct rb_node* insert(struct rb_node *node, const struct host *host) {
    if(!node)
        return make(host);

    int r = memcmp(&host->addr, &node->data.addr, sizeof(struct in_addr));
    assert(r != 0);

    if(r < 0)
        node->left = insert(node->left, host);
    else
        node->right = insert(node->right, host);

    return fixup(node);
}

static inline struct rb_node* min_node(struct rb_node *node) {
    while(node->left)
        node = node->left;

    return node;
}

static struct rb_node* delete(struct rb_node *node, const struct in_addr *addr) {
    int r = memcmp(addr, &node->data.addr, sizeof(struct in_addr));
    if(r < 0) {
        if(!is_red(node->left) && !is_red(node->left->left))
            node = move_red_left(node);
        node->left = delete(node->left, addr);
    }
    else {
        if(is_red(node->left))
            node = rotate_right(node);

        if(r == 0 && !node->right) {
            free(node);
            return NULL;
        }

        if(!is_red(node->right) && !is_red(node->right->left))
            node = move_red_right(node);

        if(r == 0) {
            struct rb_node *min = min_node(node->right);
            node->data = min->data;
            node->right = unlink_min(node->right);
            free(min);
        }
        else
            node->right = delete(node->right, addr);
    }
    
    return fixup(node);
}

static void foreach(struct rb_node *node, void (*fun)(struct host*, void*), void *data) {
    if(node) {
        foreach(node->left, fun, data);
        fun(&node->data, data);
        foreach(node->right, fun, data);
    }
}

void rb_init(void) {
    int r;
    if(0 != (r = pthread_rwlock_init(&rwlock, NULL)))
        die("Unable to create the read-write lock pertaining to the red-black tree: %d (%s)", r, strerror(r));
}

void rb_read_lock(void) {
    int r;
    if(0 != (r = pthread_rwlock_rdlock(&rwlock)))
        die("Unable to apply a read lock to the read-write lock pertaining to the red-black tree: %d (%s)", r, strerror(r));
}

void rb_write_lock(void) {
    int r;
    if(0 != (r = pthread_rwlock_rdlock(&rwlock)))
        die("Unable to apply a read lock to the read-write lock pertaining to the red-black tree: %d (%s)", r, strerror(r));
}

void rb_unlock(void) {
    int r;
    if(0 != (r = pthread_rwlock_unlock(&rwlock)))
        die("Unable to release a lock held on the read-write lock pertaining to the red-black tree: %d (%s)", r, strerror(r));
}

void rb_delete(const struct in_addr *addr) {
    rb_root = delete(rb_root, addr);
    rb_root->red = false;
    rb_counter--;
}


void rb_insert(const struct host *host) {
    rb_root = insert(rb_root, host);
    rb_root->red = false;
    rb_counter++;
}

void rb_foreach(void (*fun)(struct host*, void*), void *data) {
    foreach(rb_root, fun, data);
}

size_t rb_count(void) {
    return rb_counter;
}
