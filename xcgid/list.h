#include <stdbool.h>

struct list_head {
    struct list_head *next, *prev;
};

#define container_of(ptr, type, member) ({              \
    const typeof(((type *)0)->member) *__mptr = (ptr);    \
    (type *)((char *)__mptr - offsetof(type, member));})

#define list_entry(ptr, type, member) \
    container_of(ptr, type, member)

#define list_first_entry(ptr, type, member) \
    list_entry((ptr)->next, type, member)

#define LIST_HEAD_INIT(name) { &name, &name }

static inline void INIT_LIST_HEAD(struct list_head *head) {
        head->next = head;
        head->prev = head;
}

static inline bool list_empty(const struct list_head *head) {
    return head->next == head;
}

static inline void __list_add(struct list_head *_new, struct list_head *prev, struct list_head *next) {
    next->prev = _new;
    _new->next = next;
    _new->prev = prev;
    prev->next = _new;
}

static inline void list_add_tail(struct list_head *val, struct list_head *head) {
    __list_add(val, head->prev, head);
}

static inline void __list_del(struct list_head *prev, struct list_head *next)
{
	next->prev = prev;
	prev->next = next;
}

#define LIST_POISON1  ((void *) 0x00100100)
#define LIST_POISON2  ((void *) 0x00200200)

static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	entry->next = (struct list_head*)LIST_POISON1;
	entry->prev = (struct list_head*)LIST_POISON2;
}