// SPDX-License-Identifier: BSD-3-Clause

#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include "osmem.h"
#include "block_meta.h"

#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))
#define META_SIZE sizeof(struct block_meta)
#define PAGE_SIZE getpagesize()
#define MMAP_THRESHOLD	(128 * 1024)
#define MAP_FAILED        ((void *) -1)

struct block_meta *base;
int heap_initialized;

struct block_meta *init_heap(void)
{
	base = (struct block_meta *)sbrk(MMAP_THRESHOLD);
	if (base == (void *)-1)
		return NULL;
	base->size = MMAP_THRESHOLD - META_SIZE;
	base->next = NULL;
	base->prev = NULL;
	base->status = STATUS_ALLOC;
	return base;
}

struct block_meta *find_space(struct block_meta *base, size_t size)
{
	struct block_meta *iter = base;
	struct block_meta *best_fit = NULL;
	size_t closest = 1000000;

	while (iter != NULL) {
		if (iter->status == STATUS_FREE && ALIGN(iter->size) >= ALIGN(size)) {
			if (ALIGN(iter->size) == size)
				return iter;
			if (ALIGN(iter->size) - size <= ALIGN(closest)) {
				closest = ALIGN(iter->size) - size;
				best_fit = iter;
			}
		}
		iter = iter->next;
	}
	return best_fit;
}
void split(struct block_meta *block, size_t actual_size)
{
	size_t needed_size = ALIGN(actual_size);
	size_t extra_size = 8;
	size_t total_available_mem = ALIGN(block->size);

	if (META_SIZE + needed_size + META_SIZE + extra_size <= META_SIZE + total_available_mem) {
		struct block_meta *new = (struct block_meta *)((char *)block + needed_size +  META_SIZE);

		new->next = block->next;
		new->prev = block;
		if (block->next)
			block->next->prev = new;
		new->status = STATUS_FREE;
		block->next = new;
		block->size = actual_size;
		new->size = total_available_mem - needed_size - ALIGN(META_SIZE);
		block->status = STATUS_ALLOC;
	}
}
struct block_meta *coalesce(struct block_meta *aux)
{
	while (aux->prev) {
		if (aux->prev->status == STATUS_FREE) {
			size_t total = META_SIZE + ALIGN(aux->size) + ALIGN(aux->prev->size);

			aux->prev->size = total;
			aux->prev->next = aux->next;
			if (aux->next)
				aux->next->prev = aux->prev;
			aux = aux->prev;
		} else {
			break;
		}
	}
	int ok = 1;

	while (ok) {
		if (aux->next) {
			if (aux->next->status == STATUS_FREE) {
				size_t total = META_SIZE + ALIGN(aux->size) + ALIGN(aux->next->size);

				aux->size = total;
				aux->next = aux->next->next;
				if (aux->next)
					aux->next->prev = aux;
				else
					aux->next = NULL;
			} else {
				return aux;
				ok = 0;
			}
		} else {
			return aux;
			ok = 0;
		}
	}
	return aux;
}
struct block_meta *expand(struct block_meta *last, size_t size)
{
	size_t needed_size = ALIGN(size) - ALIGN(last->size);

	if (sbrk(needed_size) == (void *)-1)
		return NULL;
	last->next = NULL;
	last->size = size;
	last->status = STATUS_ALLOC;
	return last;
}
void *os_malloc(size_t size)
{
	struct block_meta *block;
	size_t total_size = ALIGN(size);

	if (size <= 0)
		return NULL;
	if (heap_initialized == 0) {
		if (total_size >= MMAP_THRESHOLD) {
			block = (struct block_meta *)mmap(NULL, total_size + META_SIZE, PROT_READ | PROT_WRITE,
										 MAP_ANON | MAP_PRIVATE, -1, 0);
			DIE(block == MAP_FAILED, "mmap malloc");
			if (block == NULL)
				return NULL;
			block->next = NULL;
			block->prev = NULL;
			block->status = STATUS_MAPPED;
			block->size = total_size;
			return (void *)(block + 1);
		}
			base = init_heap();
			if (!base)
				return NULL;
			heap_initialized = 1;
			return (void *)(base + 1);
	}
	if (total_size >= MMAP_THRESHOLD) {
		block = (struct block_meta *)mmap(NULL, total_size + META_SIZE, PROT_READ | PROT_WRITE,
										 MAP_ANON | MAP_PRIVATE, -1, 0);
		DIE(block == MAP_FAILED, "mmap malloc");

		if (!block)
			return NULL;

		block->status = STATUS_MAPPED;
		block->size = size;
		return (void *)(block + 1);
	}
	block = find_space(base, size);
	if (!block) {
		struct block_meta *last = base;

		while (last->next)
			last = last->next;
		if (last->status == STATUS_FREE) {
			block = expand(last, size);
			if (!block)
				return NULL;
			block->status = STATUS_ALLOC;
			return (void *)(block + 1);
		}
		// daca nu e free
			struct block_meta *new;

			new = (struct block_meta *)sbrk(total_size + META_SIZE);
			if (new == (void *)-1)
				return NULL;
			new->next = NULL;
			new->size = size;
			new->prev = last;
			last->next = new;
			new->status = STATUS_ALLOC;
			return (void *)(new + 1);
	}
	split(block, size);
	block->status = STATUS_ALLOC;
	return (void *)(block + 1);
}

void os_free(void *ptr)
{
	if (ptr != NULL) {
		struct block_meta *aux = (struct block_meta *)ptr - 1;

		if (aux->status == STATUS_MAPPED) {
			int result = munmap(aux, ALIGN(aux->size) + ALIGN(META_SIZE));

			if (result < 0)
				return;
		} else {
			if (aux->status == STATUS_ALLOC) {
				aux->status = STATUS_FREE;
				aux = coalesce(aux);
			}
		}
	}
}
void *os_calloc(size_t nmemb, size_t size)
{
	struct block_meta *block;

	if (nmemb == 0 || size == 0)
		return NULL;
	if (size * nmemb + META_SIZE <= (unsigned long)PAGE_SIZE) {
		block = (struct block_meta *)os_malloc(nmemb * size);
		if (block != NULL) {
			memset((void *)block, 0, ALIGN(size * nmemb));
			return (void *)block;
		}
		return NULL;
	}
		block = (struct block_meta *)mmap(NULL, ALIGN(nmemb * size) + META_SIZE, PROT_READ | PROT_WRITE,
									 MAP_ANON | MAP_PRIVATE, -1, 0);
		if (block == NULL)
			return NULL;
		block->size = ALIGN(size * nmemb);
		block->status = STATUS_MAPPED;
		memset((void *)(block + 1), 0, ALIGN(nmemb * size));
		return (void *)(block + 1);

	return NULL;
}

void *os_realloc(void *ptr, size_t size)
{
	if (!ptr)
		return os_malloc(size);
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}
	struct block_meta *block = (struct block_meta *)ptr - 1;

	if (block->status == STATUS_FREE)
		return NULL;
	if (block->size >= size && block->status == STATUS_ALLOC) {
		split(block, ALIGN(size));
		block->status = STATUS_ALLOC;
		return (void *)(block + 1);
	}
	// daca era alocat cu mmap si trebuie sa fac blocul mai mic
	if (block->status == STATUS_MAPPED && size < MMAP_THRESHOLD) {
		void *adr = os_malloc(size);

		memcpy(adr, ptr, size);
		os_free(ptr);
		return adr;
	}
	int ok = 1;
	// unesc cu nodul urmator daca este free samd
	while (ok) {
		if (block->next) {
			if (block->next->status == STATUS_FREE) {
				size_t total = META_SIZE + ALIGN(block->size) + ALIGN(block->next->size);

				block->size = total;
				if (block->next->next)
					block->next->next->prev = block;
				block->next = block->next->next;
				if (block->size >= size) {
					if (block->size - META_SIZE - 8  >= size)
						split(block, size);
					return (void *)(block + 1);
				}
			} else {
				ok = 0;
			}

		} else {
			ok = 0;
		}
	}
	// daca am ajuns la sfarsitul listei si tot nu e suficient
	if (block->next == NULL) {
		if (sbrk(ALIGN(size)-ALIGN(block->size)) == (void *)-1)
			return NULL;
		block->size = size;
		return (void *)(block + 1);
	}
	void *new;

	new = os_malloc(size);
	if (!new)
		return NULL;
	memcpy(new, ptr, size);
	os_free(ptr);
	return new;
}

