/*
 * Copyright (c) 2011 Scott Vokes <vokes.s@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * A memory pool allocator, designed for systems that need to
 * allocate/free pointers in amortized O(1) time. Memory is allocated a
 * page at a time, then added to a set of pools of equally sized
 * regions. A free list for each size is maintained in the unused
 * regions. When a pointer is repooled, it is linked back into the
 * pool with the given size's free list.
 *
 * Note that repooling with the wrong size leads to subtle/ugly memory
 * clobbering bugs. Turning on memory use logging via MPOOL_DEBUG
 * can help pin down the location of most such errors.
 *
 * Allocations larger than the page size are allocated whole via
 * mmap, and those larger than mp->max_pool (configurable) are
 * freed immediately via munmap; no free list is used.
 */

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <stddef.h>

#include "mpool.h"


#define DBG MPOOL_DEBUG


static void *get_mmap(size_t sz) {
  void *p = NULL;

  p = mmap(0, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) {
    return NULL;
  }

  memset(p, 0, sz);
  return p;
}

/* Optimized base-2 integer ceiling, from _Hacker's Delight_
 * by Henry S. Warren, pg. 48. Called 'clp2' there. */
static unsigned int iceil2(unsigned int x) {
  unsigned int ret = x;

  ret = ret - 1;
  ret = ret | (ret >> 1);
  ret = ret | (ret >> 2);
  ret = ret | (ret >> 4);
  ret = ret | (ret >> 8);
  ret = ret | (ret >> 16);
  return ret + 1;
}

/* mmap a new memory pool of TOTAL_SZ bytes, then build an internal
 * freelist of SZ-byte cells, with the head at (result)[0].
 * Returns NULL on error. */
static void **mpool_new_pool(unsigned int sz, unsigned int total_sz) {
  unsigned int i = 0;
  unsigned int offset = 0;
  unsigned int lim = 0;
  void *p;
  int **pool;
  void *last = NULL;

  p = get_mmap(sz > total_sz ? sz : total_sz);
  if (p == NULL)
    return NULL;

  pool = (int **)p;
  assert(pool);
  assert(sz > sizeof(void *));

  lim = (total_sz / sz);
  if (DBG)
    fprintf(stderr, "mpool_new_pool sz: %d lim: %d => %d %p\n", sz, lim,
            lim * sz, p);

  for (i = 0; i < lim; i++) {
    if (last)
      assert(last == pool[offset]);

    offset = (i * sz) / sizeof(void *);
    /* &pool[offset] - &pool[0] equals to offset * 8, 8 is sizeof(void *) */
    pool[offset] = (int *)&pool[offset + (sz / sizeof(void *))];
    last = pool[offset];
    if (DBG > 1)
      fprintf(stderr, "%d (%d / 0x%04x) -> %p = %p\n", i, offset, offset, (void *)&pool[offset],
              (void *)pool[offset]);
  }
  pool[offset] = NULL;
  return (void **)p;
}

/* Add a new pool, resizing the pool array if necessary. */
static int add_pool(mpool *mp, void *p, uint32_t sz) {
  assert(p);
  assert(sz > 0);
  if (DBG)
    fprintf(stderr, "mpool_add_pool (%d / %d) @ %p, sz %d\n", mp->cur_cnt, POOL_ARRAY_TOTAL_CNT,
            p, sz);
  if (mp->cur_cnt == POOL_ARRAY_TOTAL_CNT) {
    fprintf(stderr, "reach max pool cnt (%d / %d) @ %p, sz %d\n", mp->cur_cnt, POOL_ARRAY_TOTAL_CNT, p, sz);
    return -1;
  }

  mp->ps[mp->cur_cnt] = p;
  mp->sizes[mp->cur_cnt] = sz;
  mp->cur_cnt++;
  return 0;
}


/* Allocate memory out of the relevant memory pool.
 * If larger than max_pool, just mmap it. If pool is full, mmap a new one and
 * link it to the end of the current one. Returns NULL on error. */
static void *_mpool_alloc(mpool *mp, uint32_t sz) {
  void **cur, **np; /* new pool */
  uint32_t i, p, szceil = 0;

  assert(mp);
  if (sz >= mp->max_pool) {
    cur = (void **)get_mmap(sz); /* just mmap it */
    if (cur == NULL)
      return NULL;
    if (DBG)
      fprintf(stderr, "_mpool_alloc mmap %d bytes @ %p\n", sz, (void *)cur);
    return cur;
  }

  for (i = 0, p = mp->min_pool;; i++, p *= 2) {
    if (p > sz) {
      szceil = p;
      break;
    }
  }

  assert(szceil > 0);

  cur = (void **)mp->hs[i];   /* get current head */
  if (cur == NULL) { /* lazily allocate & init pool */
    void **pool = mpool_new_pool(szceil, mp->pg_sz);
    if (pool == NULL)
      return NULL;
    mp->ps[i] = pool;
    mp->hs[i] = &pool[0];
    mp->sizes[i] = szceil;
    cur = (void **)mp->hs[i];
    if (1)
      fprintf(stderr, "mpool_new_pool id: %d, addr: %p\n", i, (void *)cur);
  }
  assert(cur);

  if (*cur == NULL) { /* if at end, attach to a new page */
    if (DBG)
      fprintf(stderr, "_mpool_alloc adding pool w/ cell size %d\n", szceil);
    np = mpool_new_pool(szceil, mp->pg_sz);
    if (np == NULL)
      return NULL;
    *cur = &np[0];
    assert(*cur);
    if (add_pool(mp, np, szceil) < 0)
      return NULL;
  }

  assert(*cur > (void *)4096);
  if (DBG)
    fprintf(stderr, "_mpool_alloc pool %d bytes @ %p (list %d, szceil %d )  *cur:%p\n",
            sz, (void *)cur, i, szceil, (void *)*cur);

  mp->hs[i] = *cur; /* set head to next head */
  return cur;
}

/* Push an individual pointer P back on the freelist for
 * the pool with size SZ cells.
 * if SZ is > the max pool size, just munmap it. */
static void _mpool_repool(mpool *mp, void *p, uint32_t sz) {
  uint32_t i = 0;
  uint32_t szceil, pool_size;
  uint32_t max_pool = mp->max_pool;
  void **ip;

  if (sz > max_pool) {
    if (DBG)
      fprintf(stderr, "_mpool_repool munmap sz %d @ %p\n", sz, p);
    if (munmap(p, sz) == -1) {
      fprintf(stderr, "munmap error while unmapping %d bytes at %p\n", sz, p);
    }
    return;
  }

  for (i = 0, pool_size = mp->min_pool;; i++, pool_size *= 2) {
    if (pool_size > sz) {
      break;
    }
  }

  szceil = iceil2(sz);
  szceil = szceil > mp->min_pool ? szceil : mp->min_pool;

  ip = (void **)p;
  *ip = mp->hs[i];
  assert(ip);
  mp->hs[i] = ip;
  if (1)
    fprintf(stderr, "_mpool_repool list %d, %d bytes (ceil %d): %p\n", i, sz,
            szceil, (void *)ip);
}

static void *hook_mpool_alloc(size_t sz)
{
  mem_alloc *p = NULL;

  p = (mem_alloc *) _mpool_alloc(&g_mpool, (uint32_t)sz + (uint32_t)offsetof(mem_alloc, ptr));
  p->size = (uint32_t)sz + (uint32_t)offsetof(mem_alloc, ptr);

  total_mem += (int64_t)p->size;
  return &p->ptr;
}

static void hook_mpool_free(void *ptr)
{
  mem_alloc *p  = NULL;

  p = (mem_alloc *)((char *)ptr - (uint32_t)offsetof(mem_alloc, ptr));
  total_mem -= (int64_t)p->size;

  _mpool_repool(&g_mpool, (void *)p, (uint32_t)p->size);
  return;
}

/* Free a memory pool set. */
void mpool_free(mpool *mp) {
  uint32_t i, sz, pgsz = mp->pg_sz;
  assert(mp);
  if (DBG)
    fprintf(stderr, "%d/%d pools, freeing...\n", mp->cur_cnt, POOL_ARRAY_TOTAL_CNT);
  for (i = 0; i < mp->cur_cnt; i++) {
    void *p = mp->ps[i];
    if (p) {
      sz = mp->sizes[i];
      assert(sz > 0);
      sz = sz >= pgsz ? sz : pgsz;
      if (DBG)
        fprintf(stderr, "mpool_free %d, sz %d (%p)\n", i, sz, mp->ps[i]);
      if (munmap(mp->ps[i], sz) == -1) {
        fprintf(stderr, "munmap error while unmapping %u bytes at %p\n", sz,
                mp->ps[i]);
      }
    }
  }
}


int64_t total_mem = 0;

mpool g_mpool = {
  .cur_cnt = POOL_MAX - POOL_MIN + 1,
  .min_pool = 1 << POOL_MIN,
  .max_pool = 1 << POOL_MAX,
  .pg_sz = 4096
};
