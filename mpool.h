#ifndef MPOOL_H
#define MPOOL_H

/* Turn on debugging traces, 0~2 */
#ifndef MPOOL_DEBUG
#define MPOOL_DEBUG 0
#endif


#define POOL_MIN               4
#define POOL_MAX               10
#define POOL_ARRAY_TOTAL_CNT   1000

typedef unsigned int uint32_t;

typedef struct _mpool {
  uint32_t cur_cnt;                     /* actual pool count */
  uint32_t min_pool;                    /* minimum pool size */
  uint32_t max_pool;                    /* maximum pool size */
  uint32_t pg_sz;                       /* page size, typically 4096 */
  uint32_t sizes[POOL_ARRAY_TOTAL_CNT]; /* chunk size for each pool */
  void *ps[POOL_ARRAY_TOTAL_CNT];       /* pools */
  void *hs[POOL_ARRAY_TOTAL_CNT];       /* heads for pools' free lists */
} mpool;

typedef struct _mem_alloc {
  uint32_t size;
  void *ptr;
} mem_alloc;


extern mpool g_mpool;
extern int64_t total_mem;

void cJSON_InitHooks(void);
void mpool_free(mpool *mp);

#endif /* MPOOL_H */
