#include "shmem_pool.h"

MemoryPoolBucket::MemoryPoolBucket(size_t chunk_size) : chunk_size_(chunk_size)
{
    insert();
}

MemoryPoolBucket::~MemoryPoolBucket()
{
    for (auto *chunk : chunks_)
    {
        delete chunk;
    }
    chunks_.clear();
    pthread_spin_destroy(&mutex_);
}

int MemoryPoolBucket::insert()
{
    pthread_spin_lock(&mutex_);
    void *raw_mem = mmap(nullptr, chunk_size_, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, -1, 0);
    if (raw_mem == MAP_FAILED)
    {
        LOG_ERROR("MemoryPoolBucket::insert : mmap failed...");
        return -1;
    }
    MemoryChunk *chunk = new MemoryChunk();
    memset(chunk, 0, sizeof(chunk));
    chunk->is_used = false;
    chunk->v_addr = raw_mem;
    chunk->size = chunk_size_;
    chunks_.push_back(chunk);
    free_queue_.push(chunk);
    pthread_spin_unlock(&mutex_);
    return 0;
}

int MemoryPoolBucket::del(void *chunk_ptr)
{
    pthread_spin_lock(&mutex_);
    MemoryChunk *chunk = reinterpret_cast<MemoryChunk *>(chunk_ptr);
    if (chunk->size != chunk_size_)
    {
        return -1; // ERR_INVALID_SIZE
    }

    if (chunk->is_used)
    {
        return -2; // ERR_DOUBLE_FREE
    }
    std::vector<MemoryChunk *>::iterator it = chunks_.end();
    for (std::vector<MemoryChunk *>::iterator iter = chunks_.begin(); iter != chunks_.end(); ++iter)
    {
        if ((*iter)->v_addr == chunk_ptr)
        {
            it = iter; // 找到匹配元素
            break;     // 找到第一个符合条件元素后立即退出
        }
    }
    if (it == chunks_.end())
    {
        return -3; // ERR_UNKNOWN_ADDRESS
    }
    chunk->is_used = false;
    munmap(chunk->v_addr, chunk_size_);
    free(chunk);
    pthread_spin_unlock(&mutex_);
}

void *MemoryPoolBucket::get()
{
    pthread_spin_lock(&mutex_);
    MemoryChunk *chunk = nullptr;
    if (free_queue_.empty())
    {
        chunk = reinterpret_cast<MemoryChunk *>(insert());
    }
    else
    {
        chunk = free_queue_.front();
        free_queue_.pop();
    }
    chunk->is_used = true;
    pthread_spin_unlock(&mutex_);
    return (void *)chunk;
}

int MemoryPoolBucket::clear(void *chunk_ptr)
{
    pthread_spin_lock(&mutex_);
    MemoryChunk *chunk = reinterpret_cast<MemoryChunk *>(chunk_ptr);
    if (chunk->size != chunk_size_)
    {
        return -1; // ERR_INVALID_SIZE
    }
    std::vector<MemoryChunk *>::iterator it = chunks_.end();
    for (std::vector<MemoryChunk *>::iterator iter = chunks_.begin(); iter != chunks_.end(); ++iter)
    {
        if ((*iter)->v_addr == chunk_ptr)
        {
            it = iter; // 找到匹配元素
            break;     // 找到第一个符合条件元素后立即退出
        }
    }
    if (it == chunks_.end())
    {
        return -2; // ERR_UNKNOWN_ADDRESS
    }
    chunk->mr = nullptr;
    chunk->pd = nullptr;
    chunk->is_used = false;
    free_queue_.push(chunk);
    pthread_spin_unlock(&mutex_);
    return 0;
}

SharedMemoryPool &SharedMemoryPool::instance()
{
    static SharedMemoryPool pool;
    return pool;
}

void *SharedMemoryPool::insert(size_t new_size)
{
    pthread_spin_lock(&map_mutex_);
    MemoryPoolBucket *bucket = nullptr;
    auto it = buckets_.find(new_size);
    if (it != buckets_.end())
    {
        bucket = nullptr;
        LOG_ERROR("this size bucket existed.");
    }
    else
    {
        auto [iter, inserted] = buckets_.emplace(
            new_size,
            std::make_unique<MemoryPoolBucket>(new_size) // 构造并转移所有权
        );
        if (inserted)
        {
            // 从 unique_ptr 获取原始指针
            bucket = iter->second.get();
        }
    }
    pthread_spin_unlock(&map_mutex_);
    return (void *)bucket;
}

void *SharedMemoryPool::get(size_t size)
{
    pthread_spin_lock(&map_mutex_);
    MemoryPoolBucket *bucket = nullptr;
    auto it = buckets_.find(size);
    if (it != buckets_.end())
    {
        bucket = (*it).second.get();
    }
    else
    {
        LOG_ERROR("can not find this size");
    }
    pthread_spin_unlock(&map_mutex_);
    return (void *)bucket;
}

SharedMemoryPool::SharedMemoryPool()
{
    const std::vector<size_t> preset_sizes = {
        64, 1024, 4096,              // 小对象
        16384, 262144, 1048576,      // 中等对象
        4194304, 67108864, 268435456 // 大对象
        // 1073741824                    // 1GB
    };
    for (auto size : preset_sizes)
    {
        if (size < MIN_BLOCK_SIZE || size > MAX_BLOCK_SIZE)
            continue;
        buckets_.emplace(size, std::make_unique<MemoryPoolBucket>(
                                   size));
    }
}