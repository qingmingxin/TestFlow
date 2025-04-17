#pragma once

#include <memory>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdexcept>
#include <atomic>
#include <cstring>
#include <infiniband/verbs.h>
#include <queue>
#include "log.h"

struct MemoryChunk
{
    void *v_addr;
    void *p_addr;
    bool is_used;
    ibv_mr *mr;
    ibv_pd *pd;
    size_t size;
    std::mutex m_mutex;
};

class MemoryPoolBucket
{
public:
    explicit MemoryPoolBucket(size_t chunk_size);
    ~MemoryPoolBucket();

    // 往bucket中插入内存块
    int insert();
    // 从bucket中删除内存块
    int del(void *chunk_ptr);
    // 从bucket中获取内存块
    void *get();
    // 重置内存块
    int clear(void *chunk_ptr);

private:
    const size_t chunk_size_;           // 本桶内存块大小
    std::vector<MemoryChunk *> chunks_; // 所有内存块元数据
    std::queue<MemoryChunk *> free_queue_;
    pthread_spinlock_t mutex_; // 桶级细粒度锁
};

class SharedMemoryPool
{
public:
    // ==================== 单例模式 ====================
    static SharedMemoryPool &instance();
    SharedMemoryPool(const SharedMemoryPool &) = delete;
    void operator=(const SharedMemoryPool &) = delete;

    // ==================== 核心接口 ====================
    void *insert(size_t new_size);
    void *get(size_t size);

    // ==================== 配置参数 ====================
    static constexpr size_t DEFAULT_ALIGNMENT = 4096; // 4K对齐
    static constexpr size_t MIN_BLOCK_SIZE = 64;      // 最小内存块64B
    static constexpr size_t MAX_BLOCK_SIZE = 1 << 28; // 最大内存块256MB

private:
    SharedMemoryPool() {};
    std::unordered_map<size_t, std::unique_ptr<MemoryPoolBucket>> buckets_;
    pthread_spinlock_t map_mutex_;
};
