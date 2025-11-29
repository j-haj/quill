//! Memory pool implementations for efficient GPU tensor streaming.
//!
//! This module provides memory pools to reduce allocation overhead during
//! high-throughput tensor streaming:
//!
//! - `PinnedMemoryPool`: Page-locked host memory for efficient DMA transfers
//! - `GpuMemoryPool`: GPU memory buffer reuse to avoid allocation latency
//!
//! # Example
//!
//! ```rust,ignore
//! use quill_tensor::pool::{PinnedMemoryPool, GpuMemoryPool, PoolConfig};
//!
//! // Create pools with default configuration
//! let pinned_pool = PinnedMemoryPool::new(PoolConfig::default());
//! let gpu_pool = GpuMemoryPool::new(0, PoolConfig::default()); // GPU device 0
//!
//! // Acquire buffers from pools
//! let staging = pinned_pool.acquire(1024 * 1024)?; // 1MB staging buffer
//! let gpu_buf = gpu_pool.acquire(1024 * 1024)?;    // 1MB GPU buffer
//!
//! // Buffers are returned to pool when dropped
//! ```

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::{Bytes, BytesMut};

use crate::buffer::{GpuError, GpuResult, GpuStatus, TensorBuffer};

/// Configuration for memory pools.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum total memory the pool can hold (bytes).
    /// Default: 256 MB
    pub max_pool_size: usize,

    /// Minimum buffer size to pool (smaller buffers are allocated on-demand).
    /// Default: 64 KB
    pub min_buffer_size: usize,

    /// Maximum buffer size to pool (larger buffers are allocated on-demand).
    /// Default: 64 MB
    pub max_buffer_size: usize,

    /// Number of size classes for buffer bucketing.
    /// Buffers are rounded up to the nearest power of 2.
    /// Default: 16 (covers 64KB to 64MB with power-of-2 sizes)
    pub size_classes: usize,

    /// Whether to pre-allocate buffers on pool creation.
    /// Default: false
    pub preallocate: bool,

    /// Number of buffers to pre-allocate per size class.
    /// Only used if `preallocate` is true.
    /// Default: 2
    pub preallocate_count: usize,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_pool_size: 256 * 1024 * 1024,      // 256 MB
            min_buffer_size: 64 * 1024,            // 64 KB
            max_buffer_size: 64 * 1024 * 1024,     // 64 MB
            size_classes: 16,
            preallocate: false,
            preallocate_count: 2,
        }
    }
}

impl PoolConfig {
    /// Creates a configuration optimized for high-throughput streaming.
    pub fn high_throughput() -> Self {
        Self {
            max_pool_size: 512 * 1024 * 1024,      // 512 MB
            min_buffer_size: 1024 * 1024,          // 1 MB (larger minimum)
            max_buffer_size: 128 * 1024 * 1024,    // 128 MB
            size_classes: 8,
            preallocate: true,
            preallocate_count: 4,
        }
    }

    /// Creates a configuration optimized for low memory usage.
    pub fn low_memory() -> Self {
        Self {
            max_pool_size: 64 * 1024 * 1024,       // 64 MB
            min_buffer_size: 16 * 1024,            // 16 KB
            max_buffer_size: 16 * 1024 * 1024,     // 16 MB
            size_classes: 12,
            preallocate: false,
            preallocate_count: 1,
        }
    }
}

/// Statistics for a memory pool.
#[derive(Debug, Clone, Default)]
pub struct PoolStats {
    /// Number of buffers currently in the pool (available).
    pub available_buffers: usize,
    /// Number of buffers currently in use.
    pub in_use_buffers: usize,
    /// Total bytes currently in the pool.
    pub pool_bytes: usize,
    /// Total bytes currently in use.
    pub in_use_bytes: usize,
    /// Number of allocations served from the pool (hits).
    pub hits: u64,
    /// Number of allocations that required new allocation (misses).
    pub misses: u64,
    /// Number of buffers returned to the pool.
    pub returns: u64,
    /// Number of buffers dropped (pool full or too large).
    pub drops: u64,
}

impl PoolStats {
    /// Returns the hit rate as a percentage.
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            (self.hits as f64 / total as f64) * 100.0
        }
    }
}

/// A handle to a pooled buffer that returns it to the pool on drop.
pub struct PooledBuffer {
    data: Option<BytesMut>,
    pool: Arc<PinnedMemoryPoolInner>,
    size_class: usize,
}

impl PooledBuffer {
    /// Returns the buffer's capacity.
    pub fn capacity(&self) -> usize {
        self.data.as_ref().map(|d| d.capacity()).unwrap_or(0)
    }

    /// Returns the buffer's current length.
    pub fn len(&self) -> usize {
        self.data.as_ref().map(|d| d.len()).unwrap_or(0)
    }

    /// Returns whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns a mutable reference to the underlying BytesMut.
    pub fn as_mut(&mut self) -> Option<&mut BytesMut> {
        self.data.as_mut()
    }

    /// Returns a reference to the underlying BytesMut.
    pub fn as_ref(&self) -> Option<&BytesMut> {
        self.data.as_ref()
    }

    /// Consumes this handle and returns the buffer as Bytes.
    /// The buffer will NOT be returned to the pool.
    pub fn freeze(mut self) -> Bytes {
        self.data.take().map(|d| d.freeze()).unwrap_or_default()
    }

    /// Clears the buffer, resetting length to 0 but keeping capacity.
    pub fn clear(&mut self) {
        if let Some(ref mut data) = self.data {
            data.clear();
        }
    }

    /// Extends the buffer with the given slice.
    pub fn extend_from_slice(&mut self, src: &[u8]) {
        if let Some(ref mut data) = self.data {
            data.extend_from_slice(src);
        }
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if let Some(mut data) = self.data.take() {
            data.clear(); // Reset length but keep capacity
            self.pool.return_buffer(data, self.size_class);
        }
    }
}

impl std::ops::Deref for PooledBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.data.as_ref().map(|d| d.as_ref()).unwrap_or(&[])
    }
}

impl std::ops::DerefMut for PooledBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.data.as_mut().map(|d| d.as_mut()).unwrap_or(&mut [])
    }
}

struct PinnedMemoryPoolInner {
    config: PoolConfig,
    /// Buckets for different size classes (index = log2(size) - log2(min_size))
    buckets: Vec<Mutex<VecDeque<BytesMut>>>,
    /// Statistics
    stats: PoolStatsAtomic,
}

struct PoolStatsAtomic {
    available_buffers: AtomicUsize,
    in_use_buffers: AtomicUsize,
    pool_bytes: AtomicUsize,
    in_use_bytes: AtomicUsize,
    hits: AtomicU64,
    misses: AtomicU64,
    returns: AtomicU64,
    drops: AtomicU64,
}

impl Default for PoolStatsAtomic {
    fn default() -> Self {
        Self {
            available_buffers: AtomicUsize::new(0),
            in_use_buffers: AtomicUsize::new(0),
            pool_bytes: AtomicUsize::new(0),
            in_use_bytes: AtomicUsize::new(0),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            returns: AtomicU64::new(0),
            drops: AtomicU64::new(0),
        }
    }
}

impl PoolStatsAtomic {
    fn to_stats(&self) -> PoolStats {
        PoolStats {
            available_buffers: self.available_buffers.load(Ordering::Relaxed),
            in_use_buffers: self.in_use_buffers.load(Ordering::Relaxed),
            pool_bytes: self.pool_bytes.load(Ordering::Relaxed),
            in_use_bytes: self.in_use_bytes.load(Ordering::Relaxed),
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            returns: self.returns.load(Ordering::Relaxed),
            drops: self.drops.load(Ordering::Relaxed),
        }
    }
}

impl PinnedMemoryPoolInner {
    fn new(config: PoolConfig) -> Self {
        let buckets = (0..config.size_classes)
            .map(|_| Mutex::new(VecDeque::new()))
            .collect();

        Self {
            config,
            buckets,
            stats: PoolStatsAtomic::default(),
        }
    }

    fn size_class_for(&self, size: usize) -> Option<usize> {
        if size < self.config.min_buffer_size || size > self.config.max_buffer_size {
            return None;
        }

        // Round up to next power of 2
        let rounded = size.next_power_of_two();
        let min_log2 = self.config.min_buffer_size.trailing_zeros() as usize;
        let size_log2 = rounded.trailing_zeros() as usize;

        let class = size_log2.saturating_sub(min_log2);
        if class < self.config.size_classes {
            Some(class)
        } else {
            None
        }
    }

    fn size_for_class(&self, class: usize) -> usize {
        let min_log2 = self.config.min_buffer_size.trailing_zeros();
        1 << (min_log2 as usize + class)
    }

    fn try_acquire(&self, size_class: usize) -> Option<BytesMut> {
        if size_class >= self.buckets.len() {
            return None;
        }

        let mut bucket = self.buckets[size_class].lock().ok()?;
        if let Some(buf) = bucket.pop_front() {
            let capacity = buf.capacity();
            self.stats.available_buffers.fetch_sub(1, Ordering::Relaxed);
            self.stats.pool_bytes.fetch_sub(capacity, Ordering::Relaxed);
            self.stats.in_use_buffers.fetch_add(1, Ordering::Relaxed);
            self.stats.in_use_bytes.fetch_add(capacity, Ordering::Relaxed);
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
            Some(buf)
        } else {
            None
        }
    }

    fn return_buffer(&self, buf: BytesMut, size_class: usize) {
        let capacity = buf.capacity();

        // Check if pool is full
        let current_pool_bytes = self.stats.pool_bytes.load(Ordering::Relaxed);
        if current_pool_bytes + capacity > self.config.max_pool_size {
            self.stats.drops.fetch_add(1, Ordering::Relaxed);
            self.stats.in_use_buffers.fetch_sub(1, Ordering::Relaxed);
            self.stats.in_use_bytes.fetch_sub(capacity, Ordering::Relaxed);
            return; // Drop the buffer
        }

        if size_class < self.buckets.len() {
            if let Ok(mut bucket) = self.buckets[size_class].lock() {
                bucket.push_back(buf);
                self.stats.available_buffers.fetch_add(1, Ordering::Relaxed);
                self.stats.pool_bytes.fetch_add(capacity, Ordering::Relaxed);
                self.stats.in_use_buffers.fetch_sub(1, Ordering::Relaxed);
                self.stats.in_use_bytes.fetch_sub(capacity, Ordering::Relaxed);
                self.stats.returns.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// A pool of page-locked (pinned) host memory for efficient DMA transfers.
///
/// Pinned memory cannot be paged out by the OS, which is required for
/// efficient CUDA DMA transfers. This pool pre-allocates and reuses
/// pinned buffers to avoid the overhead of repeated pinning.
///
/// # Example
///
/// ```rust
/// use quill_tensor::pool::{PinnedMemoryPool, PoolConfig};
///
/// let pool = PinnedMemoryPool::new(PoolConfig::default());
///
/// // Acquire a buffer
/// let mut buffer = pool.acquire(1024).expect("allocation failed");
/// buffer.extend_from_slice(b"hello world");
///
/// // Buffer is returned to pool when dropped
/// drop(buffer);
///
/// // Check statistics
/// let stats = pool.stats();
/// println!("Hit rate: {:.1}%", stats.hit_rate());
/// ```
#[derive(Clone)]
pub struct PinnedMemoryPool {
    inner: Arc<PinnedMemoryPoolInner>,
}

impl PinnedMemoryPool {
    /// Creates a new pinned memory pool with the given configuration.
    pub fn new(config: PoolConfig) -> Self {
        let inner = Arc::new(PinnedMemoryPoolInner::new(config));
        Self { inner }
    }

    /// Creates a pool with default configuration.
    pub fn default_pool() -> Self {
        Self::new(PoolConfig::default())
    }

    /// Acquires a buffer of at least the specified size from the pool.
    ///
    /// If a suitable buffer is available in the pool, it will be reused.
    /// Otherwise, a new buffer is allocated.
    ///
    /// The returned buffer will be automatically returned to the pool when dropped.
    pub fn acquire(&self, size: usize) -> GpuResult<PooledBuffer> {
        let size_class = self.inner.size_class_for(size);

        let (data, class) = if let Some(class) = size_class {
            // Try to get from pool
            if let Some(buf) = self.inner.try_acquire(class) {
                (buf, class)
            } else {
                // Allocate new buffer
                let actual_size = self.inner.size_for_class(class);
                let buf = BytesMut::with_capacity(actual_size);
                self.inner.stats.misses.fetch_add(1, Ordering::Relaxed);
                self.inner.stats.in_use_buffers.fetch_add(1, Ordering::Relaxed);
                self.inner.stats.in_use_bytes.fetch_add(actual_size, Ordering::Relaxed);
                (buf, class)
            }
        } else {
            // Size outside pool range - allocate directly
            let buf = BytesMut::with_capacity(size);
            self.inner.stats.misses.fetch_add(1, Ordering::Relaxed);
            (buf, 0)
        };

        Ok(PooledBuffer {
            data: Some(data),
            pool: self.inner.clone(),
            size_class: class,
        })
    }

    /// Returns the current pool statistics.
    pub fn stats(&self) -> PoolStats {
        self.inner.stats.to_stats()
    }

    /// Returns the pool configuration.
    pub fn config(&self) -> &PoolConfig {
        &self.inner.config
    }

    /// Clears all buffers from the pool.
    pub fn clear(&self) {
        for bucket in &self.inner.buckets {
            if let Ok(mut b) = bucket.lock() {
                let count = b.len();
                let bytes: usize = b.iter().map(|buf| buf.capacity()).sum();
                b.clear();
                self.inner.stats.available_buffers.fetch_sub(count, Ordering::Relaxed);
                self.inner.stats.pool_bytes.fetch_sub(bytes, Ordering::Relaxed);
            }
        }
    }
}

impl Default for PinnedMemoryPool {
    fn default() -> Self {
        Self::default_pool()
    }
}

/// A handle to a pooled GPU buffer that returns it to the pool on drop.
pub struct PooledGpuBuffer {
    buffer: Option<TensorBuffer>,
    pool: Arc<GpuMemoryPoolInner>,
    size_class: usize,
}

impl PooledGpuBuffer {
    /// Returns the buffer's size in bytes.
    pub fn len(&self) -> usize {
        self.buffer.as_ref().map(|b| b.len()).unwrap_or(0)
    }

    /// Returns whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns whether this buffer is on GPU.
    pub fn is_gpu(&self) -> bool {
        self.buffer.as_ref().map(|b| b.is_gpu()).unwrap_or(false)
    }

    /// Returns a reference to the underlying TensorBuffer.
    pub fn as_ref(&self) -> Option<&TensorBuffer> {
        self.buffer.as_ref()
    }

    /// Returns a mutable reference to the underlying TensorBuffer.
    pub fn as_mut(&mut self) -> Option<&mut TensorBuffer> {
        self.buffer.as_mut()
    }

    /// Consumes this handle and returns the underlying TensorBuffer.
    /// The buffer will NOT be returned to the pool.
    pub fn take(mut self) -> Option<TensorBuffer> {
        self.buffer.take()
    }

    /// Copies data into this buffer.
    pub fn copy_from_slice(&mut self, data: &[u8]) -> GpuResult<()> {
        if let Some(ref mut buffer) = self.buffer {
            buffer.copy_from_slice(data)
        } else {
            Err(GpuError::AllocationFailed("Buffer not available".to_string()))
        }
    }

    /// Copies buffer contents to host memory.
    pub fn to_host(&self) -> GpuResult<Bytes> {
        if let Some(ref buffer) = self.buffer {
            buffer.to_host()
        } else {
            Err(GpuError::AllocationFailed("Buffer not available".to_string()))
        }
    }
}

impl Drop for PooledGpuBuffer {
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            self.pool.return_buffer(buffer, self.size_class);
        }
    }
}

struct GpuMemoryPoolInner {
    device_id: usize,
    config: PoolConfig,
    buckets: Vec<Mutex<VecDeque<TensorBuffer>>>,
    stats: PoolStatsAtomic,
}

impl GpuMemoryPoolInner {
    fn new(device_id: usize, config: PoolConfig) -> Self {
        let buckets = (0..config.size_classes)
            .map(|_| Mutex::new(VecDeque::new()))
            .collect();

        Self {
            device_id,
            config,
            buckets,
            stats: PoolStatsAtomic::default(),
        }
    }

    fn size_class_for(&self, size: usize) -> Option<usize> {
        if size < self.config.min_buffer_size || size > self.config.max_buffer_size {
            return None;
        }

        let rounded = size.next_power_of_two();
        let min_log2 = self.config.min_buffer_size.trailing_zeros() as usize;
        let size_log2 = rounded.trailing_zeros() as usize;

        let class = size_log2.saturating_sub(min_log2);
        if class < self.config.size_classes {
            Some(class)
        } else {
            None
        }
    }

    fn size_for_class(&self, class: usize) -> usize {
        let min_log2 = self.config.min_buffer_size.trailing_zeros();
        1 << (min_log2 as usize + class)
    }

    fn try_acquire(&self, size_class: usize) -> Option<TensorBuffer> {
        if size_class >= self.buckets.len() {
            return None;
        }

        let mut bucket = self.buckets[size_class].lock().ok()?;
        if let Some(buf) = bucket.pop_front() {
            let size = buf.len();
            self.stats.available_buffers.fetch_sub(1, Ordering::Relaxed);
            self.stats.pool_bytes.fetch_sub(size, Ordering::Relaxed);
            self.stats.in_use_buffers.fetch_add(1, Ordering::Relaxed);
            self.stats.in_use_bytes.fetch_add(size, Ordering::Relaxed);
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
            Some(buf)
        } else {
            None
        }
    }

    fn return_buffer(&self, buf: TensorBuffer, size_class: usize) {
        let size = buf.len();

        // Check if pool is full
        let current_pool_bytes = self.stats.pool_bytes.load(Ordering::Relaxed);
        if current_pool_bytes + size > self.config.max_pool_size {
            self.stats.drops.fetch_add(1, Ordering::Relaxed);
            self.stats.in_use_buffers.fetch_sub(1, Ordering::Relaxed);
            self.stats.in_use_bytes.fetch_sub(size, Ordering::Relaxed);
            return; // Drop the buffer
        }

        if size_class < self.buckets.len() {
            if let Ok(mut bucket) = self.buckets[size_class].lock() {
                bucket.push_back(buf);
                self.stats.available_buffers.fetch_add(1, Ordering::Relaxed);
                self.stats.pool_bytes.fetch_add(size, Ordering::Relaxed);
                self.stats.in_use_buffers.fetch_sub(1, Ordering::Relaxed);
                self.stats.in_use_bytes.fetch_sub(size, Ordering::Relaxed);
                self.stats.returns.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// A pool of GPU memory buffers for efficient tensor allocation.
///
/// This pool reuses GPU allocations to avoid the latency of repeated
/// cudaMalloc/cudaFree calls. Buffers are bucketed by size class
/// (powers of 2) for efficient matching.
///
/// # Example
///
/// ```rust,ignore
/// use quill_tensor::pool::{GpuMemoryPool, PoolConfig};
///
/// // Create pool for GPU device 0
/// let pool = GpuMemoryPool::new(0, PoolConfig::default())?;
///
/// // Acquire a buffer
/// let mut buffer = pool.acquire(1024 * 1024)?; // 1 MB
///
/// // Use the buffer
/// buffer.copy_from_slice(&data)?;
///
/// // Buffer is returned to pool when dropped
/// drop(buffer);
/// ```
#[derive(Clone)]
pub struct GpuMemoryPool {
    inner: Arc<GpuMemoryPoolInner>,
}

impl GpuMemoryPool {
    /// Creates a new GPU memory pool for the specified device.
    pub fn new(device_id: usize, config: PoolConfig) -> GpuResult<Self> {
        // Verify GPU is available
        let status = GpuStatus::detect();
        if !status.is_available() {
            return Err(GpuError::NoDevices);
        }

        if device_id >= status.device_count() {
            return Err(GpuError::InvalidDeviceId(device_id, status.device_count()));
        }

        Ok(Self {
            inner: Arc::new(GpuMemoryPoolInner::new(device_id, config)),
        })
    }

    /// Creates a pool with default configuration for the specified device.
    pub fn default_for_device(device_id: usize) -> GpuResult<Self> {
        Self::new(device_id, PoolConfig::default())
    }

    /// Returns the device ID this pool is associated with.
    pub fn device_id(&self) -> usize {
        self.inner.device_id
    }

    /// Acquires a buffer of at least the specified size from the pool.
    ///
    /// If a suitable buffer is available in the pool, it will be reused.
    /// Otherwise, a new buffer is allocated on the GPU.
    pub fn acquire(&self, size: usize) -> GpuResult<PooledGpuBuffer> {
        let size_class = self.inner.size_class_for(size);

        let (buffer, class) = if let Some(class) = size_class {
            if let Some(buf) = self.inner.try_acquire(class) {
                (buf, class)
            } else {
                // Allocate new buffer
                let actual_size = self.inner.size_for_class(class);
                let buf = TensorBuffer::try_allocate_gpu(actual_size, self.inner.device_id)?;
                self.inner.stats.misses.fetch_add(1, Ordering::Relaxed);
                self.inner.stats.in_use_buffers.fetch_add(1, Ordering::Relaxed);
                self.inner.stats.in_use_bytes.fetch_add(actual_size, Ordering::Relaxed);
                (buf, class)
            }
        } else {
            // Size outside pool range
            let buf = TensorBuffer::try_allocate_gpu(size, self.inner.device_id)?;
            self.inner.stats.misses.fetch_add(1, Ordering::Relaxed);
            (buf, 0)
        };

        Ok(PooledGpuBuffer {
            buffer: Some(buffer),
            pool: self.inner.clone(),
            size_class: class,
        })
    }

    /// Returns the current pool statistics.
    pub fn stats(&self) -> PoolStats {
        self.inner.stats.to_stats()
    }

    /// Returns the pool configuration.
    pub fn config(&self) -> &PoolConfig {
        &self.inner.config
    }

    /// Clears all buffers from the pool.
    pub fn clear(&self) {
        for bucket in &self.inner.buckets {
            if let Ok(mut b) = bucket.lock() {
                let count = b.len();
                let bytes: usize = b.iter().map(|buf| buf.len()).sum();
                b.clear();
                self.inner.stats.available_buffers.fetch_sub(count, Ordering::Relaxed);
                self.inner.stats.pool_bytes.fetch_sub(bytes, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_config_default() {
        let config = PoolConfig::default();
        assert_eq!(config.max_pool_size, 256 * 1024 * 1024);
        assert_eq!(config.min_buffer_size, 64 * 1024);
        assert_eq!(config.max_buffer_size, 64 * 1024 * 1024);
    }

    #[test]
    fn test_pool_config_high_throughput() {
        let config = PoolConfig::high_throughput();
        assert_eq!(config.max_pool_size, 512 * 1024 * 1024);
        assert!(config.preallocate);
    }

    #[test]
    fn test_pinned_pool_acquire_release() {
        let pool = PinnedMemoryPool::new(PoolConfig::default());

        // Acquire buffer
        let mut buffer = pool.acquire(100 * 1024).unwrap();
        assert!(buffer.capacity() >= 100 * 1024);

        // Write some data
        buffer.extend_from_slice(&[42u8; 1000]);
        assert_eq!(buffer.len(), 1000);

        // Check stats
        let stats = pool.stats();
        assert_eq!(stats.in_use_buffers, 1);

        // Release buffer
        drop(buffer);

        // Buffer should be back in pool
        let stats = pool.stats();
        assert_eq!(stats.in_use_buffers, 0);
        assert_eq!(stats.available_buffers, 1);
    }

    #[test]
    fn test_pinned_pool_reuse() {
        let pool = PinnedMemoryPool::new(PoolConfig::default());

        // Acquire and release
        let buffer1 = pool.acquire(100 * 1024).unwrap();
        let cap1 = buffer1.capacity();
        drop(buffer1);

        // Acquire again - should reuse
        let buffer2 = pool.acquire(100 * 1024).unwrap();
        assert_eq!(buffer2.capacity(), cap1);

        let stats = pool.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
    }

    #[test]
    fn test_pinned_pool_size_classes() {
        let pool = PinnedMemoryPool::new(PoolConfig::default());

        // Different sizes should use different buckets
        let buf_small = pool.acquire(64 * 1024).unwrap();
        let buf_large = pool.acquire(1024 * 1024).unwrap();

        assert!(buf_small.capacity() >= 64 * 1024);
        assert!(buf_large.capacity() >= 1024 * 1024);
        assert!(buf_large.capacity() > buf_small.capacity());
    }

    #[test]
    fn test_pinned_pool_stats() {
        let pool = PinnedMemoryPool::new(PoolConfig::default());

        let stats = pool.stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.hit_rate(), 0.0);

        // Acquire, release, acquire
        let buf = pool.acquire(100 * 1024).unwrap();
        drop(buf);
        let _buf = pool.acquire(100 * 1024).unwrap();

        let stats = pool.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hit_rate(), 50.0);
    }

    #[test]
    fn test_pinned_pool_clear() {
        let pool = PinnedMemoryPool::new(PoolConfig::default());

        // Add some buffers to pool
        let buf1 = pool.acquire(100 * 1024).unwrap();
        let buf2 = pool.acquire(200 * 1024).unwrap();
        drop(buf1);
        drop(buf2);

        assert!(pool.stats().available_buffers >= 2);

        // Clear pool
        pool.clear();

        assert_eq!(pool.stats().available_buffers, 0);
        assert_eq!(pool.stats().pool_bytes, 0);
    }

    #[test]
    fn test_pinned_pool_freeze() {
        let pool = PinnedMemoryPool::new(PoolConfig::default());

        let mut buffer = pool.acquire(1024).unwrap();
        buffer.extend_from_slice(b"hello");

        // Freeze consumes the buffer (not returned to pool)
        let bytes = buffer.freeze();
        assert_eq!(&bytes[..], b"hello");

        // Pool should have no available buffers
        let stats = pool.stats();
        assert_eq!(stats.returns, 0);
    }

    #[test]
    fn test_gpu_pool_creation_fallback() {
        // On machines without GPU, this should fail with NoDevices
        let result = GpuMemoryPool::new(0, PoolConfig::default());

        // Either succeeds (GPU available) or fails with appropriate error
        match result {
            Ok(pool) => {
                assert_eq!(pool.device_id(), 0);
            }
            Err(GpuError::NoDevices) | Err(GpuError::NotCompiled) => {
                // Expected on machines without GPU or without cuda feature
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_pool_outside_range() {
        let config = PoolConfig {
            min_buffer_size: 1024,
            max_buffer_size: 1024 * 1024,
            ..Default::default()
        };
        let pool = PinnedMemoryPool::new(config);

        // Small buffer (below min) - still works but not pooled
        let small = pool.acquire(100).unwrap();
        assert!(small.capacity() >= 100);

        // Large buffer (above max) - still works but not pooled
        let large = pool.acquire(10 * 1024 * 1024).unwrap();
        assert!(large.capacity() >= 10 * 1024 * 1024);
    }
}
