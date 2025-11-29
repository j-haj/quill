# GPU Tensor Streaming

Zero-copy GPU tensor streaming for ML inference workloads. This guide covers how to use CUDA GPU memory with Quill tensors for efficient network-to-GPU transfers.

## Overview

Quill's tensor support includes optional CUDA GPU integration via the `cuda` feature. When enabled, tensors can be allocated directly in GPU memory, enabling:

- Direct network-to-GPU VRAM transfers (DMA)
- Zero-copy interop with ML frameworks
- Multi-GPU inference servers
- 10-100x improvement over CPU path for large tensors

## Quick Start

### Enable CUDA Feature

Add `quill-tensor` with the `cuda` feature to your `Cargo.toml`:

```toml
[dependencies]
quill-tensor = { version = "0.1", features = ["cuda"] }
```

### Check GPU Availability

```rust
use quill_tensor::{GpuStatus, TensorBuffer};

fn main() {
    let status = GpuStatus::detect();

    match status {
        GpuStatus::Available { device_count } => {
            println!("Found {} GPU(s)", device_count);
        }
        GpuStatus::NotCompiled => {
            println!("CUDA feature not enabled");
        }
        GpuStatus::NoCuda(reason) => {
            println!("CUDA driver not available: {}", reason);
        }
        GpuStatus::NoDevices => {
            println!("No GPU devices found");
        }
    }
}
```

### Allocate GPU Buffers

```rust
use quill_tensor::{TensorBuffer, TensorMeta, DType, Device};

// Method 1: Allocate with fallback (recommended)
let buffer = TensorBuffer::try_allocate_gpu(1024 * 1024, 0)?; // 1MB on GPU 0

// Method 2: Allocate based on TensorMeta
let meta = TensorMeta::new(vec![1024, 768], DType::Float32)
    .with_device(Device::Cuda);
let buffer = meta.allocate_buffer(0)?; // Allocates 3MB

// Method 3: Strict GPU allocation (no fallback)
let buffer = TensorBuffer::allocate_gpu(1024, 0)?;
```

## API Reference

### GpuStatus

Represents GPU availability status:

```rust
pub enum GpuStatus {
    /// CUDA feature not compiled
    NotCompiled,
    /// CUDA driver not available
    NoCuda(String),
    /// No GPU devices found
    NoDevices,
    /// GPU available with device count
    Available { device_count: usize },
}
```

Key methods:
- `GpuStatus::detect()` - Detects GPU availability (cache this result)
- `is_available()` - Returns `true` if GPU can be used
- `device_count()` - Number of available GPUs (0 if unavailable)

### TensorBuffer

Unified buffer for CPU and GPU storage:

```rust
pub enum TensorBuffer {
    Cpu(Bytes),
    #[cfg(feature = "cuda")]
    Cuda(CudaBuffer),
}
```

Key methods:

| Method | Description |
|--------|-------------|
| `cpu(bytes)` | Create CPU buffer from Bytes |
| `cpu_zeros(size)` | Create zero-filled CPU buffer |
| `try_allocate_gpu(size, device)` | Allocate GPU with CPU fallback |
| `allocate_gpu(size, device)` | Allocate GPU (returns error on failure) |
| `len()` | Buffer size in bytes |
| `is_cpu()` / `is_gpu()` | Check buffer location |
| `to_host()` | Copy to CPU Bytes |
| `to_gpu(device)` | Move to GPU |
| `to_cpu()` | Move to CPU |
| `copy_from_slice(data)` | Copy data into buffer |

### CudaBuffer

GPU device memory (only with `cuda` feature):

```rust
pub struct CudaBuffer {
    device_id: usize,
    storage: CudaSlice<u8>,
    len: usize,
}
```

Key methods:

| Method | Description |
|--------|-------------|
| `allocate(size, device)` | Allocate GPU memory |
| `len()` | Buffer size |
| `device_id()` | GPU device ID |
| `copy_from_host(data)` | Host-to-device transfer |
| `copy_to_host()` | Device-to-host transfer |

### Device

Extended with GPU helpers:

```rust
impl Device {
    /// Returns true if this is a GPU device
    pub fn is_gpu(&self) -> bool;

    /// Returns true if this is a CPU device
    pub fn is_cpu(&self) -> bool;

    /// Allocate buffer appropriate for this device
    pub fn allocate_buffer(&self, size: usize, device_id: usize) -> GpuResult<TensorBuffer>;
}
```

### TensorMeta

Extended with buffer allocation:

```rust
impl TensorMeta {
    /// Allocate buffer for this tensor's device
    pub fn allocate_buffer(&self, device_id: usize) -> GpuResult<TensorBuffer>;
}
```

## Graceful Fallback

All GPU operations fall back to CPU when unavailable:

```rust
// This always succeeds, even without GPU
let buffer = TensorBuffer::try_allocate_gpu(1024, 0)?;

if buffer.is_gpu() {
    println!("Allocated on GPU");
} else {
    println!("Fell back to CPU (no GPU available)");
}
```

Fallback occurs when:
1. `cuda` feature not compiled
2. CUDA driver not installed/available
3. No GPU devices found
4. GPU allocation fails (out of memory)

A warning is logged when fallback occurs.

## Memory Transfers

### Host to Device (H2D)

```rust
let data = vec![1.0f32; 1000];
let data_bytes: &[u8] = bytemuck::cast_slice(&data);

// Allocate GPU buffer
let mut buffer = TensorBuffer::allocate_gpu(data_bytes.len(), 0)?;

// Copy to GPU
buffer.copy_from_slice(data_bytes)?;
```

### Device to Host (D2H)

```rust
// Copy back to host
let host_bytes = buffer.to_host()?;

// Or move entire buffer to CPU
let cpu_buffer = buffer.to_cpu()?;
```

### Device to Device

```rust
// Move from GPU 0 to GPU 1
let gpu1_buffer = buffer.to_gpu(1)?;
```

## Integration with Tensor Streaming

### GpuTensorReceiver

Use `GpuTensorReceiver` to stream tensors directly to GPU memory:

```rust
use quill_tensor::{GpuTensorReceiver, GpuReceiverEvent, TensorMeta, Device, DType};

// Create metadata for GPU tensor
let meta = TensorMeta::new(vec![1024, 768], DType::Float32)
    .with_device(Device::Cuda);

// Create GPU-aware receiver (device_id = 0)
let mut receiver = GpuTensorReceiver::new(meta, 0)?;

// Feed incoming frame data
for frame in incoming_frames {
    receiver.feed(&frame.encode());

    // Process frames
    loop {
        match receiver.poll()? {
            GpuReceiverEvent::Metadata(meta) => {
                println!("Received metadata: {:?}", meta.shape);
            }
            GpuReceiverEvent::Data { offset, size } => {
                println!("Received {} bytes at offset {}", size, offset);
            }
            GpuReceiverEvent::End => break,
            GpuReceiverEvent::NeedMoreData => break,
            GpuReceiverEvent::Cancelled(reason) => {
                return Err(format!("Cancelled: {}", reason).into());
            }
        }
    }
}

// Take the completed tensor buffer
let (meta, buffer) = receiver.take()?;

if buffer.is_gpu() {
    println!("Data received directly on GPU!");
}
```

### Progress Tracking

```rust
let mut receiver = GpuTensorReceiver::new(meta, 0)?;

// Check progress during streaming
println!("Expected: {} bytes", receiver.expected_bytes());
println!("Received: {} bytes", receiver.received_bytes());
println!("Complete: {}", receiver.is_complete());
```

### Convert to CPU Tensor

```rust
// For compatibility with existing code that expects CPU tensors
let tensor = receiver.take_tensor()?; // Copies to CPU if on GPU
```

### Flow Control for GPU Memory

GPU memory is limited. Use flow control to prevent OOM:

```rust
use quill_core::TensorCreditTracker;

let tracker = TensorCreditTracker::new(
    256 * 1024,  // 256KB initial credits
    512 * 1024,  // 512KB high water mark
    128 * 1024,  // 128KB low water mark
);

// Before allocating GPU memory
if tracker.should_pause() {
    // Wait for consumer to catch up
}
```

## Error Handling

```rust
use quill_tensor::{GpuError, GpuResult};

fn process_tensor() -> GpuResult<()> {
    let buffer = TensorBuffer::allocate_gpu(1024, 0)?;
    // ...
    Ok(())
}

// Handle errors
match process_tensor() {
    Ok(()) => println!("Success"),
    Err(GpuError::NotCompiled) => println!("Compile with cuda feature"),
    Err(GpuError::NoDevices) => println!("No GPU available"),
    Err(GpuError::AllocationFailed(msg)) => println!("OOM: {}", msg),
    Err(e) => println!("Error: {}", e),
}
```

## Performance Tips

### 1. Cache GPU Status

```rust
// Good: Query once
lazy_static! {
    static ref GPU_STATUS: GpuStatus = GpuStatus::detect();
}

// Bad: Query every time
fn process() {
    if GpuStatus::detect().is_available() { /* ... */ }
}
```

### 2. Reuse Buffers

```rust
// Good: Reuse buffer
let mut buffer = TensorBuffer::allocate_gpu(size, 0)?;
for batch in batches {
    buffer.copy_from_slice(&batch)?;
    process(&buffer)?;
}

// Bad: Allocate each time
for batch in batches {
    let buffer = TensorBuffer::allocate_gpu(size, 0)?;
    buffer.copy_from_slice(&batch)?;
}
```

### 3. Use Appropriate Chunk Sizes

For maximum PCIe throughput:
- **Recommended chunk size**: 4 MB (95% utilization on A100)
- **Minimum for efficiency**: 1 MB
- **Default Quill chunk**: 64 KB (can be configured)

### 4. Use Memory Pools

For high-throughput streaming, use memory pools to avoid repeated allocations:

```rust
use quill_tensor::pool::{PinnedMemoryPool, GpuMemoryPool, PoolConfig};

// Create pools once
let pinned_pool = PinnedMemoryPool::new(PoolConfig::default());
let gpu_pool = GpuMemoryPool::new(0, PoolConfig::default())?;

// Reuse buffers from pool
for batch in batches {
    let mut buffer = gpu_pool.acquire(batch_size)?;
    buffer.copy_from_slice(&batch)?;
    process(&buffer)?;
    // Buffer returns to pool when dropped
}
```

## Memory Pools

Memory pools reduce allocation overhead during high-throughput tensor streaming by reusing buffers.

### PinnedMemoryPool

Pools page-locked (pinned) host memory for efficient DMA transfers:

```rust
use quill_tensor::pool::{PinnedMemoryPool, PoolConfig};

// Create pool with default configuration
let pool = PinnedMemoryPool::new(PoolConfig::default());

// Acquire buffer from pool
let mut buffer = pool.acquire(1024 * 1024)?; // 1MB
buffer.extend_from_slice(&data);

// Buffer automatically returns to pool when dropped
drop(buffer);

// Check pool statistics
let stats = pool.stats();
println!("Hit rate: {:.1}%", stats.hit_rate());
```

### GpuMemoryPool

Pools GPU memory buffers to avoid cudaMalloc/cudaFree latency:

```rust
use quill_tensor::pool::{GpuMemoryPool, PoolConfig};

// Create pool for GPU device 0
let pool = GpuMemoryPool::new(0, PoolConfig::default())?;

// Acquire GPU buffer
let mut buffer = pool.acquire(1024 * 1024)?;
buffer.copy_from_slice(&host_data)?;

// Buffer returns to pool when dropped
```

### PoolConfig

Configure pool behavior:

```rust
use quill_tensor::pool::PoolConfig;

// Default configuration
let config = PoolConfig::default();
// max_pool_size: 256 MB
// min_buffer_size: 64 KB
// max_buffer_size: 64 MB
// size_classes: 16 (power-of-2 bucketing)

// High-throughput configuration
let config = PoolConfig::high_throughput();
// max_pool_size: 512 MB
// min_buffer_size: 1 MB
// preallocate: true

// Low-memory configuration
let config = PoolConfig::low_memory();
// max_pool_size: 64 MB
// min_buffer_size: 16 KB
```

### PooledGpuReceiver

For high-throughput streaming, use `PooledGpuReceiver` which integrates with memory pools:

```rust
use quill_tensor::{PooledGpuReceiver, TensorMeta, DType, Device};
use quill_tensor::pool::{PinnedMemoryPool, GpuMemoryPool, PoolConfig};

// Create pools (typically done once at startup)
let pinned_pool = PinnedMemoryPool::new(PoolConfig::default());
let gpu_pool = GpuMemoryPool::new(0, PoolConfig::default())?;

// Create pooled receiver
let meta = TensorMeta::new(vec![1024, 768], DType::Float32)
    .with_device(Device::Cuda);
let mut receiver = PooledGpuReceiver::new(meta, pinned_pool, Some(gpu_pool))?;

// Stream tensor data
for frame in incoming_frames {
    receiver.feed(&frame.encode());
    while let Ok(event) = receiver.poll() {
        match event {
            GpuReceiverEvent::End => break,
            GpuReceiverEvent::NeedMoreData => break,
            _ => continue,
        }
    }
}

// Check pool statistics
println!("Pinned pool hit rate: {:.1}%", receiver.pinned_pool_stats().hit_rate());
if let Some(gpu_stats) = receiver.gpu_pool_stats() {
    println!("GPU pool hit rate: {:.1}%", gpu_stats.hit_rate());
}

// Take result - buffers return to pool when dropped
let (meta, buffer) = receiver.take()?;
```

### Pool Statistics

Monitor pool efficiency:

```rust
let stats = pool.stats();

println!("Available buffers: {}", stats.available_buffers);
println!("In-use buffers: {}", stats.in_use_buffers);
println!("Pool bytes: {}", stats.pool_bytes);
println!("Hits: {} ({:.1}%)", stats.hits, stats.hit_rate());
println!("Misses: {}", stats.misses);
println!("Returns: {}", stats.returns);
println!("Drops: {}", stats.drops);
```

## Build Configuration

### With CUDA Support

```bash
# Build with CUDA
cargo build --features cuda

# Run tests with CUDA
cargo test --features cuda
```

### Without CUDA Support

```bash
# Build without CUDA (default)
cargo build

# All GPU operations fall back to CPU
```

### Check CUDA at Runtime

```rust
fn main() {
    #[cfg(feature = "cuda")]
    println!("Built with CUDA support");

    #[cfg(not(feature = "cuda"))]
    println!("Built without CUDA support");

    // Runtime check
    println!("GPU available: {}", GpuStatus::detect().is_available());
}
```

## Troubleshooting

### "CUDA driver not available"

1. Ensure NVIDIA drivers are installed
2. Check `nvidia-smi` works
3. Verify CUDA toolkit installation

### "No CUDA devices found"

1. Check GPU is detected: `nvidia-smi`
2. Verify GPU supports CUDA
3. Check CUDA_VISIBLE_DEVICES environment variable

### "GPU allocation failed"

1. Check available GPU memory: `nvidia-smi`
2. Reduce batch size
3. Use flow control to limit concurrent allocations

### Compilation fails with cuda feature

1. Ensure CUDA toolkit is installed
2. Set `CUDA_PATH` environment variable
3. Check cudarc requirements

## Future Enhancements

- **Phase 19.4**: DLPack for PyTorch/JAX interop, Python bindings
- **Async DMA**: Asynchronous memory transfers for overlapping compute
- **Multi-stream**: Concurrent transfers and compute on different CUDA streams

## See Also

- [Flow Control](./flow-control.md) - Byte-based flow control for tensors
- [Tensor Streaming](./tensor-streaming.md) - Zero-copy tensor streaming
- [Performance Guide](./performance.md) - Optimization tips
