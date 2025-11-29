//! Tensor types and streaming support for the Quill RPC framework.
//!
//! This crate provides first-class tensor and token streaming support for
//! LLM inference and agent-to-agent communication.
//!
//! # Features
//!
//! - **Zero-copy streaming**: Pre-allocate buffers based on tensor metadata
//! - **ML data types**: f32, f16, bf16, i8, i32, i64, u8, bool
//! - **Tensor streaming**: Chunk large tensors for efficient transfer
//! - **Token batching**: Efficient LLM token generation streaming
//! - **GPU support**: Optional CUDA GPU memory via `cuda` feature
//!
//! # GPU Support
//!
//! Enable the `cuda` feature for GPU tensor storage:
//!
//! ```toml
//! [dependencies]
//! quill-tensor = { version = "0.1", features = ["cuda"] }
//! ```
//!
//! GPU operations gracefully fall back to CPU when CUDA is unavailable.
//!
//! # Example
//!
//! ```rust
//! use quill_tensor::{Tensor, TensorMeta, DType};
//! use bytes::Bytes;
//!
//! // Create a tensor
//! let meta = TensorMeta::new(vec![2, 3], DType::Float32);
//! let data = vec![1.0f32, 2.0, 3.0, 4.0, 5.0, 6.0];
//! let tensor = Tensor::from_f32(&meta, &data);
//!
//! assert_eq!(tensor.numel(), 6);
//! assert_eq!(tensor.byte_size(), 24);
//! ```

pub mod buffer;
pub mod dtype;
pub mod frame;
pub mod pool;
pub mod stream;
pub mod tensor;
pub mod token;

pub use buffer::{GpuError, GpuResult, GpuStatus, TensorBuffer};
pub use dtype::DType;
pub use frame::{FrameType, TensorFrame, TensorFrameError, TensorFrameParser};
pub use pool::{
    GpuMemoryPool, PinnedMemoryPool, PoolConfig, PoolStats, PooledBuffer, PooledGpuBuffer,
};
pub use stream::{
    GpuReceiverEvent, GpuTensorReceiver, PooledGpuReceiver, PooledTensorBuffer, TensorChunk,
    TensorReceiver, TensorSender, TensorStream,
};
pub use tensor::{Device, Tensor, TensorMeta, TensorView};
pub use token::{Token, TokenBatch, TokenBatchBuilder, TokenStream};

/// Re-export half crate types for convenience
pub use half::{bf16, f16};

/// Re-export CudaBuffer when cuda feature is enabled
#[cfg(feature = "cuda")]
pub use buffer::CudaBuffer;
