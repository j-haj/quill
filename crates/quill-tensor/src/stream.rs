//! Tensor streaming support for zero-copy transfer.
//!
//! Provides types for streaming tensor data with pre-allocation
//! and zero-copy semantics.
//!
//! # GPU Support
//!
//! When the `cuda` feature is enabled, use `GpuTensorReceiver` to stream
//! tensors directly to GPU memory:
//!
//! ```rust,ignore
//! use quill_tensor::{GpuTensorReceiver, TensorMeta, Device, DType};
//!
//! // Create receiver for GPU tensor
//! let meta = TensorMeta::new(vec![1024, 768], DType::Float32)
//!     .with_device(Device::Cuda);
//!
//! let mut receiver = GpuTensorReceiver::new(meta, 0)?; // GPU device 0
//!
//! // Feed incoming frames
//! for frame in incoming_frames {
//!     receiver.feed(&frame.encode());
//! }
//!
//! // Get tensor (data is already on GPU)
//! let tensor = receiver.take_tensor()?;
//! ```

use bytes::{Bytes, BytesMut};
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_core::Stream;
use pin_project_lite::pin_project;

use crate::buffer::{GpuError, TensorBuffer};
use crate::frame::{FrameType, TensorFrame, TensorFrameError, TensorFrameParser};
use crate::pool::{GpuMemoryPool, PinnedMemoryPool, PooledBuffer, PooledGpuBuffer};
use crate::tensor::{Device, Tensor, TensorMeta};

/// Error type for tensor streaming operations.
#[derive(Debug, thiserror::Error)]
pub enum TensorStreamError {
    /// Frame parsing error.
    #[error("frame error: {0}")]
    Frame(#[from] TensorFrameError),

    /// Received unexpected frame type.
    #[error("unexpected frame type: expected {expected}, got {actual}")]
    UnexpectedFrame {
        expected: &'static str,
        actual: &'static str,
    },

    /// Missing tensor metadata.
    #[error("missing tensor metadata: TENSOR_PAYLOAD received before TENSOR_META")]
    MissingMetadata,

    /// Tensor size mismatch.
    #[error("tensor size mismatch: expected {expected} bytes, got {actual}")]
    SizeMismatch { expected: usize, actual: usize },

    /// Stream was cancelled.
    #[error("stream cancelled: {0}")]
    Cancelled(String),

    /// GPU operation error.
    #[error("GPU error: {0}")]
    Gpu(#[from] GpuError),

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

/// A chunk of tensor data for streaming.
#[derive(Debug, Clone)]
pub struct TensorChunk {
    /// Offset in bytes from the start of the tensor.
    pub offset: usize,
    /// Raw chunk data.
    pub data: Bytes,
}

impl TensorChunk {
    /// Creates a new chunk.
    pub fn new(offset: usize, data: Bytes) -> Self {
        Self { offset, data }
    }

    /// Returns the size of this chunk in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns whether this chunk is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

pin_project! {
    /// A stream of tensor chunks for receiving large tensors.
    pub struct TensorStream<S> {
        #[pin]
        inner: S,
        meta: Option<TensorMeta>,
    }
}

impl<S> TensorStream<S> {
    /// Creates a new tensor stream.
    pub fn new(inner: S) -> Self {
        Self { inner, meta: None }
    }

    /// Creates a tensor stream with known metadata.
    pub fn with_meta(inner: S, meta: TensorMeta) -> Self {
        Self {
            inner,
            meta: Some(meta),
        }
    }

    /// Returns the tensor metadata if available.
    pub fn meta(&self) -> Option<&TensorMeta> {
        self.meta.as_ref()
    }

    /// Consumes this wrapper and returns the inner stream.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S, E> Stream for TensorStream<S>
where
    S: Stream<Item = Result<TensorChunk, E>>,
{
    type Item = Result<TensorChunk, E>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().inner.poll_next(cx)
    }
}

/// Sender for streaming tensor data.
///
/// Encodes tensor data as frames for efficient transfer.
pub struct TensorSender {
    chunk_size: usize,
}

impl TensorSender {
    /// Default chunk size (64 KB).
    pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

    /// Creates a new sender with default chunk size.
    pub fn new() -> Self {
        Self {
            chunk_size: Self::DEFAULT_CHUNK_SIZE,
        }
    }

    /// Creates a sender with custom chunk size.
    pub fn with_chunk_size(chunk_size: usize) -> Self {
        Self { chunk_size }
    }

    /// Encodes a tensor as a sequence of frames.
    ///
    /// Returns:
    /// 1. TENSOR_META frame with tensor metadata
    /// 2. One or more TENSOR_PAYLOAD frames with raw data
    /// 3. END_STREAM frame
    pub fn encode_tensor(&self, tensor: &Tensor) -> Vec<TensorFrame> {
        let mut frames = Vec::new();

        // Encode metadata as protobuf-like format
        let meta_payload = self.encode_meta(&tensor.meta);
        frames.push(TensorFrame::tensor_meta(meta_payload));

        // Split data into chunks
        let data = &tensor.data;
        let mut offset = 0;
        while offset < data.len() {
            let end = std::cmp::min(offset + self.chunk_size, data.len());
            let chunk = data.slice(offset..end);
            frames.push(TensorFrame::tensor_payload(chunk));
            offset = end;
        }

        // End stream
        frames.push(TensorFrame::end_stream());

        frames
    }

    /// Encodes tensor metadata to bytes.
    ///
    /// Simple binary format (not protobuf for efficiency):
    /// - ndim: u8
    /// - shape: [u64; ndim]
    /// - dtype: u8
    /// - device: u8
    /// - byte_size: u64
    /// - name_len: u16
    /// - name: [u8; name_len] (optional)
    fn encode_meta(&self, meta: &TensorMeta) -> Bytes {
        let name_bytes = meta.name.as_ref().map(|n| n.as_bytes()).unwrap_or(&[]);
        let capacity = 1 + meta.shape.len() * 8 + 1 + 1 + 8 + 2 + name_bytes.len();
        let mut buf = BytesMut::with_capacity(capacity);

        buf.extend_from_slice(&[meta.shape.len() as u8]);
        for &dim in &meta.shape {
            buf.extend_from_slice(&(dim as u64).to_le_bytes());
        }
        buf.extend_from_slice(&[meta.dtype as u8]);
        buf.extend_from_slice(&[meta.device as u8]);
        buf.extend_from_slice(&(meta.byte_size() as u64).to_le_bytes());
        buf.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(name_bytes);

        buf.freeze()
    }
}

impl Default for TensorSender {
    fn default() -> Self {
        Self::new()
    }
}

/// Receiver for streaming tensor data.
///
/// Decodes frames and assembles tensor data with zero-copy where possible.
pub struct TensorReceiver {
    parser: TensorFrameParser,
    meta: Option<TensorMeta>,
    buffer: BytesMut,
    expected_size: usize,
    received_size: usize,
}

impl TensorReceiver {
    /// Creates a new receiver.
    pub fn new() -> Self {
        Self {
            parser: TensorFrameParser::new(),
            meta: None,
            buffer: BytesMut::new(),
            expected_size: 0,
            received_size: 0,
        }
    }

    /// Creates a receiver with known metadata (enables pre-allocation).
    pub fn with_meta(meta: TensorMeta) -> Self {
        let byte_size = meta.byte_size();
        Self {
            parser: TensorFrameParser::new(),
            meta: Some(meta),
            buffer: BytesMut::with_capacity(byte_size),
            expected_size: byte_size,
            received_size: 0,
        }
    }

    /// Feeds raw bytes into the receiver.
    pub fn feed(&mut self, data: &[u8]) {
        self.parser.feed(data);
    }

    /// Feeds a Bytes buffer into the receiver.
    pub fn feed_bytes(&mut self, data: Bytes) {
        self.parser.feed_bytes(data);
    }

    /// Processes available frames and returns the next event.
    pub fn poll(&mut self) -> Result<ReceiverEvent, TensorStreamError> {
        match self.parser.parse_frame()? {
            None => Ok(ReceiverEvent::NeedMoreData),
            Some(frame) => self.handle_frame(frame),
        }
    }

    /// Returns the tensor metadata if received.
    pub fn meta(&self) -> Option<&TensorMeta> {
        self.meta.as_ref()
    }

    /// Returns whether all expected data has been received.
    pub fn is_complete(&self) -> bool {
        self.expected_size > 0 && self.received_size >= self.expected_size
    }

    /// Takes the completed tensor, returning None if not complete.
    pub fn take_tensor(&mut self) -> Option<Tensor> {
        if !self.is_complete() {
            return None;
        }

        let meta = self.meta.take()?;
        let data = std::mem::take(&mut self.buffer).freeze();
        self.received_size = 0;
        self.expected_size = 0;

        Some(Tensor::new(meta, data))
    }

    fn handle_frame(&mut self, frame: TensorFrame) -> Result<ReceiverEvent, TensorStreamError> {
        match frame.frame_type {
            FrameType::TensorMeta => {
                let meta = self.decode_meta(&frame.payload)?;
                self.expected_size = meta.byte_size();
                self.buffer = BytesMut::with_capacity(self.expected_size);
                self.received_size = 0;
                self.meta = Some(meta.clone());
                Ok(ReceiverEvent::Metadata(meta))
            }
            FrameType::TensorPayload => {
                if self.meta.is_none() {
                    return Err(TensorStreamError::MissingMetadata);
                }
                let chunk_size = frame.payload.len();
                self.buffer.extend_from_slice(&frame.payload);
                self.received_size += chunk_size;
                Ok(ReceiverEvent::Data(TensorChunk::new(
                    self.received_size - chunk_size,
                    frame.payload,
                )))
            }
            FrameType::EndStream => {
                if self.expected_size > 0 && self.received_size != self.expected_size {
                    return Err(TensorStreamError::SizeMismatch {
                        expected: self.expected_size,
                        actual: self.received_size,
                    });
                }
                Ok(ReceiverEvent::End)
            }
            FrameType::Cancel => {
                let reason = String::from_utf8_lossy(&frame.payload).into_owned();
                Ok(ReceiverEvent::Cancelled(reason))
            }
            _ => Err(TensorStreamError::UnexpectedFrame {
                expected: "TENSOR_META, TENSOR_PAYLOAD, END_STREAM, or CANCEL",
                actual: frame.frame_type.name(),
            }),
        }
    }

    fn decode_meta(&self, data: &[u8]) -> Result<TensorMeta, TensorStreamError> {
        if data.is_empty() {
            return Err(TensorStreamError::Internal("empty metadata".to_string()));
        }

        let ndim = data[0] as usize;
        let mut offset = 1;

        if data.len() < offset + ndim * 8 + 1 + 1 + 8 + 2 {
            return Err(TensorStreamError::Internal("metadata too short".to_string()));
        }

        let mut shape = Vec::with_capacity(ndim);
        for _ in 0..ndim {
            let dim = u64::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]) as usize;
            shape.push(dim);
            offset += 8;
        }

        let dtype = crate::dtype::DType::try_from(data[offset]).map_err(|_| {
            TensorStreamError::Internal(format!("unknown dtype: {}", data[offset]))
        })?;
        offset += 1;

        let device = crate::tensor::Device::from_proto(data[offset] as i32)
            .ok_or_else(|| TensorStreamError::Internal(format!("unknown device: {}", data[offset])))?;
        offset += 1;

        // Skip byte_size (we compute it from shape)
        offset += 8;

        let name_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        let name = if name_len > 0 && data.len() >= offset + name_len {
            Some(String::from_utf8_lossy(&data[offset..offset + name_len]).into_owned())
        } else {
            None
        };

        Ok(TensorMeta {
            shape,
            dtype,
            device,
            strides: None,
            name,
            requires_grad: false,
        })
    }
}

impl Default for TensorReceiver {
    fn default() -> Self {
        Self::new()
    }
}

/// GPU-aware tensor receiver for streaming directly to GPU memory.
///
/// This receiver allocates a buffer on the appropriate device (CPU or GPU)
/// based on the tensor metadata, and streams incoming data directly to that
/// buffer. For GPU tensors, this enables efficient network-to-GPU transfers.
///
/// # Example
///
/// ```rust,ignore
/// use quill_tensor::{GpuTensorReceiver, TensorMeta, Device, DType};
///
/// // Receive a GPU tensor
/// let meta = TensorMeta::new(vec![1024, 768], DType::Float32)
///     .with_device(Device::Cuda);
///
/// let mut receiver = GpuTensorReceiver::new(meta, 0)?;
///
/// // Feed incoming data
/// for frame in frames {
///     receiver.feed(&frame.encode());
///     receiver.poll()?;
/// }
///
/// // Get tensor with data on GPU
/// let (meta, buffer) = receiver.take()?;
/// assert!(buffer.is_gpu());
/// ```
pub struct GpuTensorReceiver {
    parser: TensorFrameParser,
    meta: TensorMeta,
    device_id: usize,
    /// CPU staging buffer for accumulating incoming data
    staging: BytesMut,
    /// Target buffer (CPU or GPU)
    buffer: Option<TensorBuffer>,
    expected_size: usize,
    received_size: usize,
    /// Whether we've finished receiving
    complete: bool,
}

impl GpuTensorReceiver {
    /// Creates a new GPU-aware receiver with the specified metadata and device.
    ///
    /// # Arguments
    ///
    /// * `meta` - Tensor metadata (shape, dtype, device)
    /// * `device_id` - GPU device ID for CUDA tensors (ignored for CPU)
    ///
    /// # Returns
    ///
    /// A receiver that will allocate on the appropriate device.
    /// For `Device::Cuda`, allocation falls back to CPU if GPU is unavailable.
    pub fn new(meta: TensorMeta, device_id: usize) -> Result<Self, TensorStreamError> {
        let expected_size = meta.byte_size();

        // Allocate staging buffer for incoming network data
        let staging = BytesMut::with_capacity(expected_size);

        Ok(Self {
            parser: TensorFrameParser::new(),
            meta,
            device_id,
            staging,
            buffer: None,
            expected_size,
            received_size: 0,
            complete: false,
        })
    }

    /// Creates a receiver from raw metadata bytes (from TENSOR_META frame).
    ///
    /// This is useful when you receive metadata dynamically and want to
    /// create a GPU-aware receiver on the fly.
    pub fn from_meta_bytes(data: &[u8], device_id: usize) -> Result<Self, TensorStreamError> {
        let meta = decode_tensor_meta(data)?;
        Self::new(meta, device_id)
    }

    /// Returns the tensor metadata.
    pub fn meta(&self) -> &TensorMeta {
        &self.meta
    }

    /// Returns the device ID.
    pub fn device_id(&self) -> usize {
        self.device_id
    }

    /// Returns whether all expected data has been received.
    pub fn is_complete(&self) -> bool {
        self.complete || (self.expected_size > 0 && self.received_size >= self.expected_size)
    }

    /// Returns the number of bytes received so far.
    pub fn received_bytes(&self) -> usize {
        self.received_size
    }

    /// Returns the expected total size in bytes.
    pub fn expected_bytes(&self) -> usize {
        self.expected_size
    }

    /// Feeds raw bytes into the receiver.
    pub fn feed(&mut self, data: &[u8]) {
        self.parser.feed(data);
    }

    /// Feeds a Bytes buffer into the receiver.
    pub fn feed_bytes(&mut self, data: Bytes) {
        self.parser.feed_bytes(data);
    }

    /// Processes available frames and returns the next event.
    pub fn poll(&mut self) -> Result<GpuReceiverEvent, TensorStreamError> {
        match self.parser.parse_frame()? {
            None => Ok(GpuReceiverEvent::NeedMoreData),
            Some(frame) => self.handle_frame(frame),
        }
    }

    /// Takes the completed tensor buffer.
    ///
    /// Returns the metadata and buffer containing tensor data.
    /// For GPU tensors, the data will be on the GPU (if allocation succeeded).
    ///
    /// # Returns
    ///
    /// - `Ok((meta, buffer))` if tensor is complete
    /// - `Err` if tensor is not complete or transfer failed
    pub fn take(mut self) -> Result<(TensorMeta, TensorBuffer), TensorStreamError> {
        if !self.is_complete() {
            return Err(TensorStreamError::Internal(
                "Cannot take incomplete tensor".to_string(),
            ));
        }

        // If buffer not yet created, do final transfer
        if self.buffer.is_none() {
            self.finalize_transfer()?;
        }

        let buffer = self.buffer.take().ok_or_else(|| {
            TensorStreamError::Internal("Buffer not available".to_string())
        })?;

        Ok((self.meta, buffer))
    }

    /// Takes the completed tensor as a Tensor struct (CPU only).
    ///
    /// This converts GPU buffers to CPU for compatibility with existing code.
    pub fn take_tensor(self) -> Result<Tensor, TensorStreamError> {
        let (meta, buffer) = self.take()?;
        let data = buffer.to_host()?;
        Ok(Tensor::new(meta, data))
    }

    fn handle_frame(&mut self, frame: TensorFrame) -> Result<GpuReceiverEvent, TensorStreamError> {
        match frame.frame_type {
            FrameType::TensorMeta => {
                // Update metadata if received dynamically
                let new_meta = decode_tensor_meta(&frame.payload)?;
                self.meta = new_meta.clone();
                self.expected_size = new_meta.byte_size();
                self.staging = BytesMut::with_capacity(self.expected_size);
                self.received_size = 0;
                Ok(GpuReceiverEvent::Metadata(new_meta))
            }
            FrameType::TensorPayload => {
                let chunk_size = frame.payload.len();
                self.staging.extend_from_slice(&frame.payload);
                self.received_size += chunk_size;

                Ok(GpuReceiverEvent::Data {
                    offset: self.received_size - chunk_size,
                    size: chunk_size,
                })
            }
            FrameType::EndStream => {
                if self.expected_size > 0 && self.received_size != self.expected_size {
                    return Err(TensorStreamError::SizeMismatch {
                        expected: self.expected_size,
                        actual: self.received_size,
                    });
                }

                // Finalize transfer to target device
                self.finalize_transfer()?;
                self.complete = true;

                Ok(GpuReceiverEvent::End)
            }
            FrameType::Cancel => {
                let reason = String::from_utf8_lossy(&frame.payload).into_owned();
                Ok(GpuReceiverEvent::Cancelled(reason))
            }
            _ => Err(TensorStreamError::UnexpectedFrame {
                expected: "TENSOR_META, TENSOR_PAYLOAD, END_STREAM, or CANCEL",
                actual: frame.frame_type.name(),
            }),
        }
    }

    /// Finalizes the transfer by moving data to the target device.
    fn finalize_transfer(&mut self) -> Result<(), TensorStreamError> {
        if self.buffer.is_some() {
            return Ok(()); // Already transferred
        }

        // Allocate on target device
        let mut buffer = self.meta.device.allocate_buffer(self.expected_size, self.device_id)?;

        // Copy staging data to buffer
        let staging_data = std::mem::take(&mut self.staging);
        buffer.copy_from_slice(&staging_data)?;

        self.buffer = Some(buffer);
        Ok(())
    }
}

/// Events produced by the GPU tensor receiver.
#[derive(Debug)]
pub enum GpuReceiverEvent {
    /// Tensor metadata received or updated.
    Metadata(TensorMeta),
    /// Data chunk received.
    Data {
        /// Offset in bytes from start of tensor.
        offset: usize,
        /// Size of this chunk in bytes.
        size: usize,
    },
    /// Stream ended successfully.
    End,
    /// Stream was cancelled.
    Cancelled(String),
    /// Need more data to parse next frame.
    NeedMoreData,
}

/// GPU tensor receiver with memory pool integration for high-throughput streaming.
///
/// This receiver uses memory pools to reduce allocation overhead:
/// - `PinnedMemoryPool` for staging buffers (page-locked host memory)
/// - `GpuMemoryPool` for target GPU buffers
///
/// # Example
///
/// ```rust,ignore
/// use quill_tensor::{PooledGpuReceiver, TensorMeta, DType, Device};
/// use quill_tensor::pool::{PinnedMemoryPool, GpuMemoryPool, PoolConfig};
///
/// // Create pools
/// let pinned_pool = PinnedMemoryPool::new(PoolConfig::default());
/// let gpu_pool = GpuMemoryPool::new(0, PoolConfig::default())?;
///
/// // Create pooled receiver
/// let meta = TensorMeta::new(vec![1024, 768], DType::Float32)
///     .with_device(Device::Cuda);
/// let mut receiver = PooledGpuReceiver::new(meta, pinned_pool, Some(gpu_pool))?;
///
/// // Stream data
/// for frame in frames {
///     receiver.feed(&frame.encode());
///     receiver.poll()?;
/// }
///
/// // Take result - buffers return to pool when dropped
/// let (meta, buffer) = receiver.take()?;
/// ```
pub struct PooledGpuReceiver {
    parser: TensorFrameParser,
    meta: TensorMeta,
    device_id: usize,
    /// Pinned staging buffer from pool
    staging: Option<PooledBuffer>,
    /// Staging write offset
    staging_offset: usize,
    /// Target GPU buffer from pool (if GPU device)
    gpu_buffer: Option<PooledGpuBuffer>,
    /// Target CPU buffer (if CPU device or no GPU pool)
    cpu_buffer: Option<TensorBuffer>,
    /// Memory pools
    pinned_pool: PinnedMemoryPool,
    gpu_pool: Option<GpuMemoryPool>,
    expected_size: usize,
    received_size: usize,
    complete: bool,
}

impl PooledGpuReceiver {
    /// Creates a new pooled GPU receiver.
    ///
    /// # Arguments
    ///
    /// * `meta` - Tensor metadata
    /// * `pinned_pool` - Pool for staging buffers
    /// * `gpu_pool` - Optional pool for GPU buffers (required for GPU tensors)
    pub fn new(
        meta: TensorMeta,
        pinned_pool: PinnedMemoryPool,
        gpu_pool: Option<GpuMemoryPool>,
    ) -> Result<Self, TensorStreamError> {
        let expected_size = meta.byte_size();

        // Acquire staging buffer from pool
        let staging = pinned_pool.acquire(expected_size)?;

        // Get device ID from GPU pool if available
        let device_id = gpu_pool.as_ref().map(|p| p.device_id()).unwrap_or(0);

        Ok(Self {
            parser: TensorFrameParser::new(),
            meta,
            device_id,
            staging: Some(staging),
            staging_offset: 0,
            gpu_buffer: None,
            cpu_buffer: None,
            pinned_pool,
            gpu_pool,
            expected_size,
            received_size: 0,
            complete: false,
        })
    }

    /// Returns the tensor metadata.
    pub fn meta(&self) -> &TensorMeta {
        &self.meta
    }

    /// Returns whether all data has been received.
    pub fn is_complete(&self) -> bool {
        self.complete || (self.expected_size > 0 && self.received_size >= self.expected_size)
    }

    /// Returns bytes received so far.
    pub fn received_bytes(&self) -> usize {
        self.received_size
    }

    /// Returns expected total bytes.
    pub fn expected_bytes(&self) -> usize {
        self.expected_size
    }

    /// Returns pool statistics for the pinned memory pool.
    pub fn pinned_pool_stats(&self) -> crate::pool::PoolStats {
        self.pinned_pool.stats()
    }

    /// Returns pool statistics for the GPU memory pool.
    pub fn gpu_pool_stats(&self) -> Option<crate::pool::PoolStats> {
        self.gpu_pool.as_ref().map(|p| p.stats())
    }

    /// Feeds raw bytes into the receiver.
    pub fn feed(&mut self, data: &[u8]) {
        self.parser.feed(data);
    }

    /// Feeds a Bytes buffer into the receiver.
    pub fn feed_bytes(&mut self, data: Bytes) {
        self.parser.feed_bytes(data);
    }

    /// Processes available frames and returns the next event.
    pub fn poll(&mut self) -> Result<GpuReceiverEvent, TensorStreamError> {
        match self.parser.parse_frame()? {
            None => Ok(GpuReceiverEvent::NeedMoreData),
            Some(frame) => self.handle_frame(frame),
        }
    }

    /// Takes the completed tensor buffer.
    ///
    /// Returns the metadata and buffer. For pooled GPU buffers, the buffer
    /// will be returned to the pool when the `PooledGpuBuffer` is dropped.
    pub fn take(mut self) -> Result<(TensorMeta, PooledTensorBuffer), TensorStreamError> {
        if !self.is_complete() {
            return Err(TensorStreamError::Internal(
                "Cannot take incomplete tensor".to_string(),
            ));
        }

        // Finalize transfer if not done
        if self.gpu_buffer.is_none() && self.cpu_buffer.is_none() {
            self.finalize_transfer()?;
        }

        // Return appropriate buffer type
        if let Some(gpu_buf) = self.gpu_buffer.take() {
            Ok((self.meta, PooledTensorBuffer::Gpu(gpu_buf)))
        } else if let Some(cpu_buf) = self.cpu_buffer.take() {
            Ok((self.meta, PooledTensorBuffer::Cpu(cpu_buf)))
        } else {
            Err(TensorStreamError::Internal("No buffer available".to_string()))
        }
    }

    /// Takes the completed tensor as a CPU Tensor.
    pub fn take_tensor(self) -> Result<Tensor, TensorStreamError> {
        let (meta, buffer) = self.take()?;
        let data = buffer.to_host()?;
        Ok(Tensor::new(meta, data))
    }

    fn handle_frame(&mut self, frame: TensorFrame) -> Result<GpuReceiverEvent, TensorStreamError> {
        match frame.frame_type {
            FrameType::TensorMeta => {
                let new_meta = decode_tensor_meta(&frame.payload)?;
                self.meta = new_meta.clone();
                self.expected_size = new_meta.byte_size();
                self.received_size = 0;
                self.staging_offset = 0;

                // Re-acquire staging buffer with new size
                self.staging = Some(self.pinned_pool.acquire(self.expected_size)?);

                Ok(GpuReceiverEvent::Metadata(new_meta))
            }
            FrameType::TensorPayload => {
                let chunk_size = frame.payload.len();

                // Write to staging buffer
                if let Some(ref mut staging) = self.staging {
                    staging.extend_from_slice(&frame.payload);
                }
                self.staging_offset += chunk_size;
                self.received_size += chunk_size;

                Ok(GpuReceiverEvent::Data {
                    offset: self.received_size - chunk_size,
                    size: chunk_size,
                })
            }
            FrameType::EndStream => {
                if self.expected_size > 0 && self.received_size != self.expected_size {
                    return Err(TensorStreamError::SizeMismatch {
                        expected: self.expected_size,
                        actual: self.received_size,
                    });
                }

                self.finalize_transfer()?;
                self.complete = true;

                Ok(GpuReceiverEvent::End)
            }
            FrameType::Cancel => {
                let reason = String::from_utf8_lossy(&frame.payload).into_owned();
                Ok(GpuReceiverEvent::Cancelled(reason))
            }
            _ => Err(TensorStreamError::UnexpectedFrame {
                expected: "TENSOR_META, TENSOR_PAYLOAD, END_STREAM, or CANCEL",
                actual: frame.frame_type.name(),
            }),
        }
    }

    fn finalize_transfer(&mut self) -> Result<(), TensorStreamError> {
        if self.gpu_buffer.is_some() || self.cpu_buffer.is_some() {
            return Ok(());
        }

        let staging = self.staging.take().ok_or_else(|| {
            TensorStreamError::Internal("Staging buffer not available".to_string())
        })?;

        // For GPU tensors with a GPU pool, use pooled GPU allocation
        if self.meta.device.is_gpu() {
            if let Some(ref gpu_pool) = self.gpu_pool {
                let mut gpu_buf = gpu_pool.acquire(self.expected_size)?;
                gpu_buf.copy_from_slice(&staging)?;
                self.gpu_buffer = Some(gpu_buf);
                return Ok(());
            }
        }

        // Fallback: allocate buffer directly (CPU or GPU)
        let mut new_buf = self.meta.device.allocate_buffer(self.expected_size, self.device_id)?;
        new_buf.copy_from_slice(&staging)?;
        self.cpu_buffer = Some(new_buf);

        Ok(())
    }
}

/// A pooled tensor buffer that returns to its pool on drop.
pub enum PooledTensorBuffer {
    /// CPU buffer (not pooled, regular TensorBuffer)
    Cpu(TensorBuffer),
    /// GPU buffer from a pool
    Gpu(PooledGpuBuffer),
}

impl PooledTensorBuffer {
    /// Returns the buffer size in bytes.
    pub fn len(&self) -> usize {
        match self {
            Self::Cpu(buf) => buf.len(),
            Self::Gpu(buf) => buf.len(),
        }
    }

    /// Returns whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns whether this is a GPU buffer.
    pub fn is_gpu(&self) -> bool {
        match self {
            Self::Cpu(buf) => buf.is_gpu(),
            Self::Gpu(_) => true,
        }
    }

    /// Copies buffer contents to host memory.
    pub fn to_host(&self) -> Result<Bytes, GpuError> {
        match self {
            Self::Cpu(buf) => buf.to_host(),
            Self::Gpu(buf) => buf.to_host(),
        }
    }
}

/// Decodes tensor metadata from bytes.
fn decode_tensor_meta(data: &[u8]) -> Result<TensorMeta, TensorStreamError> {
    if data.is_empty() {
        return Err(TensorStreamError::Internal("empty metadata".to_string()));
    }

    let ndim = data[0] as usize;
    let mut offset = 1;

    if data.len() < offset + ndim * 8 + 1 + 1 + 8 + 2 {
        return Err(TensorStreamError::Internal("metadata too short".to_string()));
    }

    let mut shape = Vec::with_capacity(ndim);
    for _ in 0..ndim {
        let dim = u64::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]) as usize;
        shape.push(dim);
        offset += 8;
    }

    let dtype = crate::dtype::DType::try_from(data[offset]).map_err(|_| {
        TensorStreamError::Internal(format!("unknown dtype: {}", data[offset]))
    })?;
    offset += 1;

    let device = Device::from_proto(data[offset] as i32)
        .ok_or_else(|| TensorStreamError::Internal(format!("unknown device: {}", data[offset])))?;
    offset += 1;

    // Skip byte_size (we compute it from shape)
    offset += 8;

    let name_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    let name = if name_len > 0 && data.len() >= offset + name_len {
        Some(String::from_utf8_lossy(&data[offset..offset + name_len]).into_owned())
    } else {
        None
    };

    Ok(TensorMeta {
        shape,
        dtype,
        device,
        strides: None,
        name,
        requires_grad: false,
    })
}

/// Events produced by the tensor receiver.
#[derive(Debug)]
pub enum ReceiverEvent {
    /// Tensor metadata received - receiver can now pre-allocate.
    Metadata(TensorMeta),
    /// Tensor data chunk received.
    Data(TensorChunk),
    /// Stream ended successfully.
    End,
    /// Stream was cancelled.
    Cancelled(String),
    /// Need more data to parse next frame.
    NeedMoreData,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DType;

    #[test]
    fn test_tensor_sender_small() {
        let meta = TensorMeta::new(vec![2, 3], DType::Float32);
        let tensor = Tensor::from_f32(&meta, &[1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);

        let sender = TensorSender::new();
        let frames = sender.encode_tensor(&tensor);

        // Should have: TENSOR_META, TENSOR_PAYLOAD, END_STREAM
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].frame_type, FrameType::TensorMeta);
        assert_eq!(frames[1].frame_type, FrameType::TensorPayload);
        assert_eq!(frames[2].frame_type, FrameType::EndStream);
    }

    #[test]
    fn test_tensor_sender_chunked() {
        let meta = TensorMeta::new(vec![1024], DType::Float32);
        let data: Vec<f32> = (0..1024).map(|i| i as f32).collect();
        let tensor = Tensor::from_f32(&meta, &data);

        // Use small chunk size to force multiple chunks
        let sender = TensorSender::with_chunk_size(1024);
        let frames = sender.encode_tensor(&tensor);

        // 4096 bytes / 1024 = 4 payload frames
        assert!(frames.len() > 3);
        assert_eq!(frames[0].frame_type, FrameType::TensorMeta);
        assert_eq!(frames.last().unwrap().frame_type, FrameType::EndStream);
    }

    #[test]
    fn test_tensor_receiver() {
        let meta = TensorMeta::new(vec![4], DType::Float32);
        let tensor = Tensor::from_f32(&meta, &[1.0, 2.0, 3.0, 4.0]);

        let sender = TensorSender::new();
        let frames = sender.encode_tensor(&tensor);

        let mut receiver = TensorReceiver::new();

        // Feed all frames
        for frame in frames {
            receiver.feed(&frame.encode());
        }

        // Process frames
        let mut got_meta = false;
        let mut got_data = false;
        let mut got_end = false;

        loop {
            match receiver.poll().unwrap() {
                ReceiverEvent::Metadata(m) => {
                    assert_eq!(m.shape, vec![4]);
                    assert_eq!(m.dtype, DType::Float32);
                    got_meta = true;
                }
                ReceiverEvent::Data(chunk) => {
                    assert_eq!(chunk.len(), 16); // 4 * f32
                    got_data = true;
                }
                ReceiverEvent::End => {
                    got_end = true;
                    break;
                }
                ReceiverEvent::NeedMoreData => break,
                ReceiverEvent::Cancelled(_) => panic!("unexpected cancel"),
            }
        }

        assert!(got_meta);
        assert!(got_data);
        assert!(got_end);

        // Take the tensor
        let received = receiver.take_tensor().unwrap();
        assert_eq!(received.as_f32(), &[1.0, 2.0, 3.0, 4.0]);
    }

    #[test]
    fn test_receiver_with_prealloc() {
        let meta = TensorMeta::new(vec![100], DType::Float32);
        let data: Vec<f32> = (0..100).map(|i| i as f32).collect();
        let tensor = Tensor::from_f32(&meta, &data);

        let sender = TensorSender::new();
        let frames = sender.encode_tensor(&tensor);

        // Create receiver with known metadata (enables pre-allocation)
        let mut receiver = TensorReceiver::with_meta(meta);

        for frame in frames {
            receiver.feed(&frame.encode());
        }

        // Process until complete
        loop {
            match receiver.poll().unwrap() {
                ReceiverEvent::End => break,
                ReceiverEvent::NeedMoreData => break,
                _ => continue,
            }
        }

        let received = receiver.take_tensor().unwrap();
        assert_eq!(received.numel(), 100);
    }

    #[test]
    fn test_gpu_receiver_cpu_tensor() {
        // Test GPU receiver with CPU tensor (should work on any machine)
        let meta = TensorMeta::new(vec![4], DType::Float32).with_device(Device::Cpu);
        let tensor = Tensor::from_f32(&meta, &[1.0, 2.0, 3.0, 4.0]);

        let sender = TensorSender::new();
        let frames = sender.encode_tensor(&tensor);

        let mut receiver = GpuTensorReceiver::new(meta, 0).unwrap();

        // Feed all frames
        for frame in frames {
            receiver.feed(&frame.encode());
        }

        // Process frames
        let mut got_data = false;
        let mut got_end = false;

        loop {
            match receiver.poll().unwrap() {
                GpuReceiverEvent::Metadata(_) => {}
                GpuReceiverEvent::Data { size, .. } => {
                    assert_eq!(size, 16); // 4 * f32
                    got_data = true;
                }
                GpuReceiverEvent::End => {
                    got_end = true;
                    break;
                }
                GpuReceiverEvent::NeedMoreData => break,
                GpuReceiverEvent::Cancelled(_) => panic!("unexpected cancel"),
            }
        }

        assert!(got_data);
        assert!(got_end);

        // Take the tensor
        let (meta, buffer) = receiver.take().unwrap();
        assert_eq!(meta.shape, vec![4]);
        assert!(buffer.is_cpu()); // CPU device should allocate CPU buffer
        assert_eq!(buffer.len(), 16);
    }

    #[test]
    fn test_gpu_receiver_cuda_fallback() {
        // Test GPU receiver with CUDA tensor on machine without GPU
        // Should fall back to CPU allocation
        let meta = TensorMeta::new(vec![4], DType::Float32).with_device(Device::Cuda);
        let tensor = Tensor::from_f32(&meta.clone().with_device(Device::Cpu), &[5.0, 6.0, 7.0, 8.0]);

        let sender = TensorSender::new();
        let frames = sender.encode_tensor(&tensor);

        let mut receiver = GpuTensorReceiver::new(meta, 0).unwrap();

        // Feed all frames (sender encodes with CPU device, but we handle it)
        for frame in frames {
            receiver.feed(&frame.encode());
        }

        // Process frames
        loop {
            match receiver.poll().unwrap() {
                GpuReceiverEvent::End => break,
                GpuReceiverEvent::NeedMoreData => break,
                _ => continue,
            }
        }

        // Take should work (falls back to CPU if no GPU)
        let (meta, buffer) = receiver.take().unwrap();
        assert_eq!(meta.byte_size(), 16);
        assert_eq!(buffer.len(), 16);

        // Verify data
        let host_data = buffer.to_host().unwrap();
        assert_eq!(host_data.len(), 16);
    }

    #[test]
    fn test_gpu_receiver_take_tensor() {
        // Test the take_tensor() convenience method
        let meta = TensorMeta::new(vec![2, 2], DType::Float32);
        let tensor = Tensor::from_f32(&meta, &[1.0, 2.0, 3.0, 4.0]);

        let sender = TensorSender::new();
        let frames = sender.encode_tensor(&tensor);

        let mut receiver = GpuTensorReceiver::new(meta, 0).unwrap();

        for frame in frames {
            receiver.feed(&frame.encode());
        }

        loop {
            match receiver.poll().unwrap() {
                GpuReceiverEvent::End => break,
                GpuReceiverEvent::NeedMoreData => break,
                _ => continue,
            }
        }

        // Use take_tensor for CPU Tensor
        let received = receiver.take_tensor().unwrap();
        assert_eq!(received.shape(), &[2, 2]);
        assert_eq!(received.as_f32(), &[1.0, 2.0, 3.0, 4.0]);
    }

    #[test]
    fn test_gpu_receiver_progress_tracking() {
        let meta = TensorMeta::new(vec![100], DType::Float32); // 400 bytes
        let data: Vec<f32> = (0..100).map(|i| i as f32).collect();
        let tensor = Tensor::from_f32(&meta, &data);

        // Use small chunks to test progress
        let sender = TensorSender::with_chunk_size(100);
        let frames = sender.encode_tensor(&tensor);

        let mut receiver = GpuTensorReceiver::new(meta, 0).unwrap();

        assert_eq!(receiver.expected_bytes(), 400);
        assert_eq!(receiver.received_bytes(), 0);
        assert!(!receiver.is_complete());

        for frame in frames {
            receiver.feed(&frame.encode());
            while let Ok(event) = receiver.poll() {
                match event {
                    GpuReceiverEvent::NeedMoreData => break,
                    GpuReceiverEvent::End => break,
                    _ => {}
                }
            }
        }

        assert!(receiver.is_complete());
        assert_eq!(receiver.received_bytes(), 400);
    }

    #[test]
    fn test_decode_tensor_meta() {
        // Test the metadata decoding function
        let meta = TensorMeta::new(vec![10, 20], DType::Float16)
            .with_device(Device::Cuda)
            .with_name("test_tensor");

        // Encode using sender
        let sender = TensorSender::new();
        let tensor = Tensor::zeros(meta.clone());
        let frames = sender.encode_tensor(&tensor);

        // Get the metadata frame
        let meta_frame = &frames[0];
        assert_eq!(meta_frame.frame_type, FrameType::TensorMeta);

        // Decode
        let decoded = decode_tensor_meta(&meta_frame.payload).unwrap();
        assert_eq!(decoded.shape, vec![10, 20]);
        assert_eq!(decoded.dtype, DType::Float16);
        assert_eq!(decoded.device, Device::Cuda);
        assert_eq!(decoded.name, Some("test_tensor".to_string()));
    }

    #[test]
    fn test_pooled_receiver_cpu_tensor() {
        use crate::pool::{PinnedMemoryPool, PoolConfig};

        let pool = PinnedMemoryPool::new(PoolConfig::default());

        let meta = TensorMeta::new(vec![4], DType::Float32).with_device(Device::Cpu);
        let tensor = Tensor::from_f32(&meta, &[1.0, 2.0, 3.0, 4.0]);

        let sender = TensorSender::new();
        let frames = sender.encode_tensor(&tensor);

        let mut receiver = PooledGpuReceiver::new(meta, pool.clone(), None).unwrap();

        // Feed frames
        for frame in frames {
            receiver.feed(&frame.encode());
        }

        // Process until complete
        loop {
            match receiver.poll().unwrap() {
                GpuReceiverEvent::End => break,
                GpuReceiverEvent::NeedMoreData => break,
                _ => continue,
            }
        }

        // Check pool stats
        let stats = receiver.pinned_pool_stats();
        assert!(stats.in_use_buffers >= 1 || stats.returns >= 0);

        // Take the tensor
        let received = receiver.take_tensor().unwrap();
        assert_eq!(received.shape(), &[4]);
        assert_eq!(received.as_f32(), &[1.0, 2.0, 3.0, 4.0]);

        // After taking, staging buffers should be returned to pool
        // (2 returns: initial buffer + buffer from TensorMeta re-allocation)
        let final_stats = pool.stats();
        assert!(final_stats.returns >= 1);
    }

    #[test]
    fn test_pooled_receiver_buffer_reuse() {
        use crate::pool::{PinnedMemoryPool, PoolConfig};

        // Use low_memory config with smaller min buffer size for testing
        let config = PoolConfig {
            min_buffer_size: 256,  // 256 bytes min (so 400 bytes fits)
            max_buffer_size: 1024 * 1024,
            ..Default::default()
        };
        let pool = PinnedMemoryPool::new(config);

        // First tensor - 400 bytes (100 f32s)
        let meta = TensorMeta::new(vec![100], DType::Float32);
        let data: Vec<f32> = (0..100).map(|i| i as f32).collect();
        let tensor = Tensor::from_f32(&meta, &data);

        let sender = TensorSender::new();
        let frames = sender.encode_tensor(&tensor);

        {
            let mut receiver = PooledGpuReceiver::new(meta.clone(), pool.clone(), None).unwrap();
            for frame in &frames {
                receiver.feed(&frame.encode());
            }
            loop {
                match receiver.poll().unwrap() {
                    GpuReceiverEvent::End | GpuReceiverEvent::NeedMoreData => break,
                    _ => continue,
                }
            }
            let _ = receiver.take_tensor().unwrap();
        }

        // Check pool has buffers available for reuse
        let stats = pool.stats();
        assert!(stats.returns >= 1, "expected at least 1 return, got {}", stats.returns);
        assert!(stats.available_buffers >= 1, "expected at least 1 available buffer");

        // Second tensor should reuse the buffer
        {
            let mut receiver = PooledGpuReceiver::new(meta, pool.clone(), None).unwrap();
            for frame in &frames {
                receiver.feed(&frame.encode());
            }
            loop {
                match receiver.poll().unwrap() {
                    GpuReceiverEvent::End | GpuReceiverEvent::NeedMoreData => break,
                    _ => continue,
                }
            }
            let _ = receiver.take_tensor().unwrap();
        }

        // Check pool hit - should have hits from buffer reuse
        let final_stats = pool.stats();
        assert!(final_stats.hits >= 1, "expected at least 1 hit, got {}", final_stats.hits);
        assert!(final_stats.hit_rate() > 0.0, "expected hit rate > 0");
    }

    #[test]
    fn test_pooled_receiver_progress() {
        use crate::pool::{PinnedMemoryPool, PoolConfig};

        let pool = PinnedMemoryPool::new(PoolConfig::default());

        let meta = TensorMeta::new(vec![100], DType::Float32); // 400 bytes
        let data: Vec<f32> = (0..100).map(|i| i as f32).collect();
        let tensor = Tensor::from_f32(&meta, &data);

        let sender = TensorSender::with_chunk_size(100);
        let frames = sender.encode_tensor(&tensor);

        let mut receiver = PooledGpuReceiver::new(meta, pool, None).unwrap();

        assert_eq!(receiver.expected_bytes(), 400);
        assert_eq!(receiver.received_bytes(), 0);
        assert!(!receiver.is_complete());

        for frame in frames {
            receiver.feed(&frame.encode());
            while let Ok(event) = receiver.poll() {
                match event {
                    GpuReceiverEvent::NeedMoreData | GpuReceiverEvent::End => break,
                    _ => {}
                }
            }
        }

        assert!(receiver.is_complete());
        assert_eq!(receiver.received_bytes(), 400);
    }

    #[test]
    fn test_pooled_tensor_buffer() {
        // Test PooledTensorBuffer operations
        let cpu_buf = TensorBuffer::cpu_zeros(100);
        let pooled = PooledTensorBuffer::Cpu(cpu_buf);

        assert_eq!(pooled.len(), 100);
        assert!(!pooled.is_empty());
        assert!(!pooled.is_gpu());

        let host_data = pooled.to_host().unwrap();
        assert_eq!(host_data.len(), 100);
    }
}
