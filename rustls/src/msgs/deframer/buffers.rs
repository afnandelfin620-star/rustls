use alloc::vec::Vec;
use core::mem;
use core::ops::Range;
#[cfg(feature = "std")]
use std::io;

#[cfg(feature = "std")]
use crate::msgs::message::MAX_WIRE_SIZE;

/// l5droid patch: maximum bytes requested per socket read (upstream: 4 KiB).
#[cfg(feature = "std")]
const L5_READ_LIMIT: usize = 16 * 1024;

/// Conversion from a slice within a larger buffer into
/// a `Range` offset within.
#[derive(Debug)]
pub(crate) struct Locator {
    bounds: Range<*const u8>,
}

impl Locator {
    #[inline]
    pub(crate) fn new(slice: &[u8]) -> Self {
        Self {
            bounds: slice.as_ptr_range(),
        }
    }

    #[inline]
    pub(crate) fn locate(&self, slice: &[u8]) -> Range<usize> {
        let bounds = slice.as_ptr_range();
        debug_assert!(self.fully_contains(slice));
        let start = bounds.start as usize - self.bounds.start as usize;
        let len = bounds.end as usize - bounds.start as usize;
        Range {
            start,
            end: start + len,
        }
    }

    #[inline]
    pub(crate) fn fully_contains(&self, slice: &[u8]) -> bool {
        let bounds = slice.as_ptr_range();
        bounds.start >= self.bounds.start && bounds.end <= self.bounds.end
    }
}

/// Conversion from a `Range` offset to the original slice.
pub(crate) struct Delocator<'b> {
    slice: &'b [u8],
}

impl<'b> Delocator<'b> {
    #[inline]
    pub(crate) fn new(slice: &'b [u8]) -> Self {
        Self { slice }
    }

    #[inline]
    pub(crate) fn slice_from_range(&'_ self, range: &Range<usize>) -> &'b [u8] {
        // safety: this unwrap is safe so long as `range` came from `locate()`
        // for the same buffer
        self.slice.get(range.clone()).unwrap()
    }

    #[inline]
    pub(crate) fn locator(self) -> Locator {
        Locator::new(self.slice)
    }
}

/// Reordering the underlying buffer based on ranges.
pub(crate) struct Coalescer<'b> {
    slice: &'b mut [u8],
}

impl<'b> Coalescer<'b> {
    #[inline]
    pub(crate) fn new(slice: &'b mut [u8]) -> Self {
        Self { slice }
    }

    #[inline]
    pub(crate) fn copy_within(&mut self, from: Range<usize>, to: Range<usize>) {
        debug_assert!(from.len() == to.len());
        debug_assert!(self.slice.get(from.clone()).is_some());
        debug_assert!(self.slice.get(to.clone()).is_some());
        self.slice.copy_within(from, to.start);
    }

    #[inline]
    pub(crate) fn delocator(self) -> Delocator<'b> {
        Delocator::new(self.slice)
    }
}

/// Accounting structure tracking progress in parsing a single buffer.
#[derive(Clone, Debug)]
pub(crate) struct BufferProgress {
    /// Prefix of the buffer that has been processed so far.
    ///
    /// `processed` may exceed `discard`, that means we have parsed
    /// some buffer, but are still using it.  This happens due to
    /// in-place decryption of incoming records, and in-place
    /// reassembly of handshake messages.
    ///
    /// 0 <= processed <= len
    processed: usize,

    /// Prefix of the buffer that can be removed.
    ///
    /// If `discard` exceeds `processed`, that means we are ignoring
    /// data without processing it.
    ///
    /// 0 <= discard <= len
    discard: usize,
}

impl BufferProgress {
    pub(super) fn new(processed: usize) -> Self {
        Self {
            processed,
            discard: 0,
        }
    }

    #[inline]
    pub(crate) fn add_discard(&mut self, discard: usize) {
        self.discard += discard;
    }

    #[inline]
    pub(crate) fn add_processed(&mut self, processed: usize) {
        self.processed += processed;
    }

    #[inline]
    pub(crate) fn take_discard(&mut self) -> usize {
        // the caller is about to discard `discard` bytes
        // from the front of the buffer.  adjust `processed`
        // down by the same amount.
        self.processed = self
            .processed
            .saturating_sub(self.discard);
        mem::take(&mut self.discard)
    }

    #[inline]
    pub(crate) fn processed(&self) -> usize {
        self.processed
    }
}

#[derive(Default, Debug)]
pub(crate) struct DeframerVecBuffer {
    /// Buffer of data read from the socket, in the process of being parsed into messages.
    ///
    /// For buffer size management, checkout out the [`DeframerVecBuffer::prepare_read()`] method.
    buf: Vec<u8>,
    #[cfg(feature = "l5-experimental")]
    pool: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,

    /// l5droid patch: start of the not-yet-discarded data. `discard()` only
    /// advances this offset; the pending bytes are moved to the front once per
    /// read (in `compact()`), instead of once per processed record.
    start: usize,

    /// What size prefix of `buf` is used.
    used: usize,
    #[cfg(feature = "l5-experimental")]
    pub(crate) l5_capacity: usize,
}

impl DeframerVecBuffer {
    /// Transfer a whole receive allocation, keeping only an incomplete trailing
    /// record in the next slab. No application payload is copied or compacted.
    #[cfg(feature = "l5-experimental")]
    pub(crate) fn detach_prefix(&mut self, taken: usize) -> bytes::Bytes {
        assert!(taken <= self.used - self.start);
        let end = self.start + taken;
        let remaining = self.used - end;
        let size = self.buf.len();
        let mut next = self.pool.lock().unwrap().pop().unwrap_or_default();
        next.resize(size, 0); // Recycled slabs already have this size: no memset.
        next[..remaining].copy_from_slice(&self.buf[end..self.used]);
        let old = mem::replace(&mut self.buf, next);
        let start = mem::take(&mut self.start);
        self.used = remaining;
        bytes::Bytes::from_owner(ReceiveSlab { buf: old, pool: self.pool.clone() }).slice(start..end)
    }

    /// Discard `taken` bytes from the start of our buffer.
    ///
    /// Observable behaviour is unchanged from upstream: `filled()` afterwards
    /// starts `taken` bytes later. Only the data movement is deferred.
    pub(crate) fn discard(&mut self, taken: usize) {
        if taken < self.used - self.start {
            self.start += taken;
        } else {
            self.start = 0;
            self.used = 0;
        }
    }

    pub(crate) fn filled_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.start..self.used]
    }

    pub(crate) fn filled(&self) -> &[u8] {
        &self.buf[self.start..self.used]
    }

    /// Move pending bytes to the front of `buf`.
    #[cfg(feature = "std")]
    fn compact(&mut self) {
        if self.start > 0 {
            self.buf
                .copy_within(self.start..self.used, 0);
            self.used -= self.start;
            self.start = 0;
        }
    }
}

#[cfg(feature = "std")]
impl DeframerVecBuffer {
    /// Read some bytes from `rd`, and add them to the buffer.
    pub(crate) fn read(&mut self, rd: &mut dyn io::Read, in_handshake: bool) -> io::Result<usize> {
        if let Err(err) = self.prepare_read(in_handshake) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, err));
        }

        // Try to do the largest reads possible. Note that if
        // we get a message with a length field out of range here,
        // we do a zero length read.  That looks like an EOF to
        // the next layer up, which is fine.
        //
        // l5droid patch: each read is capped at `L5_READ_LIMIT` (tunable; on-device
        // CPU-time measurements of 4 KiB vs 64 KiB were dominated by noise in
        // kernel-time attribution, so the value is being evaluated empirically).
        let mut read_limit = L5_READ_LIMIT;
        #[cfg(feature = "l5-experimental")]
        if self.l5_capacity > 0 { read_limit = self.l5_capacity; }
        let end = Ord::min(self.buf.len(), self.used + read_limit);
        let new_bytes = rd.read(&mut self.buf[self.used..end])?;
        self.used += new_bytes;
        Ok(new_bytes)
    }

    /// Resize the internal `buf` if necessary for reading more bytes.
    fn prepare_read(&mut self, is_joining_hs: bool) -> Result<(), &'static str> {
        /// TLS allows for handshake messages of up to 16MB.  We
        /// restrict that to 64KB to limit potential for denial-of-
        /// service.
        const MAX_HANDSHAKE_SIZE: u32 = 0xffff;

        const READ_SIZE: usize = 4096;

        // l5droid patch: outside handshake joining, keep one fixed buffer (no
        // shrink to 4 KiB whenever it drains followed by realloc + zero-fill on
        // the next record) and only move pending bytes to the front when the
        // tail has no room for a full read, instead of once per record.
        let mut data_buffer_size: usize = 64 * 1024 + MAX_WIRE_SIZE;
        let mut read_limit = L5_READ_LIMIT;
        #[cfg(feature = "l5-experimental")]
        if self.l5_capacity > 0 { data_buffer_size = self.l5_capacity + MAX_WIRE_SIZE; read_limit = self.l5_capacity; }

        // Handshake joining keeps upstream's exact logic on a compacted buffer.
        if is_joining_hs || self.buf.len() > data_buffer_size {
            self.compact();
        }

        // We allow a maximum of 64k of buffered data for handshake messages only. Enforce this
        // by varying the maximum allowed buffer size here based on whether a prefix of a
        // handshake payload is currently being buffered. Given that the first read of such a
        // payload will only ever be 4k bytes, the next time we come around here we allow a
        // larger buffer size. Once the large message and any following handshake messages in
        // the same flight have been consumed, `pop()` will call `discard()` to reset `used`.
        // At this point, the buffer resizing logic below should reduce the buffer size.
        let allow_max = match is_joining_hs {
            true => MAX_HANDSHAKE_SIZE as usize,
            false => data_buffer_size,
        };

        if self.used - self.start >= allow_max {
            return Err("message buffer full");
        }

        // Handshake joining keeps upstream's incremental 4k growth. Otherwise the
        // buffer is sized to `DATA_BUFFER_SIZE` once and kept. If a large handshake
        // message left it bigger than `allow_max`, reduce it again (large messages
        // should be rare); the buffer was compacted above and `used < allow_max`,
        // so no buffered bytes are lost.
        let need_capacity = match is_joining_hs {
            true => Ord::min(allow_max, self.used + READ_SIZE),
            false => allow_max,
        };
        if need_capacity > self.buf.len() {
            self.buf.resize(need_capacity, 0);
        } else if self.buf.len() > allow_max {
            self.buf.resize(need_capacity, 0);
            self.buf.shrink_to(need_capacity);
        }

        // Pending data is < one record, so after compaction there is always room.
        if self.buf.len() - self.used < read_limit {
            self.compact();
        }

        Ok(())
    }

    /// Append `bytes` to the end of this buffer.
    ///
    /// Return a `Range` saying where it went.
    pub(crate) fn extend(&mut self, bytes: &[u8]) -> Range<usize> {
        self.compact();
        let len = bytes.len();
        let start = self.used;
        let end = start + len;
        if self.buf.len() < end {
            self.buf.resize(end, 0);
        }
        self.buf[start..end].copy_from_slice(bytes);
        self.used += len;
        Range { start, end }
    }
}

#[cfg(feature = "l5-experimental")]
struct ReceiveSlab {
    buf: Vec<u8>,
    pool: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
}
#[cfg(feature = "l5-experimental")]
impl AsRef<[u8]> for ReceiveSlab { fn as_ref(&self) -> &[u8] { &self.buf } }
#[cfg(feature = "l5-experimental")]
impl Drop for ReceiveSlab {
    fn drop(&mut self) {
        let mut pool = self.pool.lock().unwrap();
        // A reuse cache, not a traffic/queue budget. Live slabs remain owned by Bytes.
        if pool.len() < 4 { pool.push(mem::take(&mut self.buf)); }
    }
}

/// A borrowed version of [`DeframerVecBuffer`] that tracks discard operations
#[derive(Debug)]
pub(crate) struct DeframerSliceBuffer<'a> {
    // a fully initialized buffer that will be deframed
    buf: &'a mut [u8],
    // number of bytes to discard from the front of `buf` at a later time
    discard: usize,
}

impl<'a> DeframerSliceBuffer<'a> {
    pub(crate) fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, discard: 0 }
    }

    /// Tracks a pending discard operation of `num_bytes`
    pub(crate) fn queue_discard(&mut self, num_bytes: usize) {
        self.discard += num_bytes;
    }

    pub(crate) fn pending_discard(&self) -> usize {
        self.discard
    }

    pub(crate) fn filled_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.discard..]
    }
}
