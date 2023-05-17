//! Aligned memory

use std::{mem, ptr};

/// Scalar types, aka "plain old data"
pub trait Pod {}

impl Pod for bool {}
impl Pod for u8 {}
impl Pod for u16 {}
impl Pod for u32 {}
impl Pod for u64 {}
impl Pod for i8 {}
impl Pod for i16 {}
impl Pod for i32 {}
impl Pod for i64 {}

/// Provides u8 slices at a specified alignment
#[derive(Debug, PartialEq, Eq)]
pub struct AlignedMemory<const ALIGN: usize> {
    max_len: usize,
    align_offset: usize,
    mem: Vec<u8>,
    zero_up_to_max_len: bool,
}

impl<const ALIGN: usize> AlignedMemory<ALIGN> {
    fn get_mem(max_len: usize) -> (Vec<u8>, usize) {
        let mut mem: Vec<u8> = Vec::with_capacity(max_len.saturating_add(ALIGN));
        mem.push(0);
        let align_offset = mem.as_ptr().align_offset(ALIGN);
        mem.resize(align_offset, 0);
        (mem, align_offset)
    }
    fn get_mem_zeroed(max_len: usize) -> (Vec<u8>, usize) {
        // use calloc() to get zeroed memory from the OS instead of using
        // malloc() + memset(), see
        // https://github.com/rust-lang/rust/issues/54628
        let mut mem = vec![0; max_len];
        let align_offset = mem.as_ptr().align_offset(ALIGN);
        mem.resize(max_len.saturating_add(align_offset), 0);
        (mem, align_offset)
    }
    /// Returns a filled AlignedMemory by copying the given slice
    pub fn from_slice(data: &[u8]) -> Self {
        let max_len = data.len();
        let (mut mem, align_offset) = Self::get_mem(max_len);
        mem.extend_from_slice(data);
        Self {
            max_len,
            align_offset,
            mem,
            zero_up_to_max_len: false,
        }
    }
    /// Returns a new empty AlignedMemory with uninitialized preallocated memory
    pub fn with_capacity(max_len: usize) -> Self {
        let (mem, align_offset) = Self::get_mem(max_len);
        Self {
            max_len,
            align_offset,
            mem,
            zero_up_to_max_len: false,
        }
    }
    /// Returns a new empty AlignedMemory with zero initialized preallocated memory
    pub fn with_capacity_zeroed(max_len: usize) -> Self {
        let (mut mem, align_offset) = Self::get_mem_zeroed(max_len);
        mem.truncate(align_offset);
        Self {
            max_len,
            align_offset,
            mem,
            zero_up_to_max_len: true,
        }
    }
    /// Returns a new filled AlignedMemory with zero initialized preallocated memory
    pub fn zero_filled(max_len: usize) -> Self {
        let (mem, align_offset) = Self::get_mem_zeroed(max_len);
        Self {
            max_len,
            align_offset,
            mem,
            zero_up_to_max_len: true,
        }
    }
    /// Calculate memory size
    pub fn mem_size(&self) -> usize {
        self.mem.capacity().saturating_add(mem::size_of::<Self>())
    }
    /// Get the length of the data
    pub fn len(&self) -> usize {
        self.mem.len().saturating_sub(self.align_offset)
    }
    /// Is the memory empty
    pub fn is_empty(&self) -> bool {
        self.mem.len() == self.align_offset
    }
    /// Get the current write index
    pub fn write_index(&self) -> usize {
        self.mem.len()
    }
    /// Get an aligned slice
    pub fn as_slice(&self) -> &[u8] {
        let start = self.align_offset;
        let end = self.mem.len();
        &self.mem[start..end]
    }
    /// Get an aligned mutable slice
    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        let start = self.align_offset;
        let end = self.mem.len();
        &mut self.mem[start..end]
    }
    /// Grows memory with `value` repeated `num` times starting at the `write_index`
    pub fn fill_write(&mut self, num: usize, value: u8) -> std::io::Result<()> {
        let new_len = match (
            self.mem.len().checked_add(num),
            self.align_offset.checked_add(self.max_len),
        ) {
            (Some(new_len), Some(allocation_end)) if new_len <= allocation_end => new_len,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "aligned memory resize failed",
                ))
            }
        };
        if self.zero_up_to_max_len && value == 0 {
            // Safe because everything up to `max_len` is zeroed and no shrinking is allowed
            unsafe {
                self.mem.set_len(new_len);
            }
        } else {
            self.mem.resize(new_len, value);
        }
        Ok(())
    }

    /// Write a generic type T into the memory.
    ///
    /// # Safety
    ///
    /// Unsafe since it assumes that there is enough capacity.
    pub unsafe fn write_unchecked<T: Pod>(&mut self, value: T) {
        let pos = self.mem.len();
        let new_len = pos.saturating_add(mem::size_of::<T>());
        debug_assert!(new_len <= self.align_offset.saturating_add(self.max_len));
        self.mem.set_len(new_len);
        ptr::write_unaligned(
            self.mem.get_unchecked_mut(pos..new_len).as_mut_ptr().cast(),
            value,
        );
    }

    /// Write a slice of bytes into the memory.
    ///
    /// # Safety
    ///
    /// Unsafe since it assumes that there is enough capacity.
    pub unsafe fn write_all_unchecked(&mut self, value: &[u8]) {
        let pos = self.mem.len();
        let new_len = pos.saturating_add(value.len());
        debug_assert!(new_len <= self.align_offset.saturating_add(self.max_len));
        self.mem.set_len(new_len);
        self.mem
            .get_unchecked_mut(pos..new_len)
            .copy_from_slice(value);
    }
}

// Custom Clone impl is needed to ensure alignment. Derived clone would just
// clone self.mem and there would be no guarantee that the clone allocation is
// aligned.
impl<const ALIGN: usize> Clone for AlignedMemory<ALIGN> {
    fn clone(&self) -> Self {
        AlignedMemory::from_slice(self.as_slice())
    }
}

impl<const ALIGN: usize> std::io::Write for AlignedMemory<ALIGN> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match (
            self.mem.len().checked_add(buf.len()),
            self.align_offset.checked_add(self.max_len),
        ) {
            (Some(new_len), Some(allocation_end)) if new_len <= allocation_end => {}
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "aligned memory write failed",
                ))
            }
        }
        self.mem.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<const ALIGN: usize, T: AsRef<[u8]>> From<T> for AlignedMemory<ALIGN> {
    fn from(bytes: T) -> Self {
        AlignedMemory::from_slice(bytes.as_ref())
    }
}
