use {
    super::*,
    crate::declare_syscall,
    solana_rbpf::{error::EbpfError, memory_region::MemoryRegion},
    std::slice,
};

fn mem_op_consume(invoke_context: &mut InvokeContext, n: u64) -> Result<(), Error> {
    let compute_budget = invoke_context.get_compute_budget();
    let cost = compute_budget
        .mem_op_base_cost
        .max(n.saturating_div(compute_budget.cpi_bytes_per_unit));
    consume_compute_meter(invoke_context, cost)
}

declare_syscall!(
    /// memcpy
    SyscallMemcpy,
    fn inner_call(
        invoke_context: &mut InvokeContext,
        dst_addr: u64,
        src_addr: u64,
        n: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        mem_op_consume(invoke_context, n)?;

        if !is_nonoverlapping(src_addr, n, dst_addr, n) {
            return Err(SyscallError::CopyOverlapping.into());
        }

        // host addresses can overlap so we always invoke memmove
        memmove(invoke_context, dst_addr, src_addr, n, memory_mapping)
    }
);

declare_syscall!(
    /// memmove
    SyscallMemmove,
    fn inner_call(
        invoke_context: &mut InvokeContext,
        dst_addr: u64,
        src_addr: u64,
        n: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        mem_op_consume(invoke_context, n)?;

        memmove(invoke_context, dst_addr, src_addr, n, memory_mapping)
    }
);

declare_syscall!(
    /// memcmp
    SyscallMemcmp,
    fn inner_call(
        invoke_context: &mut InvokeContext,
        s1_addr: u64,
        s2_addr: u64,
        n: u64,
        cmp_result_addr: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        mem_op_consume(invoke_context, n)?;

        if invoke_context
            .feature_set
            .is_active(&feature_set::bpf_account_data_direct_mapping::id())
        {
            let cmp_result = translate_type_mut::<i32>(
                memory_mapping,
                cmp_result_addr,
                invoke_context.get_check_aligned(),
            )?;
            *cmp_result = memcmp_non_contiguous(s1_addr, s2_addr, n, memory_mapping)?;
        } else {
            let s1 = translate_slice::<u8>(
                memory_mapping,
                s1_addr,
                n,
                invoke_context.get_check_aligned(),
                invoke_context.get_check_size(),
            )?;
            let s2 = translate_slice::<u8>(
                memory_mapping,
                s2_addr,
                n,
                invoke_context.get_check_aligned(),
                invoke_context.get_check_size(),
            )?;
            let cmp_result = translate_type_mut::<i32>(
                memory_mapping,
                cmp_result_addr,
                invoke_context.get_check_aligned(),
            )?;

            debug_assert_eq!(s1.len(), n as usize);
            debug_assert_eq!(s2.len(), n as usize);
            // Safety:
            // memcmp is marked unsafe since it assumes that the inputs are at least
            // `n` bytes long. `s1` and `s2` are guaranteed to be exactly `n` bytes
            // long because `translate_slice` would have failed otherwise.
            *cmp_result = unsafe { memcmp(s1, s2, n as usize) };
        }

        Ok(0)
    }
);

declare_syscall!(
    /// memset
    SyscallMemset,
    fn inner_call(
        invoke_context: &mut InvokeContext,
        dst_addr: u64,
        c: u64,
        n: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        mem_op_consume(invoke_context, n)?;

        if invoke_context
            .feature_set
            .is_active(&feature_set::bpf_account_data_direct_mapping::id())
        {
            memset_non_contiguous(dst_addr, c as u8, n, memory_mapping)
        } else {
            let s = translate_slice_mut::<u8>(
                memory_mapping,
                dst_addr,
                n,
                invoke_context.get_check_aligned(),
                invoke_context.get_check_size(),
            )?;
            s.fill(c as u8);
            Ok(0)
        }
    }
);

fn memmove(
    invoke_context: &mut InvokeContext,
    dst_addr: u64,
    src_addr: u64,
    n: u64,
    memory_mapping: &MemoryMapping,
) -> Result<u64, Error> {
    if invoke_context
        .feature_set
        .is_active(&feature_set::bpf_account_data_direct_mapping::id())
    {
        memmove_non_contiguous(dst_addr, src_addr, n, memory_mapping)
    } else {
        let dst_ptr = translate_slice_mut::<u8>(
            memory_mapping,
            dst_addr,
            n,
            invoke_context.get_check_aligned(),
            invoke_context.get_check_size(),
        )?
        .as_mut_ptr();
        let src_ptr = translate_slice::<u8>(
            memory_mapping,
            src_addr,
            n,
            invoke_context.get_check_aligned(),
            invoke_context.get_check_size(),
        )?
        .as_ptr();

        unsafe { std::ptr::copy(src_ptr, dst_ptr, n as usize) };
        Ok(0)
    }
}

fn memmove_non_contiguous(
    dst_addr: u64,
    src_addr: u64,
    n: u64,
    memory_mapping: &MemoryMapping,
) -> Result<u64, Error> {
    let reverse = dst_addr.wrapping_sub(src_addr) < n;
    iter_memory_pair_chunks(
        AccessType::Load,
        src_addr,
        AccessType::Store,
        dst_addr,
        n,
        memory_mapping,
        reverse,
        |src_host_addr, dst_host_addr, chunk_len| {
            unsafe {
                std::ptr::copy(
                    src_host_addr as *const u8,
                    dst_host_addr as *mut u8,
                    chunk_len,
                )
            };
            Ok(0)
        },
    )
}

// Marked unsafe since it assumes that the slices are at least `n` bytes long.
unsafe fn memcmp(s1: &[u8], s2: &[u8], n: usize) -> i32 {
    for i in 0..n {
        let a = *s1.get_unchecked(i);
        let b = *s2.get_unchecked(i);
        if a != b {
            return (a as i32).saturating_sub(b as i32);
        };
    }

    0
}

fn memcmp_non_contiguous(
    src_addr: u64,
    dst_addr: u64,
    n: u64,
    memory_mapping: &MemoryMapping,
) -> Result<i32, Error> {
    match iter_memory_pair_chunks(
        AccessType::Load,
        src_addr,
        AccessType::Load,
        dst_addr,
        n,
        memory_mapping,
        false,
        |s1_addr, s2_addr, chunk_len| {
            let res = unsafe {
                let s1 = slice::from_raw_parts(s1_addr as *const u8, chunk_len);
                let s2 = slice::from_raw_parts(s2_addr as *const u8, chunk_len);
                // Safety:
                // memcmp is marked unsafe since it assumes that s1 and s2 are exactly chunk_len
                // long. The whole point of iter_memory_pair_chunks is to find same length chunks
                // across two memory regions.
                memcmp(s1, s2, chunk_len)
            };
            if res != 0 {
                return Err(MemcmpError::Diff(res).into());
            }
            Ok(0)
        },
    ) {
        Ok(res) => Ok(res),
        Err(error) => match error.downcast_ref() {
            Some(MemcmpError::Diff(diff)) => Ok(*diff),
            _ => Err(error),
        },
    }
}

#[derive(Debug)]
enum MemcmpError {
    Diff(i32),
}

impl std::fmt::Display for MemcmpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemcmpError::Diff(diff) => write!(f, "memcmp diff: {diff}"),
        }
    }
}

impl std::error::Error for MemcmpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MemcmpError::Diff(_) => None,
        }
    }
}

fn memset_non_contiguous(
    dst_addr: u64,
    c: u8,
    n: u64,
    memory_mapping: &MemoryMapping,
) -> Result<u64, Error> {
    let dst_chunk_iter = MemoryChunkIterator::new(memory_mapping, AccessType::Store, dst_addr, n)?;
    for item in dst_chunk_iter {
        let (dst_region, dst_vm_addr, dst_len) = item?;
        let dst_host_addr = Result::from(dst_region.vm_to_host(dst_vm_addr, dst_len as u64))?;
        unsafe { slice::from_raw_parts_mut(dst_host_addr as *mut u8, dst_len).fill(c) }
    }

    Ok(0)
}

fn iter_memory_pair_chunks<T, F>(
    src_access: AccessType,
    src_addr: u64,
    dst_access: AccessType,
    mut dst_addr: u64,
    n: u64,
    memory_mapping: &MemoryMapping,
    reverse: bool,
    mut fun: F,
) -> Result<T, Error>
where
    T: Default,
    F: FnMut(*const u8, *const u8, usize) -> Result<T, Error>,
{
    let mut src_chunk_iter = MemoryChunkIterator::new(memory_mapping, src_access, src_addr, n)
        .map_err(EbpfError::from)?;
    loop {
        // iterate source chunks
        let (src_region, src_vm_addr, mut src_len) = match if reverse {
            src_chunk_iter.next_back()
        } else {
            src_chunk_iter.next()
        } {
            Some(item) => item?,
            None => break,
        };

        let mut src_host_addr = Result::from(src_region.vm_to_host(src_vm_addr, src_len as u64))?;
        let mut dst_chunk_iter = MemoryChunkIterator::new(memory_mapping, dst_access, dst_addr, n)
            .map_err(EbpfError::from)?;
        // iterate over destination chunks until this source chunk has been completely copied
        while src_len > 0 {
            loop {
                let (dst_region, dst_vm_addr, dst_len) = match if reverse {
                    dst_chunk_iter.next_back()
                } else {
                    dst_chunk_iter.next()
                } {
                    Some(item) => item?,
                    None => break,
                };
                let dst_host_addr =
                    Result::from(dst_region.vm_to_host(dst_vm_addr, dst_len as u64))?;
                let chunk_len = src_len.min(dst_len);
                fun(
                    src_host_addr as *const u8,
                    dst_host_addr as *const u8,
                    chunk_len,
                )?;
                src_len = src_len.saturating_sub(chunk_len);
                if reverse {
                    dst_addr = dst_addr.saturating_sub(chunk_len as u64);
                } else {
                    dst_addr = dst_addr.saturating_add(chunk_len as u64);
                }
                if src_len == 0 {
                    break;
                }
                src_host_addr = src_host_addr.saturating_add(chunk_len as u64);
            }
        }
    }

    Ok(T::default())
}

struct MemoryChunkIterator<'a> {
    memory_mapping: &'a MemoryMapping<'a>,
    access_type: AccessType,
    initial_vm_addr: u64,
    vm_addr_start: u64,
    // exclusive end index (start + len, so one past the last valid address)
    vm_addr_end: u64,
    len: u64,
}

impl<'a> MemoryChunkIterator<'a> {
    fn new(
        memory_mapping: &'a MemoryMapping,
        access_type: AccessType,
        vm_addr: u64,
        len: u64,
    ) -> Result<MemoryChunkIterator<'a>, EbpfError> {
        let vm_addr_end = vm_addr.checked_add(len).ok_or(EbpfError::AccessViolation(
            0,
            access_type,
            vm_addr,
            len,
            "unknown",
        ))?;
        Ok(MemoryChunkIterator {
            memory_mapping,
            access_type,
            initial_vm_addr: vm_addr,
            len,
            vm_addr_start: vm_addr,
            vm_addr_end,
        })
    }

    fn region(&mut self, vm_addr: u64) -> Result<&'a MemoryRegion, Error> {
        match self.memory_mapping.region(self.access_type, vm_addr) {
            Ok(region) => Ok(region),
            Err(error) => match error.downcast_ref() {
                Some(EbpfError::AccessViolation(pc, access_type, _vm_addr, _len, name)) => {
                    Err(Box::new(EbpfError::AccessViolation(
                        *pc,
                        *access_type,
                        self.initial_vm_addr,
                        self.len,
                        name,
                    )))
                }
                Some(EbpfError::StackAccessViolation(pc, access_type, _vm_addr, _len, frame)) => {
                    Err(Box::new(EbpfError::StackAccessViolation(
                        *pc,
                        *access_type,
                        self.initial_vm_addr,
                        self.len,
                        *frame,
                    )))
                }
                _ => Err(error),
            },
        }
    }
}

impl<'a> Iterator for MemoryChunkIterator<'a> {
    type Item = Result<(&'a MemoryRegion, u64, usize), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.vm_addr_start == self.vm_addr_end {
            return None;
        }

        let region = match self.region(self.vm_addr_start) {
            Ok(region) => region,
            Err(e) => {
                self.vm_addr_start = self.vm_addr_end;
                return Some(Err(e));
            }
        };

        let vm_addr = self.vm_addr_start;

        let chunk_len = if region.vm_addr_end <= self.vm_addr_end {
            // consume the whole region
            let len = region.vm_addr_end.saturating_sub(self.vm_addr_start);
            self.vm_addr_start = region.vm_addr_end;
            len
        } else {
            // consume part of the region
            let len = self.vm_addr_end.saturating_sub(self.vm_addr_start);
            self.vm_addr_start = self.vm_addr_end;
            len
        };

        Some(Ok((region, vm_addr, chunk_len as usize)))
    }
}

impl<'a> DoubleEndedIterator for MemoryChunkIterator<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.vm_addr_start == self.vm_addr_end {
            return None;
        }

        let region = match self.region(self.vm_addr_end.saturating_sub(1)) {
            Ok(region) => region,
            Err(e) => {
                self.vm_addr_start = self.vm_addr_end;
                return Some(Err(e));
            }
        };

        let chunk_len = if region.vm_addr >= self.vm_addr_start {
            // consume the whole region
            let len = self.vm_addr_end.saturating_sub(region.vm_addr);
            self.vm_addr_end = region.vm_addr;
            len
        } else {
            // consume part of the region
            let len = self.vm_addr_end.saturating_sub(self.vm_addr_start);
            self.vm_addr_end = self.vm_addr_start;
            len
        };

        Some(Ok((region, self.vm_addr_end, chunk_len as usize)))
    }
}
