//! Cached data for hashing accounts
use {
    crate::{accounts_hash::CalculateHashIntermediate, cache_hash_data_stats::CacheHashDataStats},
    memmap2::MmapMut,
    solana_measure::measure::Measure,
    std::{
        collections::HashSet,
        fs::{self, remove_file, OpenOptions},
        io::{Seek, SeekFrom, Write},
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
    },
};

pub type EntryType = CalculateHashIntermediate;
pub type SavedType = Vec<Vec<EntryType>>;
pub type SavedTypeSlice = [Vec<EntryType>];

#[repr(C)]
pub struct Header {
    count: usize,
}

pub(crate) struct CacheHashDataFile {
    cell_size: u64,
    mmap: MmapMut,
    capacity: u64,
}

impl CacheHashDataFile {
    /// return a slice of a reference to all the cache hash data from the mmapped file
    pub(crate) fn get_cache_hash_data(&self) -> &[EntryType] {
        self.get_slice(0)
    }

    /// Populate 'accumulator' from entire contents of the cache file.

    /// get '&mut EntryType' from cache file [ix]
    fn get_mut(&mut self, ix: u64) -> &mut EntryType {
        let item_slice = self.get_slice_internal(ix);
        unsafe {
            let item = item_slice.as_ptr() as *mut EntryType;
            &mut *item
        }
    }

    /// get '&[EntryType]' from cache file [ix..]
    fn get_slice(&self, ix: u64) -> &[EntryType] {
        let start = self.get_element_offset_byte(ix);
        let item_slice: &[u8] = &self.mmap[start..];
        let remaining_elements = item_slice.len() / std::mem::size_of::<EntryType>();
        unsafe {
            let item = item_slice.as_ptr() as *const EntryType;
            std::slice::from_raw_parts(item, remaining_elements)
        }
    }

    /// return byte offset of entry 'ix' into a slice which contains a header and at least ix elements
    fn get_element_offset_byte(&self, ix: u64) -> usize {
        let start = (ix * self.cell_size) as usize + std::mem::size_of::<Header>();
        debug_assert_eq!(start % std::mem::align_of::<EntryType>(), 0);
        start
    }

    /// get the bytes representing cache file [ix]
    fn get_slice_internal(&self, ix: u64) -> &[u8] {
        let start = self.get_element_offset_byte(ix);
        let end = start + std::mem::size_of::<EntryType>();
        assert!(
            end <= self.capacity as usize,
            "end: {}, capacity: {}, ix: {}, cell size: {}",
            end,
            self.capacity,
            ix,
            self.cell_size
        );
        &self.mmap[start..end]
    }

    fn get_header_mut(&mut self) -> &mut Header {
        let start = 0_usize;
        let end = start + std::mem::size_of::<Header>();
        let item_slice: &[u8] = &self.mmap[start..end];
        unsafe {
            let item = item_slice.as_ptr() as *mut Header;
            &mut *item
        }
    }

    fn new_map(file: impl AsRef<Path>, capacity: u64) -> Result<MmapMut, std::io::Error> {
        let mut data = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(file)?;

        // Theoretical performance optimization: write a zero to the end of
        // the file so that we won't have to resize it later, which may be
        // expensive.
        data.seek(SeekFrom::Start(capacity - 1)).unwrap();
        data.write_all(&[0]).unwrap();
        data.rewind().unwrap();
        data.flush().unwrap();
        Ok(unsafe { MmapMut::map_mut(&data).unwrap() })
    }

    fn load_map(file: impl AsRef<Path>) -> Result<MmapMut, std::io::Error> {
        let data = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open(file)?;

        Ok(unsafe { MmapMut::map_mut(&data).unwrap() })
    }
}

pub type PreExistingCacheFiles = HashSet<PathBuf>;
pub struct CacheHashData {
    cache_dir: PathBuf,
    pre_existing_cache_files: Arc<Mutex<PreExistingCacheFiles>>,
    pub stats: Arc<Mutex<CacheHashDataStats>>,
}

impl Drop for CacheHashData {
    fn drop(&mut self) {
        self.delete_old_cache_files();
        self.stats.lock().unwrap().report();
    }
}

impl CacheHashData {
    pub fn new(cache_dir: PathBuf) -> CacheHashData {
        std::fs::create_dir_all(&cache_dir).unwrap_or_else(|err| {
            panic!("error creating cache dir {}: {err}", cache_dir.display())
        });

        let result = CacheHashData {
            cache_dir,
            pre_existing_cache_files: Arc::new(Mutex::new(PreExistingCacheFiles::default())),
            stats: Arc::new(Mutex::new(CacheHashDataStats::default())),
        };

        result.get_cache_files();
        result
    }
    fn delete_old_cache_files(&self) {
        let pre_existing_cache_files = self.pre_existing_cache_files.lock().unwrap();
        if !pre_existing_cache_files.is_empty() {
            self.stats.lock().unwrap().unused_cache_files += pre_existing_cache_files.len();
            for file_name in pre_existing_cache_files.iter() {
                let result = self.cache_dir.join(file_name);
                let _ = fs::remove_file(result);
            }
        }
    }
    fn get_cache_files(&self) {
        if self.cache_dir.is_dir() {
            let dir = fs::read_dir(&self.cache_dir);
            if let Ok(dir) = dir {
                let mut pre_existing = self.pre_existing_cache_files.lock().unwrap();
                for entry in dir.flatten() {
                    if let Some(name) = entry.path().file_name() {
                        pre_existing.insert(PathBuf::from(name));
                    }
                }
                self.stats.lock().unwrap().cache_file_count += pre_existing.len();
            }
        }
    }

    /// load from 'file_name' into 'accumulator'

    /// map 'file_name' into memory
    pub(crate) fn load_map(
        &self,
        file_name: impl AsRef<Path>,
    ) -> Result<CacheHashDataFile, std::io::Error> {
        let mut stats = CacheHashDataStats::default();
        let result = self.map(file_name, &mut stats);
        self.stats.lock().unwrap().accumulate(&stats);
        result
    }

    /// create and return a MappedCacheFile for a cache file path
    fn map(
        &self,
        file_name: impl AsRef<Path>,
        stats: &mut CacheHashDataStats,
    ) -> Result<CacheHashDataFile, std::io::Error> {
        let path = self.cache_dir.join(&file_name);
        let file_len = std::fs::metadata(&path)?.len();
        let mut m1 = Measure::start("read_file");
        let mmap = CacheHashDataFile::load_map(&path)?;
        m1.stop();
        stats.read_us = m1.as_us();
        let header_size = std::mem::size_of::<Header>() as u64;
        if file_len < header_size {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }

        let cell_size = std::mem::size_of::<EntryType>() as u64;
        unsafe {
            assert_eq!(
                mmap.align_to::<EntryType>().0.len(),
                0,
                "mmap is not aligned"
            );
        }
        assert_eq!((cell_size as usize) % std::mem::size_of::<u64>(), 0);
        let mut cache_file = CacheHashDataFile {
            mmap,
            cell_size,
            capacity: 0,
        };
        let header = cache_file.get_header_mut();
        let entries = header.count;

        let capacity = cell_size * (entries as u64) + header_size;
        if file_len < capacity {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        cache_file.capacity = capacity;
        assert_eq!(
            capacity, file_len,
            "expected: {capacity}, len on disk: {file_len} {}, entries: {entries}, cell_size: {cell_size}", path.display(),
        );

        stats.total_entries = entries;
        stats.cache_file_size += capacity as usize;

        self.pre_existing_cache_files
            .lock()
            .unwrap()
            .remove(file_name.as_ref());

        stats.loaded_from_cache += 1;
        stats.entries_loaded_from_cache += entries;

        Ok(cache_file)
    }

    /// save 'data' to 'file_name'
    pub fn save(
        &self,
        file_name: impl AsRef<Path>,
        data: &SavedTypeSlice,
    ) -> Result<(), std::io::Error> {
        let mut stats = CacheHashDataStats::default();
        let result = self.save_internal(file_name, data, &mut stats);
        self.stats.lock().unwrap().accumulate(&stats);
        result
    }

    fn save_internal(
        &self,
        file_name: impl AsRef<Path>,
        data: &SavedTypeSlice,
        stats: &mut CacheHashDataStats,
    ) -> Result<(), std::io::Error> {
        let mut m = Measure::start("save");
        let cache_path = self.cache_dir.join(file_name);
        // overwrite any existing file at this path
        let _ignored = remove_file(&cache_path);
        let cell_size = std::mem::size_of::<EntryType>() as u64;
        let mut m1 = Measure::start("create save");
        let entries = data
            .iter()
            .map(|x: &Vec<EntryType>| x.len())
            .collect::<Vec<_>>();
        let entries = entries.iter().sum::<usize>();
        let capacity = cell_size * (entries as u64) + std::mem::size_of::<Header>() as u64;

        let mmap = CacheHashDataFile::new_map(&cache_path, capacity)?;
        m1.stop();
        stats.create_save_us += m1.as_us();
        let mut cache_file = CacheHashDataFile {
            mmap,
            cell_size,
            capacity,
        };

        let mut header = cache_file.get_header_mut();
        header.count = entries;

        stats.cache_file_size = capacity as usize;
        stats.total_entries = entries;

        let mut m2 = Measure::start("write_to_mmap");
        let mut i = 0;
        data.iter().for_each(|x| {
            x.iter().for_each(|item| {
                let d = cache_file.get_mut(i as u64);
                i += 1;
                *d = item.clone();
            })
        });
        assert_eq!(i, entries);
        m2.stop();
        stats.write_to_mmap_us += m2.as_us();
        m.stop();
        stats.save_us += m.as_us();
        stats.saved_to_cache += 1;
        Ok(())
    }
}
