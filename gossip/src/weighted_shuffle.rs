//! The `weighted_shuffle` module provides an iterator over shuffled weights.

use {
    num_traits::CheckedAdd,
    rand::{
        distributions::uniform::{SampleUniform, UniformSampler},
        Rng,
    },
    std::ops::{AddAssign, Sub, SubAssign},
};

// Each internal tree node has FANOUT many child nodes with indices:
//     (index << BIT_SHIFT) + 1 ..= (index << BIT_SHIFT) + FANOUT
// Conversely, for each node, the parent node is obtained by:
//     (index - 1) >> BIT_SHIFT
const BIT_SHIFT: usize = 4;
const FANOUT: usize = 1 << BIT_SHIFT;
const BIT_MASK: usize = FANOUT - 1;

/// Implements an iterator where indices are shuffled according to their
/// weights:
///   - Returned indices are unique in the range [0, weights.len()).
///   - Higher weighted indices tend to appear earlier proportional to their
///     weight.
///   - Zero weighted indices are shuffled and appear only at the end, after
///     non-zero weighted indices.
#[derive(Clone)]
pub struct WeightedShuffle<T> {
    // Underlying array implementing the tree.
    // tree[i][j] is the sum of all weights in the j'th sub-tree of node i.
    tree: Vec<[T; FANOUT - 1]>,
    // Current sum of all weights, excluding already sampled ones.
    weight: T,
    // Indices of zero weighted entries.
    zeros: Vec<usize>,
}

impl<T> WeightedShuffle<T>
where
    T: Copy + Default + PartialOrd + AddAssign + CheckedAdd,
{
    /// If weights are negative or overflow the total sum
    /// they are treated as zero.
    pub fn new(name: &'static str, weights: &[T]) -> Self {
        let zero = <T as Default>::default();
        let mut tree = vec![[zero; FANOUT - 1]; get_tree_size(weights.len())];
        let mut sum = zero;
        let mut zeros = Vec::default();
        let mut num_negative = 0;
        let mut num_overflow = 0;
        for (k, &weight) in weights.iter().enumerate() {
            #[allow(clippy::neg_cmp_op_on_partial_ord)]
            // weight < zero does not work for NaNs.
            if !(weight >= zero) {
                zeros.push(k);
                num_negative += 1;
                continue;
            }
            if weight == zero {
                zeros.push(k);
                continue;
            }
            sum = match sum.checked_add(&weight) {
                Some(val) => val,
                None => {
                    zeros.push(k);
                    num_overflow += 1;
                    continue;
                }
            };
            // Traverse the tree from the leaf node upwards to the root,
            // updating the sub-tree sums along the way.
            let mut index = tree.len() + k; // leaf node
            while index != 0 {
                let offset = index & BIT_MASK;
                index = (index - 1) >> BIT_SHIFT; // parent node
                if offset > 0 {
                    tree[index][offset - 1] += weight;
                }
            }
        }
        if num_negative > 0 {
            datapoint_error!("weighted-shuffle-negative", (name, num_negative, i64));
        }
        if num_overflow > 0 {
            datapoint_error!("weighted-shuffle-overflow", (name, num_overflow, i64));
        }
        Self {
            tree,
            weight: sum,
            zeros,
        }
    }
}

impl<T> WeightedShuffle<T>
where
    T: Copy + Default + PartialOrd + AddAssign + SubAssign + Sub<Output = T>,
{
    // Removes given weight at index k.
    fn remove(&mut self, k: usize, weight: T) {
        debug_assert!(self.weight >= weight);
        self.weight -= weight;
        // Traverse the tree from the leaf node upwards to the root,
        // updating the sub-tree sums along the way.
        let mut index = self.tree.len() + k; // leaf node
        while index != 0 {
            let offset = index & BIT_MASK;
            index = (index - 1) >> BIT_SHIFT; // parent node
            if offset > 0 {
                debug_assert!(self.tree[index][offset - 1] >= weight);
                self.tree[index][offset - 1] -= weight;
            }
        }
    }

    // Returns smallest index such that sum of weights[..=k] > val,
    // along with its respective weight.
    fn search(&self, mut val: T) -> (/*index:*/ usize, /*weight:*/ T) {
        let zero = <T as Default>::default();
        debug_assert!(val >= zero);
        debug_assert!(val < self.weight);
        // Traverse the tree downwards from the root while maintaining the
        // weight of the subtree which contains the target leaf node.
        let mut index = 0; // root
        let mut weight = self.weight;
        'outer: while index < self.tree.len() {
            for (j, &node) in self.tree[index].iter().enumerate() {
                if val < node {
                    // Traverse to the j+1 subtree of self.tree[index].
                    weight = node;
                    index = (index << BIT_SHIFT) + j + 1;
                    continue 'outer;
                } else {
                    debug_assert!(weight >= node);
                    weight -= node;
                    val -= node;
                }
            }
            // Traverse to the right-most subtree of self.tree[index].
            index = (index << BIT_SHIFT) + FANOUT;
        }
        (index - self.tree.len(), weight)
    }

    pub fn remove_index(&mut self, k: usize) {
        // Traverse the tree from the leaf node upwards to the root, while
        // maintaining the sum of weights of subtrees *not* containing the leaf
        // node.
        let mut index = self.tree.len() + k; // leaf node
        let mut weight = <T as Default>::default(); // zero
        while index != 0 {
            let offset = index & BIT_MASK;
            index = (index - 1) >> BIT_SHIFT; // parent node
            if offset > 0 {
                if self.tree[index][offset - 1] != weight {
                    self.remove(k, self.tree[index][offset - 1] - weight);
                } else {
                    self.remove_zero(k);
                }
                return;
            }
            // The leaf node is in the right-most subtree of self.tree[index].
            for &node in &self.tree[index] {
                weight += node;
            }
        }
        // The leaf node is the right-most node of the whole tree.
        if self.weight != weight {
            self.remove(k, self.weight - weight);
        } else {
            self.remove_zero(k);
        }
    }

    fn remove_zero(&mut self, k: usize) {
        if let Some(index) = self.zeros.iter().position(|&ix| ix == k) {
            self.zeros.remove(index);
        }
    }
}

impl<T> WeightedShuffle<T>
where
    T: Copy + Default + PartialOrd + AddAssign + SampleUniform + SubAssign + Sub<Output = T>,
{
    // Equivalent to weighted_shuffle.shuffle(&mut rng).next()
    pub fn first<R: Rng>(&self, rng: &mut R) -> Option<usize> {
        let zero = <T as Default>::default();
        if self.weight > zero {
            let sample = <T as SampleUniform>::Sampler::sample_single(zero, self.weight, rng);
            let (index, _weight) = WeightedShuffle::search(self, sample);
            return Some(index);
        }
        if self.zeros.is_empty() {
            return None;
        }
        let index = <usize as SampleUniform>::Sampler::sample_single(0usize, self.zeros.len(), rng);
        self.zeros.get(index).copied()
    }
}

impl<'a, T: 'a> WeightedShuffle<T>
where
    T: Copy + Default + PartialOrd + AddAssign + SampleUniform + SubAssign + Sub<Output = T>,
{
    pub fn shuffle<R: Rng>(mut self, rng: &'a mut R) -> impl Iterator<Item = usize> + 'a {
        std::iter::from_fn(move || {
            let zero = <T as Default>::default();
            if self.weight > zero {
                let sample = <T as SampleUniform>::Sampler::sample_single(zero, self.weight, rng);
                let (index, weight) = WeightedShuffle::search(&self, sample);
                self.remove(index, weight);
                return Some(index);
            }
            if self.zeros.is_empty() {
                return None;
            }
            let index =
                <usize as SampleUniform>::Sampler::sample_single(0usize, self.zeros.len(), rng);
            Some(self.zeros.swap_remove(index))
        })
    }
}

// Maps number of items to the "internal" size of the tree
// which "implicitly" holds those items on the leaves.
fn get_tree_size(count: usize) -> usize {
    let mut size = if count == 1 { 1 } else { 0 };
    let mut nodes = 1;
    while nodes < count {
        size += nodes;
        nodes *= FANOUT;
    }
    size
}

