pub const BLOCK_SIZE256: usize = 32;
pub const NUM_ROUNDS256: usize = 72;
pub const NUM_WORDS256: usize = 4;
pub const TWEAK_SIZE: usize = 16;
pub const C240: u64 = 0x1bd11bdaa9fc1a22;


pub const TWEAK_COUNT: usize = (TWEAK_SIZE / 8) + 1;
pub const ROUND_KEYS_COUNT: usize = (NUM_ROUNDS256 / 4) + 1;


pub const R4: [[i64; 2]; 8] = [
    [14, 16],
    [52, 57],
    [23, 40],
    [5,  37],
    [25, 33],
    [46, 12],
    [58, 22],
    [32, 32],
];

pub const PADDING: usize = 8;