use crate::constants;

pub struct Mix{
    d: usize,
    j: usize
}

impl Mix {
    pub fn new(d: usize, j: usize) -> Mix {
        Mix {d,j}
    }

    fn shift(&self) -> i64 {
        constants::R4[self.d % 8][self.j]
    }

    pub fn mix(&self, x0: u64, x1: u64) -> (u64, u64) {
        let s = self.shift();

        let y0 = x0.wrapping_add(x1);
        let y1 = ((x1 << s) | (x1 >> (64 - s))) ^ y0;
        (y0, y1)
    }

    pub fn demix(&self, y0: u64, y1: u64) -> (u64, u64) {
        let s = self.shift();
        let x1 = ((y1 ^ y0) << (64 - s)) | ((y1 ^ y0) >> s);
        let x0 = y0.wrapping_sub(x1);
        (x0, x1)
    }
}


#[cfg(test)]
mod mix_tests {
    use super::*;

    #[test]
    fn mix_overflow() {
        let mix = Mix::new(0, 1);
        let (x0, x1) = (u64::MAX, 2);
        let (y0, _) = mix.mix(x0, x1);
        
        assert_eq!(y0, 1);
    }

    #[test]
    fn mix_check_res() {
        let mix = Mix::new(4, 1);
        let (x0, x1) = (15, 44);
        let (y0, y1) = mix.mix(x0, x1);
        
        assert_eq!(y0, 59);
        assert_eq!(y1, 377957122107);


        let mix = Mix::new(2, 0);
        let (x0, x1) = (0x198248612874123, 0x123127121824178);
        let (y0, y1) = mix.mix(x0, x1);
        
        assert_eq!(y0, 196811444078609051);
        assert_eq!(y1, 4191716383270703890);
    }

    #[test]
    fn demix_check_res() {
        let mix = Mix::new(4, 1);
        let (y0, y1) = (59, 377957122107);
        let (x0, x1) = mix.demix(y0, y1);
        
        assert_eq!(x0, 15);
        assert_eq!(x1, 44);

        let mix = Mix::new(2, 0);
        let (y0, y1) = (196811444078609051, 4191716383270703890);
        let (x0, x1) = mix.demix(y0, y1);
        
        assert_eq!(x0, 0x198248612874123);
        assert_eq!(x1, 0x123127121824178);
    }
}