use std::num::Wrapping;

pub struct Mt19337 {
    state: [Wrapping<u32>; 624],
    index: usize
}

impl Mt19337 {
    const SIZE: usize = 624;
    const SEED_MULT: Wrapping<u32> = Wrapping(0x6c07_8965);
    const UPPER_MASK: Wrapping<u32> = Wrapping(0x8000_0000);
    const LOWER_MASK: Wrapping<u32> = Wrapping(0x7fff_ffff);
    const FIRST_MASK: Wrapping<u32> = Wrapping(0x9d2c_5680);
    const SECOND_MASK: Wrapping<u32> = Wrapping(0xefc6_0000);
    const TWIST_CONST: Wrapping<u32> = Wrapping(0x9908_b0df);

    pub fn new(seed: u32) -> Self {
        let mut result = Self {
            state: [Wrapping(0); Mt19337::SIZE],
            index: 0
        };
        result.seed(seed);
        result
    }

    pub fn seed(&mut self, seed: u32) {
        self.state[0] = Wrapping(seed);
        for i in 1..Mt19337::SIZE {
            let x = self.state[i - 1] ^ (self.state[i - 1] >> 30);
            self.state[i] = Mt19337::SEED_MULT * x + Wrapping(i as u32);
        }
        self.twist();
    }

    pub fn next_u32(&mut self) -> u32 {
        if self.index >= Mt19337::SIZE {
            self.twist();
        }
        let mut x = self.state[self.index];

        x ^=  x >> 11;
        x ^= (x <<  7) & Mt19337::FIRST_MASK;
        x ^= (x << 15) & Mt19337::SECOND_MASK;
        x ^=  x >> 18;

        self.index += 1;
        x.0
    }

    fn twist(&mut self) {
        let k = Mt19337::SIZE - 1;
        let m = 227;
        let n = Mt19337::SIZE - m;
        for i in 0..m {
            let x = (self.state[i] & Mt19337::UPPER_MASK) | (self.state[(i + 1) ] & Mt19337::LOWER_MASK);
            self.state[i] = self.state[n + i] ^ (x >> 1) ^ ((x & Wrapping(1)) * Mt19337::TWIST_CONST);
        }
        for i in n..Mt19337::SIZE - 1 {
            let x = (self.state[i] & Mt19337::UPPER_MASK) | (self.state[i + 1] & Mt19337::LOWER_MASK);
            self.state[i] = self.state[i - n] ^ (x >> 1) ^ ((x & Wrapping(1)) * Mt19337::TWIST_CONST);
        }
        let x = (self.state[k] & Mt19337::UPPER_MASK) | (self.state[0] & Mt19337::LOWER_MASK);
        self.state[k] = self.state[n - 1] ^ (x >> 1) ^ ((x & Wrapping(1)) * Mt19337::TWIST_CONST);
        self.index = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::Mt19337;

    #[test]
    fn known_output() {
        let mut random = Mt19337::new(1);
        let output = [
            0x6ac1f425, 0xff4780eb, 0xb8672f8c, 0xeebc1448, 
            0x00077EFF, 0x20CCC389, 0x4D65aacb, 0xffc11E85
        ];
        for i in 0..output.len() {
            assert_eq!(random.next_u32(), output[i]);
        }
    }
}