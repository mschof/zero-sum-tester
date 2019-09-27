## Zero-Sum Testing Tool
This is a short tool written in C++ to test zero-sum distinguishers for cryptographic permutations using polynomial S-boxes over GF(2^n). Currently, the following primitives are implemented:
- MiMC [1]
- Some versions of GMiMC [2]
- HadesMiMC and variants (e.g., only partial S-box layers) [3]

## Usage
Use with `<program> <n> <t> <num_rounds>`, where
- `n` is the block size
- `t` is the number of cells
- `num_rounds` is the number of rounds

## Other settings
Other settings can be changed at the top of the file and at the beginning of the main() function. These settings include:
- Changing the degree of the round function
- Changing the cipher
- Setting whether the round constants and keys are randomly chosen or not
- Changing the affine layer matrix where appropriate
- and much more

[1] [https://eprint.iacr.org/2016/492](https://eprint.iacr.org/2016/492)  
[2] [https://eprint.iacr.org/2019/397](https://eprint.iacr.org/2019/397)  
[3] Waiting for paper
