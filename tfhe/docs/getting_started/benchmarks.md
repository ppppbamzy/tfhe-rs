# Benchmarks 

Due to their nature, homomorphic operations are naturally slower than their clear equivalent. Some timings are exposed for basic operations. For completeness, benchmarks for other libraries are also given.

All benchmarks were launched on an AWS m6i.metal with the following specifications: Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz and 512GB of RAM.

## Boolean

This measures the execution time of a single binary Boolean gate.

### tfhe-rs::boolean.

| Parameter set         | Concrete FFT | Concrete FFT + AVX512 |
| --------------------- | ------------ | --------------------- |
| DEFAULT\_PARAMETERS   | 8.8ms        | 6.8ms                 |
| TFHE\_LIB\_PARAMETERS | 13.6ms       | 10.9ms                |

### tfhe-lib.

| Parameter set                                    | fftw   | spqlios-fma |
| ------------------------------------------------ | ------ | ----------- |
| default\_128bit\_gate\_bootstrapping\_parameters | 28.9ms | 15.7ms      |

### OpenFHE.

| Parameter set | GINX  | GINX (Intel HEXL) |
| ------------- | ----- | ----------------- |
| STD\_128      | 172ms | 78ms              |
| MEDIUM        | 113ms | 50.2ms            |


## Integer
This measures the execution time for some operation sets of tfhe-rs::integer.

| Operations\bit_size | `FheUint8` | `FheUint16` | `FheUint32` | `FheUint40` | `FheUint64` | `FheUint128` | `FheUint256` |
|---------------------|------------|-------------|-------------|-------------|-------------|--------------|--------------|
| add                 | 153 ms     | 198 ms      | 246 ms      | 293 ms      | 308 ms      | 426 ms       | 483 ms       |
| sub                 | 153 ms     | 197 ms      | 245 ms      | 289 ms      | 312 ms      | 435 ms       | 515 ms       |
| bitand              | 37.5 ms    | 40.3 ms     | 42.8 ms     | 43.2 ms     | 46.3 ms     | 63.0 ms      | 63.4 ms      |
| bitor               | 37.4 ms    | 39.9 ms     | 41.1 ms     | 42.1 ms     | 45.4 ms     | 56.0 ms      | 58.1 ms      |
| bitxor              | 36.5 ms    | 40.4 ms     | 41.7 ms     | 42.6 ms     | 45.3 ms     | 56.5 ms      | 59.6 ms      |
| negation            | 142 ms     | 195 ms      | 242 ms      | 282 ms      | 297 ms      | 419 ms       | 498 ms       |
| not_equal           | 81.0 ms    | 81.1 ms     | 121 ms      | 123 ms      | 126 ms      | 134 ms       | 135 ms       |
| equal               | 80.4 ms    | 81.2 ms     | 117 ms      | 120 ms      | 124 ms      | 134 ms       | 136 ms       |
| greater_or_equal    | 107 ms     | 145 ms      | 191 ms      | 229 ms      | 246 ms      | 296 ms       | 369 ms       |
| greater_than        | 110 ms     | 146 ms      | 191 ms      | 231 ms      | 245 ms      | 294 ms       | 365 ms       |
| left_shift          | 193 ms     | 237 ms      | 297 ms      | 380 ms      | 445 ms      | 548 ms       | 1.07 s       |
| right_shift         | 193 ms     | 237 ms      | 305 ms      | 380 ms      | 435 ms      | 551 ms       | 1.04 s       |
| less_or_equal       | 103 ms     | 144 ms      | 195 ms      | 229 ms      | 248 ms      | 295 ms       | 368 ms       |
| less_than           | 103 ms     | 147 ms      | 188 ms      | 226 ms      | 240 ms      | 292 ms       | 360 ms       |
| max                 | 184 ms     | 226 ms      | 280 ms      | 322 ms      | 340 ms      | 394 ms       | 510 ms       |
| min                 | 188 ms     | 226 ms      | 280 ms      | 326 ms      | 339 ms      | 399 ms       | 516 ms       |
| mul                 | 277 ms     | 385 ms      | 545 ms      | 763 ms      | 1.16 s      | 3.10 s       | 10.9 s       |
| rotate_left         | 195 ms     | 241 ms      | 300 ms      | 380 ms      | 428 ms      | 530 ms       | 1.05 s       |
| rotate_right        | 198 ms     | 243 ms      | 299 ms      | 379 ms      | 427 ms      | 541 ms       | 1.08 s       |

All timings are related to parallelized Radix-based integer operations, where each block is encrypted using the default parameters (i.e., PARAM\_MESSAGE\_2\_CARRY\_2, more information about parameters can be found [here](../fine_grain_api/shortint/parameters.md)). 
To ensure predictable timings, the operation flavor is the `default` one: the carry are propagated if needed. Operation cost could be reduced by using `unchecked`, `checked`, or `smart`. 


## Shortint
This measures the execution time for some operations and some parameter sets of tfhe-rs::shortint.

This uses the Concrete FFT + avx512 configuration.

| Parameter set               | unchecked\_add | unchecked\_mul\_lsb | keyswitch\_programmable\_bootstrap |
|-----------------------------|----------------|---------------------|------------------------------------|
| PARAM\_MESSAGE\_1\_CARRY\_1 | 338 ns         | 8.3 ms              | 8.1 ms                             |
| PARAM\_MESSAGE\_2\_CARRY\_2 | 406 ns         | 18.4 ms             | 18.4 ms                            |
| PARAM\_MESSAGE\_3\_CARRY\_3 | 3.06 µs        | 134 ms              | 129.4 ms                           |
| PARAM\_MESSAGE\_4\_CARRY\_4 | 11.7 µs        | 854 ms              | 828.1 ms                           |

Next, the timings for the operation flavor `default` are given. This flavor ensures predictable timings of an operation all along the circuit by clearing the carry space after each operation.

| Parameter set               |            add |        mul\_lsb     | keyswitch\_programmable\_bootstrap |
| --------------------------- | -------------- | ------------------- | ---------------------------------- |
| PARAM\_MESSAGE\_1\_CARRY\_1 | 7.90 ms        | 8.00 ms             | 8.10 ms                            |
| PARAM\_MESSAGE\_2\_CARRY\_2 | 18.4 ms        | 18.1 ms             | 18.4 ms                            |
| PARAM\_MESSAGE\_3\_CARRY\_3 | 131.5 ms       | 129.5 ms            | 129.4 ms                           |
| PARAM\_MESSAGE\_4\_CARRY\_4 | 852.5 ms       | 839.7 ms            | 828.1 ms                           |

## How to reproduce benchmarks

TFHE-rs benchmarks can easily be reproduced from the [sources](https://github.com/zama-ai/tfhe-rs). 

```shell
#Boolean benchmarks:
make bench_boolean

#Integer benchmarks:
make bench_integer

#Shortint benchmarks:
make bench_shortint
```

If the host machine supports AVX512, then the argument `AVX512_SUPPORT=ON' should be added, e.g.:

```shell
#Integer benchmarks:
make AVX512_SUPPORT=ON bench_integer
```




