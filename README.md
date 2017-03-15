## Digital Signature Scheme based on Supersingular Isogenies.

This software implements the digital signature scheme described in the paper [*A Post-Quantum Digital Signature Scheme Based on Supersingular Isogenies*](https://eprint.iacr.org/2017/186) by Yoo, Azarderakhsh, Jalali, Jao, and Soukharev.

This implementation leverages the [Supersingular Isogeny Diffie-Hellman (SIDH) Library](https://www.microsoft.com/en-us/research/project/sidh-library/) published by Microsoft Research.


### IMPLEMENTATION OPTIONS:

The following implementation options are available:

- The library contains a portable implementation (enabled by the "GENERIC" option) and an optimized
  x64 implementation. Note that non-x64 platforms are only supported by the generic implementation. 

- Optimized x64 assembly implementations enabled by the "ASM" option in Linux.



### INSTRUCTIONS FOR LINUX OS:

BUILDING THE LIBRARY AND EXECUTING THE TESTS WITH GNU GCC OR CLANG:

To compile on Linux using GNU GCC or clang, execute the following command from the command prompt:

make ARCH=[x64/x86/ARM] CC=[gcc/clang] ASM=[TRUE/FALSE] GENERIC=[TRUE/FALSE]

After compilation, run kex_text. This will run an iteration of the key exchange benchmark then run the keygen, 
signing, and verification algorithms of the signature scheme.

For example, to compile the key exchange tests using clang and the fully optimized x64 implementation 
in assembly, execute:

make CC=clang ARCH=x64 ASM=TRUE

Whenever an unsupported configuration is applied, the following message will be displayed: #error -- 
"Unsupported configuration". For example, the use of assembly is not supported when selecting the portable 
implementation (i.e., if GENERIC=TRUE). Similarly, x86 and ARM are only supported when GENERIC=TRUE.
