![bifrost-icon-100px](https://github.com/user-attachments/assets/7ad0ec8c-329f-47d9-aa68-074a75de6051)

# Crystals
Crystals is a post-quantum verification protocol for Solana leveraging the power of Dilithium 2 & 3 -- achieving more than 128 bits of security against all known classical and quantum attacks.

## Dilithium
Dilithium is a digital signature scheme that is strongly secure under chosen message attacks based on the hardness of lattice problems over module lattices. The security notion means that an adversary having access to a signing oracle cannot produce a signature of a message whose signature he hasn't yet seen, nor produce a different signature of a message that he already saw signed.

### Scientific Background
The design of Dilithium is based on the "Fiat-Shamir with Aborts" technique of Lyubashevsky which uses rejection sampling to make lattice-based Fiat-Shamir schemes compact and secure. The scheme with the smallest signature sizes using this approach is the one of Ducas, Durmus, Lepoint, and Lyubashevsky which is based on the NTRU assumption and crucially uses Gaussian sampling for creating signatures. Because Gaussian sampling is hard to implement securely and efficiently, we opted to only use the uniform distribution. Dilithium improves on the most efficient scheme that only uses the uniform distribution, due to Bai and Galbraith, by using a new technique that shrinks the public key by more than a factor of 2. To the best of our knowledge, Dilithium has the smallest public key + signature size of any lattice-based signature scheme that only uses uniform sampling.

#### Using crystals library in your own Solana program
#### QuickStart:
```
cargo add bifrost-crystals
```

#### Update cargo.toml
```
crystals = { features = ["mode3"] }
```

#### Reference the crate in your code
```
use crystals::*;
```
 
#### Create a verification instruction and have it update account data
```
let sig_verify = verify(&args.sig, &args.msg, &args.public_key);
assert!(sig_verify.is_ok());
Ok(())
```

** PQC verification should be used to trigger events rather than attempting to invoke them all together. Due to dilithium's large public key & signature size its recommended to bind events to the verification process.


#### * Dilithium is one of the candidate algorithms submitted to the NIST post-quantum cryptography project and was developed by a team of PQC specialists. 
#### * The crystals library & program developed by Bifrost is a memory efficient rust implementation designed specifically for the Solana blockchain.

### CRYSTALS Team - PQC Algorithm Designers

  -  Roberto Avanzi, ARM Limited (DE)
  -  Shi Bai, Florida Atlantic University (US)
  -  Joppe Bos, NXP Semiconductors (BE)
  -  Jintai Ding, Tsinghua University (CN)
  -  Léo Ducas, CWI Amsterdam (NL) & Leiden University (NL)
  -  Eike Kiltz, Ruhr University Bochum (DE)
  -  Tancrède Lepoint, Amazon Web Services (US)
  -  Vadim Lyubashevsky, IBM Research Zurich (CH)
  -  John M. Schanck, Mozilla (US)
  -  Peter Schwabe, MPI-SP (DE) & Radboud University (NL)
  -  Gregor Seiler, IBM Research Zurich (CH)
  -  Damien Stehle, CryptoLab Inc (FR)

