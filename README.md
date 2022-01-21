# ZeroNetX Cryptography
Cryptography interface for ZeroNetX

This library is a fork of the zeronet_cryptography crate by anshorei modified accordingly for ZeroNetX Usage. It has been split
from the main project because it could be useful to build programs
that have to sign data that ZN clients will consider valid.

## Benchmarks
zeronetx_cryptography has not been benchmarked yet.
If you'd like to help: contact Ansho Rei (pramukesh@zeroid.bit) on ZeroMe or ZeroMail!

## verify

```
use zeronetx_cryptography::verify;

let data = "Testmessage";
let address = "1HZwkjkeaoZfTSaJxDw6aKkxp45agDiEzN";
let signature = "G+Hnv6dXxOAmtCj8MwQrOh5m5bV9QrmQi7DSGKiRGm9TWqWP3c5uYxUI/C/c+m9+LtYO26GbVnvuwu7hVPpUdow=";

match verify(data, address, signature) {
  Ok(_) => println!("Signature is a valid."),
  Err(_) => println!("Signature is invalid."),
}
```

## sign

```
use zeronetx_cryptography::sign;

let data = "Testmessage";
let private_key = "5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss";

match sign(data, private_key) {
  Ok(signature) => println!("The signature is {}", signature),
  Err(_) => println!("An error occured during the signing process"),
}
```

## create

```
use zeronetx_cryptography::create;

let (priv_key, pub_key) = create();
```
