# AES Cipher

```
USAGE:
    aes [OPTIONS] --file <FILE> --key <KEY> <MODE>

ARGS:
    <MODE>    [possible values: enc, dec]

OPTIONS:
    -h, --help                   Print help information
    -i, --file <FILE>            The file to encrypt
    -k, --key <KEY>              The AES key, 16 chars for AES128, 24 chars for AES192, 32 chars for
                                 AES256
    -o, --output <OUTPUT>        The output file name
    -s, --key-size <KEY_SIZE>    The AES key size. 128, 192 or 256 [default: 128]
    -V, --version                Print version information
    -x, --hex                    Whether to use hex string as the key
```
