# CFShare
Split and reconstruct your file into/from encrypted shares using the Shamir Secret Sharing technique.

## How does it work
In the provided implementation the input file is encrypted using a cipher selected by the user.\
The random cipher secret key used for encryption is given as input to a Shamir Secret sharing algorithm in order to produce different secrets.\
This encrypted file is copied into _T_ shares paired with one unique Shamir secret and a hash (computed using HMAC and SHA256), which provides authenticity and integrity of the original content of the file, into multiple shares.\
Based on the user's preferences the encrypted content can be copied into one specific file so that it is not contained in every share.

In order to reconstruct the original file at least _M<T_ shares are required (_M_and _T_ are chosen by the user in the split phase).\
Once the user has the required number of shares, the original file is reconstructed by obtaining the original encryption key from the Shamir secrets in the shares, which is later used to decrypt the encrypted content of the original file.
The resulting file is later verified for its authenticity and integrity using the tag produced by HMAC.
## Split
You can use "cfshare split <arguments>" to split a file into multiple encrypted shares.
| argument | type    | description                                      |
| --------- | ------- | ------------------------------------------------ |
| `-i I`     | String  | Original file relative path        |
| `-o O`  | String | Relative path of the output files          |
| `-t T` | Int  | Total number of shares                            |
| `-m M`  | Int | Minimum number of shares required for reconstruction |
| `-so --sharesonly`  | - | Output encrypted file and shares as distinctive files |
| `-c`  | String | Select Cipher (valid options: AES|ChaCha20|Camellia, default:AES) |
## Bind
You can use "cfshare bind <arguments>" to bind multiple encrypted shares and reconstruct the original file.
| argument | type    | description                                      |
| --------- | ------- | ------------------------------------------------ |
| `-i I`     | String+  | Relative paths to encrypted files        |
| `-o O`  | String | Unencrypted reconstructed output path of the file          |
| `-s S` | String+  | Relative paths to shares (required only if the file was split with "-so" option)                            |

## Dependencies
- [cryptography](https://cryptography.io/)