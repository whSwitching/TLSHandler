# TLSHandler
C# implementation of TLS 1.2/1.3
> as you dig deeper, Transport Layer Security becomes Application Layer Security to you

****

Server/Client certificate support:
- [x] RSA
- [ ] ECC

BulkEncryption implementation:
- [x] AES_128_CBC
- [x] AES_256_CBC
- [x] AES_128_GCM
- [x] AES_256_GCM
- [x] [ChaCha20_Poly1305](https://tools.ietf.org/html/rfc8439)

[NamedGroup](https://tools.ietf.org/html/rfc8422#section-5.1.1) implementation:
- [x] secp256r1 (0x0017)
- [x] secp384r1 (0x0018)
- [x] secp521r1 (0x0019)
- [x] x25519 (0x001D)
- [x] x448 (0x001E)

[SignatureAlgorithm](https://tools.ietf.org/html/rfc8446#section-4.2.3) implementation:
- [x] rsa_pkcs1_sha256 (0x0401) &emsp;&emsp; _[(TLS 1.3 Mandatory)](https://tools.ietf.org/html/rfc8446#section-9.1)_
- [x] rsa_pkcs1_sha384 (0x0501)
- [x] rsa_pkcs1_sha512 (0x0601)
- [x] rsa_pss_rsae_sha256 (0x0804) &emsp;&emsp; _[(TLS 1.3 Mandatory)](https://tools.ietf.org/html/rfc8446#section-9.1)_
- [x] rsa_pss_rsae_sha384 (0x0805)
- [x] rsa_pss_rsae_sha512 (0x0806)
- [ ] ecdsa_secp256r1_sha256 (0x0403) &emsp;&emsp; _[(TLS 1.3 Mandatory)](https://tools.ietf.org/html/rfc8446#section-9.1)_
- [ ] ecdsa_secp384r1_sha384 (0x0503)
- [ ] ecdsa_secp521r1_sha512 (0x0603)

[CipherSuite](https://tools.ietf.org/html/rfc8446#appendix-B.4) implementation:
- [x] TLS\_RSA\_WITH\_AES\_128\_CBC\_SHA (0x002F) &emsp;&emsp; _[(TLS 1.2 Mandatory)](https://tools.ietf.org/html/rfc5246#section-9)_
- [x] TLS_RSA_WITH_AES_128_CBC_SHA256 (0x003C)
- [x] TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xC013)
- [x] TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0xC027)
- [x] TLS\_AES\_128\_GCM\_SHA256 (0x1301) &emsp;&emsp; _[(TLS 1.3 Mandatory)](https://tools.ietf.org/html/rfc8446#section-9.1)_
- [x] TLS_AES_256_GCM_SHA384 (0x1302)
- [x] TLS\_CHACHA20\_POLY1305\_SHA256 (0x1303) &emsp;&emsp; _(TLS1.3 Mobile Client Prefer)_

****

##### Not implemented
- [ ] [NewSessionTicket](https://tools.ietf.org/html/rfc8446#section-4.6.1) handshake message
- [ ] Psk KeyExchange
- [ ] [0-RTT Data](https://tools.ietf.org/html/rfc8446#section-2.3)

## Usage

* [https sample](https://github.com/whSwitching/TLSHandler/tree/master/Projects/SampleHttps) is a working demo of https service without using SslStream

* if you don&apos;t know how to Read tls records from a stream, you were actually looking for [System.Net.Security.SslStream](https://docs.microsoft.com/en-us/dotnet/api/system.net.security.sslstream?view=netframework-4.8) but not this repository
