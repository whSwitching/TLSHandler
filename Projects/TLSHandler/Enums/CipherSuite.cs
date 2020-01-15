using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Enums
{
    //https://tools.ietf.org/html/rfc5246#appendix-A.5
    //https://tools.ietf.org/html/rfc8446#appendix-B.4
    public enum CipherSuite : ushort
    {
        TLS_DHE_PSK_WITH_AES_128_CBC_SHA = 0x0090,              // SSLv3    Kx=DHEPSK    Au=PSK    Enc=AES(128)                Mac=SHA1
        TLS_DHE_PSK_WITH_AES_256_CBC_SHA = 0x0091,              // SSLv3    Kx=DHEPSK    Au=PSK    Enc=AES(256)                Mac=SHA1
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033,              // SSLv3    Kx=DH        Au=RSA    Enc=AES(128)                Mac=SHA1
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039,              // SSLv3    Kx=DH        Au=RSA    Enc=AES(256)                Mac=SHA1
        TLS_PSK_WITH_AES_128_CBC_SHA = 0x008C,                  // SSLv3    Kx=PSK       Au=PSK    Enc=AES(128)                Mac=SHA1
        TLS_PSK_WITH_AES_256_CBC_SHA = 0x008D,                  // SSLv3    Kx=PSK       Au=PSK    Enc=AES(256)                Mac=SHA1
        TLS_RSA_PSK_WITH_AES_128_CBC_SHA = 0x0094,              // SSLv3    Kx=RSAPSK    Au=RSA    Enc=AES(128)                Mac=SHA1
        TLS_RSA_PSK_WITH_AES_256_CBC_SHA = 0x0095,              // SSLv3    Kx=RSAPSK    Au=RSA    Enc=AES(256)                Mac=SHA1
        TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F,                  // SSLv3    Kx=RSA       Au=RSA    Enc=AES(128)                Mac=SHA1
        TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035,                  // SSLv3    Kx=RSA       Au=RSA    Enc=AES(256)                Mac=SHA1
        TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA = 0xC01E,          // SSLv3    Kx=SRP       Au=RSA    Enc=AES(128)                Mac=SHA1
        TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA = 0xC021,          // SSLv3    Kx=SRP       Au=RSA    Enc=AES(256)                Mac=SHA1
        TLS_SRP_SHA_WITH_AES_128_CBC_SHA = 0xC01D,              // SSLv3    Kx=SRP       Au=SRP    Enc=AES(128)                Mac=SHA1
        TLS_SRP_SHA_WITH_AES_256_CBC_SHA = 0xC020,              // SSLv3    Kx=SRP       Au=SRP    Enc=AES(256)                Mac=SHA1

        TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 = 0x00B2,           // TLSv1    Kx=DHEPSK    Au=PSK    Enc=AES(128)                Mac=SHA256
        TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 = 0x00B3,           // TLSv1    Kx=DHEPSK    Au=PSK    Enc=AES(256)                Mac=SHA384
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xC009,          // TLSv1    Kx=ECDH      Au=ECDSA  Enc=AES(128)                Mac=SHA1
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xC00A,          // TLSv1    Kx=ECDH      Au=ECDSA  Enc=AES(256)                Mac=SHA1
        TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA = 0xC035,            // TLSv1    Kx=ECDHEPSK  Au=PSK    Enc=AES(128)                Mac=SHA1
        TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 = 0xC037,         // TLSv1    Kx=ECDHEPSK  Au=PSK    Enc=AES(128)                Mac=SHA256
        TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA = 0xC036,            // TLSv1    Kx=ECDHEPSK  Au=PSK    Enc=AES(256)                Mac=SHA1
        TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 = 0xC038,         // TLSv1    Kx=ECDHEPSK  Au=PSK    Enc=AES(256)                Mac=SHA384
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xC013,            // TLSv1    Kx=ECDH      Au=RSA    Enc=AES(128)                Mac=SHA1
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xC014,            // TLSv1    Kx=ECDH      Au=RSA    Enc=AES(256)                Mac=SHA1
        TLS_PSK_WITH_AES_128_CBC_SHA256 = 0x00AE,               // TLSv1    Kx=PSK       Au=PSK    Enc=AES(128)                Mac=SHA256
        TLS_PSK_WITH_AES_256_CBC_SHA384 = 0x00AF,               // TLSv1    Kx=PSK       Au=PSK    Enc=AES(256)                Mac=SHA384
        TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 = 0x00B6,           // TLSv1    Kx=RSAPSK    Au=RSA    Enc=AES(128)                Mac=SHA256
        TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 = 0x00B7,           // TLSv1    Kx=RSAPSK    Au=RSA    Enc=AES(256)                Mac=SHA384

        TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 = 0x00AA,           // TLSv1.2  Kx=DHEPSK    Au=PSK    Enc=AESGCM(128)             Mac=AEAD
        TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 = 0x00AB,           // TLSv1.2  Kx=DHEPSK    Au=PSK    Enc=AESGCM(256)             Mac=AEAD
        TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAD,     // TLSv1.2  Kx=DHEPSK    Au=PSK    Enc=CHACHA20/POLY1305(256)  Mac=AEAD
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x0067,           // TLSv1.2  Kx=DH        Au=RSA    Enc=AES(128)                Mac=SHA256
        TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009E,           // TLSv1.2  Kx=DH        Au=RSA    Enc=AESGCM(128)             Mac=AEAD
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x006B,           // TLSv1.2  Kx=DH        Au=RSA    Enc=AES(256)                Mac=SHA256
        TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009F,           // TLSv1.2  Kx=DH        Au=RSA    Enc=AESGCM(256)             Mac=AEAD
        TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAA,     // TLSv1.2  Kx=DH        Au=RSA    Enc=CHACHA20/POLY1305(256)  Mac=AEAD
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC023,       // TLSv1.2  Kx=ECDH      Au=ECDSA  Enc=AES(128)                Mac=SHA256
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B,       // TLSv1.2  Kx=ECDH      Au=ECDSA  Enc=AESGCM(128)             Mac=AEAD
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xC024,       // TLSv1.2  Kx=ECDH      Au=ECDSA  Enc=AES(256)                Mac=SHA384
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C,       // TLSv1.2  Kx=ECDH      Au=ECDSA  Enc=AESGCM(256)             Mac=AEAD
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA9, // TLSv1.2  Kx=ECDH      Au=ECDSA  Enc=CHACHA20/POLY1305(256)  Mac=AEAD
        TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAC,   // TLSv1.2  Kx=ECDHEPSK  Au=PSK    Enc=CHACHA20/POLY1305(256)  Mac=AEAD
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xC027,         // TLSv1.2  Kx=ECDH      Au=RSA    Enc=AES(128)                Mac=SHA256
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F,         // TLSv1.2  Kx=ECDH      Au=RSA    Enc=AESGCM(128)             Mac=AEAD
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xC028,         // TLSv1.2  Kx=ECDH      Au=RSA    Enc=AES(256)                Mac=SHA384
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030,         // TLSv1.2  Kx=ECDH      Au=RSA    Enc=AESGCM(256)             Mac=AEAD
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA8,   // TLSv1.2  Kx=ECDH      Au=RSA    Enc=CHACHA20/POLY1305(256)  Mac=AEAD
        TLS_PSK_WITH_AES_128_GCM_SHA256 = 0x00A8,               // TLSv1.2  Kx=PSK       Au=PSK    Enc=AESGCM(128)             Mac=AEAD
        TLS_PSK_WITH_AES_256_GCM_SHA384 = 0x00A9,               // TLSv1.2  Kx=PSK       Au=PSK    Enc=AESGCM(256)             Mac=AEAD
        TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAB,         // TLSv1.2  Kx=PSK       Au=PSK    Enc=CHACHA20/POLY1305(256)  Mac=AEAD
        TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 = 0x00AC,           // TLSv1.2  Kx=RSAPSK    Au=RSA    Enc=AESGCM(128)             Mac=AEAD
        TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 = 0x00AD,           // TLSv1.2  Kx=RSAPSK    Au=RSA    Enc=AESGCM(256)             Mac=AEAD
        TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAE,     // TLSv1.2  Kx=RSAPSK    Au=RSA    Enc=CHACHA20/POLY1305(256)  Mac=AEAD
        TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003C,               // TLSv1.2  Kx=RSA       Au=RSA    Enc=AES(128)                Mac=SHA256
        TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009C,               // TLSv1.2  Kx=RSA       Au=RSA    Enc=AESGCM(128)             Mac=AEAD
        TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003D,               // TLSv1.2  Kx=RSA       Au=RSA    Enc=AES(256)                Mac=SHA256
        TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009D,               // TLSv1.2  Kx=RSA       Au=RSA    Enc=AESGCM(256)             Mac=AEAD

        TLS_AES_128_GCM_SHA256 = 0x1301,                        // TLSv1.3  Kx=any       Au=any    Enc=AESGCM(128)             Mac=AEAD
        TLS_AES_256_GCM_SHA384 = 0x1302,                        // TLSv1.3  Kx=any       Au=any    Enc=AESGCM(256)             Mac=AEAD
        TLS_CHACHA20_POLY1305_SHA256 = 0x1303,                  // TLSv1.3  Kx=any       Au=any    Enc=CHACHA20/POLY1305(256)  Mac=AEAD
        TLS_AES_128_CCM_SHA256 = 0x1304,                        // TLSv1.3  Kx=any       Au=any    Enc=AESCCM(128)             Mac=AEAD
        TLS_AES_128_CCM_8_SHA256 = 0x1305,                      // TLSv1.3  Kx=any       Au=any    Enc=AESCCM(128)             Mac=AEAD
    }
}
