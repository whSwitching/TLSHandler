using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Internal.BulkEncryption
{
    class Aes256_CBC : IBulkEncryption
    {
        public int KeySize { get { return 256; } }

        AesCng _aes = null;
        public Aes256_CBC()
        {
            _aes = new AesCng
            {
                KeySize = this.KeySize,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.None
            };
        }

        public byte[] Encrypt(byte[] plain, byte[] key, byte[] iv, byte[] aead_aad = null, byte[] aead_associated = null)
        {
            if (key.Length * 8 != this.KeySize)
                throw new InvalidOperationException($"the given key has invalid size {key.Length * 8}, expect {this.KeySize}");
            _aes.Key = key;
            _aes.IV = iv;
            var encryptor = _aes.CreateEncryptor();
            return encryptor.TransformFinalBlock(plain, 0, plain.Length);
        }

        public byte[] Decrypt(byte[] secret, byte[] key, byte[] iv, byte[] aead_aad = null, byte[] aead_associated = null)
        {
            if (key.Length * 8 != this.KeySize)
                throw new InvalidOperationException($"the given key has invalid size {key.Length * 8}, expect {this.KeySize}");
            _aes.Key = key;
            _aes.IV = iv;
            var decryptor = _aes.CreateDecryptor();
            return decryptor.TransformFinalBlock(secret, 0, secret.Length);
        }

        public void Dispose()
        {
            _aes.Dispose();
        }

    }
}
