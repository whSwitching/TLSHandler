using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Engines = Org.BouncyCastle.Crypto.Engines;
using Modes = Org.BouncyCastle.Crypto.Modes;
using Parameters = Org.BouncyCastle.Crypto.Parameters;

namespace TLSHandler.Internal.Crypto
{
    public class Aes128_GCM : IBulkEncryption
    {
        public int KeySize { get { return 128; } }
        public int MacSize { get { return 128; } }

        public byte[] Decrypt(byte[] secret, byte[] key, byte[] iv, byte[] aad = null, byte[] associated = null)
        {
            if (key.Length * 8 != this.KeySize)
                throw new InvalidOperationException($"the given key has invalid size {key.Length * 8}, expect {this.KeySize}");

            var cipher = new Modes.GcmBlockCipher(new Engines.AesEngine());
            cipher.Init(false, new Parameters.AeadParameters(new Parameters.KeyParameter(key), this.MacSize, iv, associated));

            if (aad != null)
                cipher.ProcessAadBytes(aad, 0, aad.Length);

            var ret = new byte[cipher.GetOutputSize(secret.Length)];
            var len = cipher.ProcessBytes(secret, 0, secret.Length, ret, 0);
            cipher.DoFinal(ret, len);

            return ret;
        }

        public byte[] Encrypt(byte[] plain, byte[] key, byte[] iv, byte[] aad = null, byte[] associated = null)
        {
            if (key.Length * 8 != this.KeySize)
                throw new InvalidOperationException($"the given key has invalid size {key.Length * 8}, expect {this.KeySize}");

            var cipher = new Modes.GcmBlockCipher(new Engines.AesEngine());
            cipher.Init(true, new Parameters.AeadParameters(new Parameters.KeyParameter(key), this.MacSize, iv, associated));

            if (aad != null)
                cipher.ProcessAadBytes(aad, 0, aad.Length);

            var ret = new byte[cipher.GetOutputSize(plain.Length)];
            var len = cipher.ProcessBytes(plain, 0, plain.Length, ret, 0);
            cipher.DoFinal(ret, len);

            return ret;
        }

        public void Dispose()
        {
        }
    }
}
