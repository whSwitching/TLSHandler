using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Internal
{
    interface IAead
    {
        int MacSize { get; }
    }

    interface IBulkEncryption : IDisposable
    {
        int KeySize { get; }

        byte[] Encrypt(byte[] plain, byte[] key, byte[] iv, byte[] aead_aad = null, byte[] aead_associated = null);

        byte[] Decrypt(byte[] secret, byte[] key, byte[] iv, byte[] aead_aad = null, byte[] aead_associated = null);
    }
}
