using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Internal
{
    interface IAeadBulkEncryption : IBulkEncryption
    {
        int MacSize { get; }

        byte[] Encrypt(byte[] plain, byte[] key, byte[] iv, byte[] aad, byte[] associated);

        byte[] Decrypt(byte[] secret, byte[] key, byte[] iv, byte[] aad, byte[] associated);
    }
}
