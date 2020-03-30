using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Internal
{
    interface IEmBulkEncryption : IBulkEncryption
    {
        byte[] Encrypt(byte[] plain, byte[] key, byte[] iv);

        byte[] Decrypt(byte[] secret, byte[] key, byte[] iv);
    }
}
