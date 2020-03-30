using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Internal.KeyExchange
{
    class PskKeyExchange : IKeyExchange
    {
        public bool IsRsaKeyExchange => throw new NotImplementedException();

        public void Exchange(byte[] encryptedPreMasterSecret, byte[] clientRandom, byte[] serverRandom, object privateParameters)
        {
            // not implemented
        }

        public void Dispose()
        {
        }
    }
}
