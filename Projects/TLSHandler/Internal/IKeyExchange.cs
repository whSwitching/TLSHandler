using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Internal
{
    interface IKeyExchange : IDisposable
    {
        bool IsRsaKeyExchange { get; }
        void Exchange(byte[] encryptedPreMasterSecret, byte[] clientRandom, byte[] serverRandom, object privateParameters);
    }
}
