using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.TLS.Handshakes
{
    public class EncryptedFragment : PacketData
    {
        public EncryptedFragment(byte[] bodyBytes)
        {
            Data = bodyBytes;
        }
    }
}
