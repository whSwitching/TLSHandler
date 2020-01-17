using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.TLS.Extensions
{
    //https://tools.ietf.org/html/rfc8446#section-4.2.9
    class PskKeyExchangeModes : Extension
    {
        public override ExtensionType Type { get { return ExtensionType.PSK_KEY_EXCHANGE_MODES; } }
        public byte EntriesLength { get { return Data[4]; } }
        public PskKeyExchangeMode[] ExchangeModes { get; private set; }

        public PskKeyExchangeModes(byte[] extensionBytes) : base(extensionBytes)
        {
            ExchangeModes = extensionBytes.Skip(5).Select(a => (PskKeyExchangeMode)a).ToArray();
        }
    }
}
