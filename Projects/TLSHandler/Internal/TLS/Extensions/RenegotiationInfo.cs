using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.TLS.Extensions
{
    //https://tools.ietf.org/html/rfc5746#section-3.2
    class RenegotiationInfo : Extension
    {
        public override ExtensionType Type { get { return ExtensionType.RENEGOTIATION_INFO; } }

        public byte SubExtensionsLength { get { return Data[4]; } }

        public Extension[] SubExtensions { get; private set; }

        public RenegotiationInfo(byte[] extensionBytes) : base(extensionBytes)
        {
            var subbytes = Data.Skip(5).ToArray();
            SubExtensions = Extension.Extract(subbytes);
        }

    }
}
