using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Enums
{
    //https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
    public enum ExtensionType : ushort
    {
        SERVER_NAME = 0x0000,
        EXTENDED_MASTER_SECRET = 0x0017,
        SUPPORTED_VERSIONS = 0x002B,
        SIGNATURE_ALGORITHMS = 0x000D,
        PRE_SHARED_KEY = 0x0029,
        PSK_KEY_EXCHANGE_MODES = 0x002D,
        SUPPORTED_GROUPS = 0x000A,      //rename from TLS1.2 elliptic_curves, Supported Elliptic Curves
        EC_POINTS_FORMATS = 0x000B,
        SIGNATURE_ALGORITHMS_CERT = 0x0032,
        KEY_SHARE = 0x0033,
        RENEGOTIATION_INFO = 0xFF01
    }
}
