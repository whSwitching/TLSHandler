using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Enums
{
    //https://tools.ietf.org/html/rfc8446#section-4.2.9
    public enum PskKeyExchangeMode : byte
    {
        psk_ke = 0,         //PSK-only key establishment
        psk_dhe_ke = 1,     //PSK with (EC)DHE key establishment
    }
}
