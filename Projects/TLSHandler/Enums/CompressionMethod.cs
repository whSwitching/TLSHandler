using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Enums
{
    //https://tools.ietf.org/html/rfc5246#page-40
    public enum CompressionMethod : byte
    {
        NO_COMPRESSION = 0x00,
    }
}
