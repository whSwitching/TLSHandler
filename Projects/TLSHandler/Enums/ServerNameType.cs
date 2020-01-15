using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Enums
{
    //https://tools.ietf.org/html/rfc6066#section-3
    public enum ServerNameType : byte
    {
        Host_Name = 0x00,
    }
}
