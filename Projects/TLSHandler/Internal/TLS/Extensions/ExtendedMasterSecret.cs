using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.TLS.Extensions
{
    //https://tools.ietf.org/html/rfc7627#section-5.1
    class ExtendedMasterSecret : Extension
    {
        public override ExtensionType Type => ExtensionType.EXTENDED_MASTER_SECRET;

        public ExtendedMasterSecret(byte[] data) : base(data)
        {
        }

    }
}
