using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.TLS.Extensions
{
    //https://tools.ietf.org/html/rfc8422#section-5.1.2
    class EcPointFormats : Extension
    {
        public override ExtensionType Type => ExtensionType.EC_POINTS_FORMATS;
        public byte EntriesLength { get { return Data[4]; } }
        public ECPointFormat[] PointFormats { get; private set; }

        public EcPointFormats(byte[] data) : base(data)
        {
            PointFormats = Data.Skip(5).Select(a => (ECPointFormat)a).ToArray();
        }

    }
}
