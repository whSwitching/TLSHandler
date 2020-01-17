using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.TLS.Extensions
{
    //Supported Elliptic Curves
    //https://tools.ietf.org/html/rfc8446#section-4.2.7
    class SupportedGroups : Extension
    {
        public override ExtensionType Type { get { return ExtensionType.SUPPORTED_GROUPS; } }

        public ushort EntriesLength { get { return Utils.ToUInt16(Data, 4); } }
        public NamedGroup[] EllipticCurvesGroups { get; private set; }

        public SupportedGroups(byte[] extensionBytes) : base(extensionBytes)
        {
            EllipticCurvesGroups = new NamedGroup[EntriesLength / 2];

            for (int i = 0; i < EllipticCurvesGroups.Length; i++)
            {
                EllipticCurvesGroups[i] = (NamedGroup)Utils.ToUInt16(Data, 6 + i * 2);
            }
        }
    }
}
