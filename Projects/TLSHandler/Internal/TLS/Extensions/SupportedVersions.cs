using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.TLS.Extensions
{
    //https://tools.ietf.org/html/rfc8446#section-4.2.1
    class SupportedVersions : Extension
    {
        public override ExtensionType Type { get { return ExtensionType.SUPPORTED_VERSIONS; } }

        public byte EntriesLength { get { return Data[4]; } }
        public ProtocolVersion[] Versions { get; private set; }

        public SupportedVersions(byte[] extensionBytes) : base(extensionBytes)
        {
            Versions = new ProtocolVersion[EntriesLength / 2];

            for (int i = 0; i < Versions.Length; i++)
            {
                Versions[i] = (ProtocolVersion)Utils.ToUInt16(Data, 5 + i * 2);
            }
        }

        public SupportedVersions(ProtocolVersion server_selected_version) : base(null)
        {
            Versions = new[] { server_selected_version };

            var type = Utils.UInt16Bytes((ushort)Type);
            var len = new byte[] { 0x00, 0x02 };
            var v = Utils.UInt16Bytes((ushort)server_selected_version);

            Data = new byte[6];
            Buffer.BlockCopy(type, 0, Data, 0, 2);
            Buffer.BlockCopy(len, 0, Data, 2, 2);
            Buffer.BlockCopy(v, 0, Data, 4, 2);
        }

    }
}
