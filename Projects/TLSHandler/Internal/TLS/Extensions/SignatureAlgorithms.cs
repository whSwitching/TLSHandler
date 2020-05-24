using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.TLS.Extensions
{
    //https://tools.ietf.org/html/rfc8446#section-4.2.3
    class SignatureAlgorithms : Extension
    {
        public override ExtensionType Type { get { return ExtensionType.SIGNATURE_ALGORITHMS; } }
        public ushort EntriesLength { get { return Utils.ToUInt16(Data, 4); } }
        public SignatureAlgorithm[] HashSignatureAlgorithms { get; private set; }

        public SignatureAlgorithms(byte[] extensionBytes) : base(extensionBytes)
        {
            HashSignatureAlgorithms = new SignatureAlgorithm[EntriesLength / 2];

            for (int i = 0; i < HashSignatureAlgorithms.Length; i++)
            {
                HashSignatureAlgorithms[i] = (SignatureAlgorithm)Utils.ToUInt16(Data, 6 + i * 2);
            }
        }

        public SignatureAlgorithms(SignatureAlgorithm[] sAlgorithms) : base(null)
        {
            HashSignatureAlgorithms = sAlgorithms;

            using (var ms = new System.IO.MemoryStream())
            {
                // Extension Type
                ms.WriteValue((ushort)Type);
                // Extension Length
                ms.WriteValue((ushort)(sAlgorithms.Length * 2 + 2));
                // EntriesLength
                ms.WriteValue((ushort)(sAlgorithms.Length * 2));
                // HashSignatureAlgorithms
                foreach (var sa in HashSignatureAlgorithms)
                    ms.WriteValue((ushort)(sa));

                Data = ms.ToArray();
            }
        }
    }
}
