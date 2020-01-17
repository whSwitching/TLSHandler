using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.TLS.Fragments
{
    //https://tools.ietf.org/html/rfc8446#section-4.4.3
    public class CertificateVerify : FragmentBody
    {
        public SignatureAlgorithm SignatureAlgorithm { get; private set; }
        public ushort SignatureLength { get; private set; }
        public byte[] Signature { get; private set; }

        public CertificateVerify(SignatureAlgorithm algorithm, byte[] signature) : base(null)
        {
            SignatureAlgorithm = algorithm;
            SignatureLength = (ushort)signature.Length;
            Signature = signature;

            var sabytes = Utils.UInt16Bytes((ushort)SignatureAlgorithm);
            var slbytes = Utils.UInt16Bytes(SignatureLength);

            Data = new byte[2 + 2 + Signature.Length];
            Buffer.BlockCopy(sabytes, 0, Data, 0, 2);
            Buffer.BlockCopy(slbytes, 0, Data, 2, 2);
            Buffer.BlockCopy(Signature, 0, Data, 4, Signature.Length);
        }
    }
}
