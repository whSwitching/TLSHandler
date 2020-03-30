using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.TLS.Fragments
{
    // only for ECDH
    //https://tools.ietf.org/html/rfc4492#section-5.4
    class ServerKeyExchange : FragmentBody
    {
        public ECCurveType CurveType { get; private set; }
        public NamedGroup NamedCurve { get; private set; }
        public byte PubkeyLength { get; private set; }
        public byte[] Pubkey { get; private set; }
        public SignatureAlgorithm SignatureAlgorithm { get; private set; }
        public ushort SignatureLength { get; private set; }
        public byte[] Signature { get; private set; }

        //https://tools.ietf.org/html/rfc5246#section-7.4.3

        public ServerKeyExchange(NamedGroup namedCurve, byte[] pubkeyWith04, SignatureAlgorithm signatureAlgorithm, byte[] signature) : base(null)
        {
            CurveType = ECCurveType.named_curve;
            NamedCurve = namedCurve;
            PubkeyLength = (byte)(pubkeyWith04.Length);
            Pubkey = pubkeyWith04;
            SignatureAlgorithm = signatureAlgorithm;
            SignatureLength = (ushort)signature.Length;
            Signature = signature;

            using (var ms = new System.IO.MemoryStream())
            {
                ms.WriteByte((byte)CurveType);
                ms.WriteValue((ushort)NamedCurve);
                ms.WriteValue(Pubkey, new[] { PubkeyLength });// Pubkey[0] == 0x04 uncompress pubkey
                ms.WriteValue((ushort)signatureAlgorithm);
                ms.WriteValue(Signature, Utils.UInt16Bytes(SignatureLength));

                Data = ms.ToArray();
            }
        }

        public static byte[] ServerECDHParams(NamedGroup namedCurve, byte[] pubkeyWith04)
        {
            using (var ms = new System.IO.MemoryStream())
            {
                ms.WriteByte((byte)ECCurveType.named_curve);
                ms.WriteValue((ushort)namedCurve);
                ms.WriteValue(pubkeyWith04, new[] { (byte)(pubkeyWith04.Length) });// Pubkey[0] == 0x04 uncompress pubkey
                return ms.ToArray();
            }
        }
    }
}
