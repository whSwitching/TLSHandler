using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Internal.TLS.Fragments
{
    //https://tools.ietf.org/html/rfc5246#section-7.4.2
    //https://tools.ietf.org/html/rfc8446#section-4.4.2
    public class Certificate : FragmentBody
    {
        internal System.Security.Cryptography.X509Certificates.X509Certificate2[] Certs { get; private set; }

        public Certificate(System.Security.Cryptography.X509Certificates.X509Certificate2[] publicCerts, bool tls13) : base(null)
        {
            Certs = publicCerts;
            var certs = new List<byte>();
            foreach (var cert in publicCerts)
            {
                var raw = cert.RawData;
                var len = Utils.UInt24Bytes((uint)raw.Length);
                certs.AddRange(len);
                certs.AddRange(raw);
            }

            var totalLen = (uint)certs.Count;
            if (tls13)
                totalLen += 2;              // 2 bytes Certificate Extensions length

            var totalLenBytes = Utils.UInt24Bytes(totalLen);

            using (var ms = new System.IO.MemoryStream())
            {
                if (tls13)
                    ms.WriteByte(0x00);     // request_context
                ms.Write(totalLenBytes, 0, totalLenBytes.Length);
                ms.Write(certs.ToArray(), 0, certs.Count);
                if (tls13)
                    ms.Write(new byte[] { 0x00, 0x00 }, 0, 2); // Certificate Extensions

                Data = ms.ToArray();
            }
        }

    }
}
