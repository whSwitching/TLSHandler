using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Internal.Crypto
{
    //https://tools.ietf.org/html/rfc5869
    public class HKDF
    {
        public static byte[] Extract(HMAC hmac, byte[] salt, byte[] ikm)
        {
            //if salt not provided, salt is set to a string of HMAC.HashSize/8 zeros
            hmac.Key = salt ?? new byte[hmac.HashSize / 8];
            var prk = hmac.ComputeHash(ikm);
            return prk;
        }

        public static byte[] Expand(HMAC hmac, byte[] prk, byte[] info, int len)
        {
            if (info == null)
                info = new byte[0];

            var hashLength = hmac.HashSize / 8;
            hmac.Key = prk;

            var n = (int)Math.Ceiling(len * 1f / hashLength);
            var t = new byte[n * hashLength];

            using (var ms = new System.IO.MemoryStream())
            {
                var prev = new byte[0];

                for (var i = 1; i <= n; i++)
                {
                    ms.Write(prev, 0, prev.Length); // T(previous) | info | 1~N
                    if (info.Length > 0)
                        ms.Write(info, 0, info.Length);
                    ms.WriteByte((byte)(0x01 * i));

                    prev = hmac.ComputeHash(ms.ToArray());

                    Array.Copy(prev, 0, t, (i - 1) * hashLength, hashLength);

                    ms.SetLength(0); //reset
                }
            }

            var okm = new byte[len];
            Array.Copy(t, okm, okm.Length);

            return okm;
        }

        public static byte[] ExpandLabel(HMAC hmac, byte[] secret, string label, byte[] context, ushort len)
        {
            var hkdfLabel = HkdfLabel(label, context, len);

            return Expand(hmac, secret, hkdfLabel, len);
        }

        public static byte[] DeriveSecret(HMAC hmac, byte[] secret, string label, byte[] messages, HashAlgorithm transcriptHash)
        {
            var transcript = transcriptHash.ComputeHash(messages);
            return ExpandLabel(hmac, secret, label, transcript, (ushort)(hmac.HashSize / 8));
        }

        static byte[] HkdfLabel(string label, byte[] context, ushort len)
        {
            using (var ms = new System.IO.MemoryStream())
            {
                var lenBytes = Utils.UInt16Bytes(len);
                var labelBytes = Encoding.ASCII.GetBytes("tls13 " + label);

                ms.Write(lenBytes, 0, lenBytes.Length);
                ms.WriteByte((byte)labelBytes.Length);
                ms.Write(labelBytes, 0, labelBytes.Length);
                ms.WriteByte((byte)context.Length);
                ms.Write(context, 0, context.Length);

                return ms.ToArray();
            }
        }
    }
}
