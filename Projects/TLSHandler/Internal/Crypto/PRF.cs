using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Internal.Crypto
{
    //https://tools.ietf.org/html/rfc5246#section-5
    public class PRF
    {
        public static byte[] GetBytes_HMACSHA256(byte[] hmackey, string label, byte[] seed, int length)
        {
            var _seed = Encoding.ASCII.GetBytes(label).Concat(seed).ToArray();
            return P_hash(hmackey, _seed, length);
        }

        static byte[] P_hash(byte[] secret, byte[] seed, int length)
        {
            var ret = new byte[length];
            var fill = 0;

            var A1 = HMAC_SHA256(secret, seed);
            var preA = A1;

            while (fill < length)
            {
                var data = HMAC_SHA256(secret, preA.Concat(seed).ToArray());
                preA = HMAC_SHA256(secret, preA);

                var leftToFill = length - fill;
                if (leftToFill >= data.Length)
                {
                    Buffer.BlockCopy(data, 0, ret, fill, data.Length);
                    fill += data.Length;
                }
                else
                {
                    Buffer.BlockCopy(data, 0, ret, fill, leftToFill);
                    fill += leftToFill;
                }
            }
            return ret;
        }

        static byte[] HMAC_SHA256(byte[] secret, byte[] seed)
        {
            using (var sha256 = new HMACSHA256(secret))
            {
                return sha256.ComputeHash(seed);
            }
        }
    }
}
