using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Internal.TLS.ValueTypes
{
    class Random : PacketData
    {
        public Random()
        {
            Data = new byte[32];
            var secs = (DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
            var time = Utils.UInt32Bytes((uint)secs);
            var random = Utils.Random(28);
            Buffer.BlockCopy(time, 0, Data, 0, 4);
            Buffer.BlockCopy(random, 0, Data, 4, 28);
        }

        public Random(byte[] random)
        {
            if (random != null && random.Length == 32)
                Data = random;
            else
                throw new ArgumentOutOfRangeException("random should be exactly 32 bytes");
        }

        public void UpdateLastBytesForTLS12Session()
        {
            // downgrade attacks: tls13 server update last 8 bytes of random when use tls12
            //https://tools.ietf.org/html/rfc8446#page-32

            var check = new byte[] { 0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01 };

            Buffer.BlockCopy(check, 0, Data, Data.Length - check.Length, check.Length);
        }
    }
}
