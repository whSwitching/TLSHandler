using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler
{
    public class Utils
    {
        public static bool BytesEqual(byte[] a, byte[] b)
        {
            if (a == b)
                return true;
            if (a == null || b == null)
                return false;
            if (a.Length == b.Length)
            {
                for (int i = 0; i < a.Length; i++)
                {
                    if (a[i] != b[i])
                        return false;
                }
                return true;
            }
            return false;
        }

        public static byte[] HexDecode(string hexStr)
        {
            return Org.BouncyCastle.Utilities.Encoders.Hex.Decode(hexStr);
        }

        public static void EmptyBuffer(byte[] buff, byte b = 0x00)
        {
            if (buff != null)
            {
                for (int i = 0; i < buff.Length; i++)
                    buff[i] = b;
            }
        }

        public static byte[] UInt16Bytes(ushort u16)
        {
            return new[] { (byte)((u16 & 0xFF00) >> 8), (byte)(u16 & 0x00FF) };
        }

        public static ushort ToUInt16(byte[] buff, int idx = 0)
        {
            return (ushort)((buff[idx] << 8) + buff[idx + 1]);
        }
    }
}
