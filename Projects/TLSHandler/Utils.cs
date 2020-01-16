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

        public static byte[] UInt16Bytes(ushort u16, bool bigEndian = true)
        {
            if (bigEndian)
                return new[] { (byte)((u16 & 0xFF00) >> 8), (byte)(u16 & 0x00FF) };
            else
                return new[] { (byte)(u16 & 0x00FF), (byte)((u16 & 0xFF00) >> 8) };
        }
    }
}
