using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler
{
    public static class Utils
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

        public static byte[] Random(int len)
        {
            var rd = new Random(DateTime.Now.Millisecond);
            var ret = new byte[len];
            rd.NextBytes(ret);
            return ret;
        }

        #region uint <=> bytes

        public static byte[] UInt16Bytes(ushort u16)
        {
            return new[] { (byte)((u16 & 0xFF00) >> 8), (byte)(u16 & 0x00FF) };
        }

        public static byte[] UInt24Bytes(uint u24)
        {
            return new[] { (byte)((u24 & 0xFF0000) >> 16), (byte)((u24 & 0xFF00) >> 8), (byte)(u24 & 0xFF) };
        }

        public static byte[] UInt32Bytes(uint u32)
        {
            return new[] { (byte)((u32 & 0xFF000000) >> 24), (byte)((u32 & 0xFF0000) >> 16), (byte)((u32 & 0xFF00) >> 8), (byte)(u32 & 0xFF) };
        }

        public static byte[] UInt64Bytes(ulong u64)
        {
            return new[]
            {
                (byte)((u64 & 0xFF00000000000000) >> 56), (byte)((u64 & 0xFF000000000000) >> 48), (byte)((u64 & 0xFF0000000000) >> 40), (byte)((u64 & 0xFF00000000) >> 32),
                (byte)((u64 & 0xFF000000) >> 24), (byte)((u64 & 0xFF0000) >> 16), (byte)((u64 & 0xFF00) >> 8), (byte)(u64 & 0xFF)
            };
        }

        public static ushort ToUInt16(byte[] buff, int idx = 0)
        {
            return (ushort)((buff[idx] << 8) + buff[idx + 1]);
        }

        public static uint ToUInt24(byte[] buff, int idx = 0)
        {
            return (uint)((buff[idx] << 16) + (buff[idx + 1] << 8) + buff[idx + 2]);
        }

        public static uint ToUInt32(byte[] buff, int idx = 0)
        {
            return (uint)((buff[idx] << 24) + (buff[idx + 1] << 16) + (buff[idx + 2] << 8) + buff[idx + 3]);
        }
        #endregion

        #region stream ext
        public static void WriteValue(this System.IO.Stream stream, uint val)
        {
            var data = UInt32Bytes(val);
            stream.Write(data, 0, data.Length);
        }
        public static void WriteValue(this System.IO.Stream stream, ushort val)
        {
            var data = UInt16Bytes(val);
            stream.Write(data, 0, data.Length);
        }
        public static void WriteValue(this System.IO.Stream stream, byte[] opaque, byte[] opaqueSizeBytes)
        {
            stream.Write(opaqueSizeBytes, 0, opaqueSizeBytes.Length);
            stream.Write(opaque, 0, opaque.Length);
        }
        #endregion
    }
}
