using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler
{
    static class Utils
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

        public static string BytesString(byte[] data)
        {
            var sb = new StringBuilder();
            var offset = 0;
            while (offset < data.Length)
            {
                sb.AppendLine(" " + string.Join(" ", data.Skip(offset).Take(16).Select(a => a.ToString("X2"))));
                offset += 16;
            }
            return sb.ToString();
        }
        
        public static byte[] CopyBuffer(byte[] from)
        {
            var to = new byte[from.Length];
            Buffer.BlockCopy(from, 0, to, 0, from.Length);
            return to;
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

        public static byte[] GetMacSeed(ulong sec_num, byte recordType, byte[] data)
        {
            var macSeed = new List<byte>();

            macSeed.AddRange(Utils.UInt64Bytes(sec_num));               // seq_num
            macSeed.Add(recordType);                                    // type
            macSeed.AddRange(new byte[] { 0x03, 0x03 });                // version
            macSeed.AddRange(Utils.UInt16Bytes((ushort)data.Length));   // length
            macSeed.AddRange(data);                                     // body

            return macSeed.ToArray();
        }

        public static byte[] GetPayloadData(IEnumerable<PacketData> fragments)
        {
            var payload = new List<byte>();
            foreach (var f in fragments)
                payload.AddRange(f.Data);
            return payload.ToArray();
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

        #region RSA
        readonly static bool foaep = false;

        public static byte[] RSA_Encrypt(byte[] data, RSAParameters publicParameters)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(publicParameters);
                int MaxBlockSize = rsa.KeySize / 8 - 11;

                if (data.Length <= MaxBlockSize)
                    return rsa.Encrypt(data, foaep);

                using (var dataStream = new System.IO.MemoryStream(data))
                using (var encryptedStream = new System.IO.MemoryStream())
                {
                    var buffer = new byte[MaxBlockSize];
                    int blockSize = dataStream.Read(buffer, 0, MaxBlockSize);

                    while (blockSize > 0)
                    {
                        var toencrypt = new byte[blockSize];
                        Array.Copy(buffer, 0, toencrypt, 0, blockSize);

                        var encryptedBuffer = rsa.Encrypt(toencrypt, foaep);
                        encryptedStream.Write(encryptedBuffer, 0, encryptedBuffer.Length);

                        blockSize = dataStream.Read(buffer, 0, MaxBlockSize);
                    }

                    return encryptedStream.ToArray();
                }
            }
        }

        public static byte[] RSA_Decrypt(byte[] encryptedData, RSAParameters privateParameters)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(privateParameters);
                int MaxBlockSize = rsa.KeySize / 8;

                if (encryptedData.Length <= MaxBlockSize)
                    return rsa.Decrypt(encryptedData, foaep);

                using (var encryptedStream = new System.IO.MemoryStream(encryptedData))
                using (var dataStream = new System.IO.MemoryStream())
                {
                    var buffer = new byte[MaxBlockSize];
                    int blockSize = encryptedStream.Read(buffer, 0, MaxBlockSize);

                    while (blockSize > 0)
                    {
                        var todecrypt = new byte[blockSize];
                        Array.Copy(buffer, 0, todecrypt, 0, blockSize);

                        var data = rsa.Decrypt(todecrypt, foaep);
                        dataStream.Write(data, 0, data.Length);

                        blockSize = encryptedStream.Read(buffer, 0, MaxBlockSize);
                    }

                    return dataStream.ToArray();
                }
            }
        }

        public static byte[] RSA_SignData(byte[] data, RSAParameters privateParameters, Enums.SignatureAlgorithm algorithm)
        {
            using (var rsa = new RSACng())
            {
                rsa.ImportParameters(privateParameters);

                if (algorithm == Enums.SignatureAlgorithm.rsa_pkcs1_sha512)
                    return rsa.SignData(data, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                else if (algorithm == Enums.SignatureAlgorithm.rsa_pkcs1_sha384)
                    return rsa.SignData(data, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);
                else if (algorithm == Enums.SignatureAlgorithm.rsa_pkcs1_sha256)
                    return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                else if (algorithm == Enums.SignatureAlgorithm.rsa_pss_rsae_sha512)
                    return rsa.SignData(data, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);
                else if (algorithm == Enums.SignatureAlgorithm.rsa_pss_rsae_sha384)
                    return rsa.SignData(data, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
                else if (algorithm == Enums.SignatureAlgorithm.rsa_pss_rsae_sha256)
                    return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
                else
                    throw new NotImplementedException($"SignatureAlgorithm {algorithm} NotImplemented");
            }
        }
        #endregion
    }
}
