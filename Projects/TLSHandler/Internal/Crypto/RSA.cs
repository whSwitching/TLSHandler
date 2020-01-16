using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Internal.Crypto
{
    class RSA
    {
        readonly static bool foaep = false;

        public static byte[] Encrypt(byte[] data, RSAParameters publicParameters)
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

        public static byte[] Decrypt(byte[] encryptedData, RSAParameters privateParameters)
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

        public static byte[] SignData(byte[] data, RSAParameters privateParameters, Enums.SignatureAlgorithm algorithm)
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
    }
}
