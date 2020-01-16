using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace UnitTest.Crypto
{
    [TestClass]
    public class HKDF_Tests
    {
        [TestMethod]
        public void Test_HKDF()
        {
            HKDF_Test1();
            HKDF_Test2();
            HKDF_Test3();
        }

        void HKDF_Test1()
        {
            var ikm = TLSHandler.Utils.HexDecode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            var salt = TLSHandler.Utils.HexDecode("000102030405060708090a0b0c");
            var info = TLSHandler.Utils.HexDecode("f0f1f2f3f4f5f6f7f8f9");
            var okm_truth = TLSHandler.Utils.HexDecode("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
            
            var hmac = new HMACSHA256();
            var prk = TLSHandler.Internal.Crypto.HKDF.Extract(hmac, salt, ikm);
            var okm = TLSHandler.Internal.Crypto.HKDF.Expand(hmac, prk, info, okm_truth.Length);
            CollectionAssert.AreEqual(okm, okm_truth);
        }

        void HKDF_Test2()
        {
            var ikm = TLSHandler.Utils.HexDecode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                        + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f");
            var salt = TLSHandler.Utils.HexDecode("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
                        + "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
            var info = TLSHandler.Utils.HexDecode("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                        + "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
            var okm_truth = TLSHandler.Utils.HexDecode("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
                        + "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87");

            var hmac = new HMACSHA256();
            var prk = TLSHandler.Internal.Crypto.HKDF.Extract(hmac, salt, ikm);
            var okm = TLSHandler.Internal.Crypto.HKDF.Expand(hmac, prk, info, okm_truth.Length);
            CollectionAssert.AreEqual(okm, okm_truth);
        }

        void HKDF_Test3()
        {
            var ikm = TLSHandler.Utils.HexDecode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            var salt = new byte[0];
            byte[] info = null;
            var okm_truth = TLSHandler.Utils.HexDecode("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");

            var hmac = new HMACSHA256();
            var prk = TLSHandler.Internal.Crypto.HKDF.Extract(hmac, salt, ikm);
            var okm = TLSHandler.Internal.Crypto.HKDF.Expand(hmac, prk, info, okm_truth.Length);
            CollectionAssert.AreEqual(okm, okm_truth);
        }
    }
}
