using System;
using System.Collections;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace UnitTest.Crypto
{
    [TestClass]
    public class BulkEncryption_Test
    {
        [TestMethod]
        public void Test_Aes128CBC()
        {
            var testVectors = new string[][]
            {
                new string[]
                {
                    "2b7e151628aed2a6abf7158809cf4f3c", //key
                    "000102030405060708090A0B0C0D0E0F", //iv
                    "6bc1bee22e409f96e93d7e117393172a", //plain
                    "7649abac8119b246cee98e9b12e9197d", //cipher
                },
                new string[]
                {
                    "2b7e151628aed2a6abf7158809cf4f3c",
                    "7649ABAC8119B246CEE98E9B12E9197D",
                    "ae2d8a571e03ac9c9eb76fac45af8e51",
                    "5086cb9b507219ee95db113a917678b2",
                },
                new string[]
                {
                    "2b7e151628aed2a6abf7158809cf4f3c",
                    "5086CB9B507219EE95DB113A917678B2",
                    "30c81c46a35ce411e5fbc1191a0a52ef",
                    "73bed6b8e3c1743b7116e69e22229516",
                },
                new string[]
                {
                    "2b7e151628aed2a6abf7158809cf4f3c",
                    "73BED6B8E3C1743B7116E69E22229516",
                    "f69f2445df4f9b17ad2b417be66c3710",
                    "3ff1caa1681fac09120eca307586e1a7",
                },
            };

            using(var aes = new TLSHandler.Internal.Crypto.Aes128_CBC())
            {
                foreach (var v in testVectors)
                {
                    var key = TLSHandler.Utils.HexDecode(v[0]);
                    var iv = TLSHandler.Utils.HexDecode(v[1]);
                    var plain_truth = TLSHandler.Utils.HexDecode(v[2]);
                    var cipher_truth = TLSHandler.Utils.HexDecode(v[3]);

                    var cipher = aes.Encrypt(plain_truth, key, iv);
                    var plain = aes.Decrypt(cipher_truth, key, iv);
                    CollectionAssert.AreEqual(cipher, cipher_truth);
                    CollectionAssert.AreEqual(plain, plain_truth);
                }
            }
            
        }

        [TestMethod]
        public void Test_Aes256CBC()
        {
            var testVectors = new string[][]
            {
                new string[]
                {
                    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",    //key
                    "000102030405060708090A0B0C0D0E0F",    //iv
                    "6bc1bee22e409f96e93d7e117393172a",    //plain
                    "f58c4c04d6e5f1ba779eabfb5f7bfbd6",    //cipher
                },
                new string[]
                {
                    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                    "F58C4C04D6E5F1BA779EABFB5F7BFBD6",
                    "ae2d8a571e03ac9c9eb76fac45af8e51",
                    "9cfc4e967edb808d679f777bc6702c7d",
                },
                new string[]
                {
                    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                    "9CFC4E967EDB808D679F777BC6702C7D",
                    "30c81c46a35ce411e5fbc1191a0a52ef",
                    "39f23369a9d9bacfa530e26304231461",
                },
               new string[]
                {
                    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                    "39F23369A9D9BACFA530E26304231461",
                    "f69f2445df4f9b17ad2b417be66c3710",
                    "b2eb05e2c39be9fcda6c19078c6a9d1b",
                },
            };

            using(var aes = new TLSHandler.Internal.Crypto.Aes256_CBC())
            {
                foreach (var v in testVectors)
                {
                    var key = TLSHandler.Utils.HexDecode(v[0]);
                    var iv = TLSHandler.Utils.HexDecode(v[1]);
                    var plain_truth = TLSHandler.Utils.HexDecode(v[2]);
                    var cipher_truth = TLSHandler.Utils.HexDecode(v[3]);

                    var cipher = aes.Encrypt(plain_truth, key, iv);
                    var plain = aes.Decrypt(cipher_truth, key, iv);
                    CollectionAssert.AreEqual(cipher, cipher_truth);
                    CollectionAssert.AreEqual(plain, plain_truth);
                }
            }
            
        }

        [TestMethod]
        public void Test_Aes128GCM()
        {
            var testVectors = new string[][]
            {
                new string[]
                {
                    "00000000000000000000000000000000",
                    "",
                    "",
                    "000000000000000000000000",
                    "",
                    "58e2fccefa7e3061367f1d57a4e7455a",
                },
                new string[]
                {
                    "00000000000000000000000000000000",
                    "00000000000000000000000000000000",
                    "",
                    "000000000000000000000000",
                    "0388dace60b6a392f328c2b971b2fe78",
                    "ab6e47d42cec13bdf53a67b21257bddf",
                },
                new string[]
                {
                    "feffe9928665731c6d6a8f9467308308",
                    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
                    "",
                    "cafebabefacedbaddecaf888",
                    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
                    "4d5c2af327cd64a62cf35abd2ba6fab4",
                },
                new string[]
                {
                    "feffe9928665731c6d6a8f9467308308",
                    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
                    "feedfacedeadbeeffeedfacedeadbeefabaddad2",
                    "cafebabefacedbaddecaf888",
                    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
                    "5bc94fbc3221a5db94fae95ae7121a47",
                },
                new string[]
                {
                    "feffe9928665731c6d6a8f9467308308",
                    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
                    "feedfacedeadbeeffeedfacedeadbeefabaddad2",
                    "cafebabefacedbad",
                    "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
                    "3612d2e79e3b0785561be14aaca2fccb",
                },
                new string[]
                {
                    "feffe9928665731c6d6a8f9467308308",
                    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
                    "feedfacedeadbeeffeedfacedeadbeefabaddad2",
                    "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
                    "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5",
                    "619cc5aefffe0bfa462af43c1699d050",
                },
            };

            using(var aes = new TLSHandler.Internal.Crypto.Aes128_GCM())
            {
                foreach (var v in testVectors)
                {
                    var key = TLSHandler.Utils.HexDecode(v[0]);
                    var plain_truth = TLSHandler.Utils.HexDecode(v[1]);
                    var aad = TLSHandler.Utils.HexDecode(v[2]);
                    var iv = TLSHandler.Utils.HexDecode(v[3]);
                    var cipher = TLSHandler.Utils.HexDecode(v[4]);
                    var tag = TLSHandler.Utils.HexDecode(v[5]);
                    var cipher_truth = cipher.Concat(tag).ToArray();

                    var cipher_result = aes.Encrypt(plain_truth, key, iv, aad);
                    CollectionAssert.AreEqual(cipher_result, cipher_truth);
                    var plain = aes.Decrypt(cipher_truth, key, iv, aad);
                    CollectionAssert.AreEqual(plain, plain_truth);
                }
            }
            
        }

        [TestMethod]
        public void Test_Aes256GCM()
        {
            var testVectors = new string[][]
            {
                new string[]
                {
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    "",
                    "",
                    "000000000000000000000000",
                    "",
                    "530f8afbc74536b9a963b4f1c4cb738b",
                },
                new string[]
                {
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    "00000000000000000000000000000000",
                    "",
                    "000000000000000000000000",
                    "cea7403d4d606b6e074ec5d3baf39d18",
                    "d0d1c8a799996bf0265b98b5d48ab919",
                },
                new string[]
                {
                    "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
                    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
                    "",
                    "cafebabefacedbaddecaf888",
                    "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
                    "b094dac5d93471bdec1a502270e3cc6c",
                },
                new string[]
                {
                    "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
                    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
                    "feedfacedeadbeeffeedfacedeadbeefabaddad2",
                    "cafebabefacedbaddecaf888",
                    "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
                    "76fc6ece0f4e1768cddf8853bb2d551b",
                },
                new string[]
                {
                    "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
                    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
                    "feedfacedeadbeeffeedfacedeadbeefabaddad2",
                    "cafebabefacedbad",
                    "c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f",
                    "3a337dbf46a792c45e454913fe2ea8f2",
                },
                new string[]
                {
                    "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
                    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
                    "feedfacedeadbeeffeedfacedeadbeefabaddad2",
                    "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
                    "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f",
                    "a44a8266ee1c8eb0c8b5d4cf5ae9f19a",
                },
            };

            using(var aes = new TLSHandler.Internal.Crypto.Aes256_GCM())
            {
                foreach (var v in testVectors)
                {
                    var key = TLSHandler.Utils.HexDecode(v[0]);
                    var plain_truth = TLSHandler.Utils.HexDecode(v[1]);
                    var aad = TLSHandler.Utils.HexDecode(v[2]);
                    var iv = TLSHandler.Utils.HexDecode(v[3]);
                    var cipher = TLSHandler.Utils.HexDecode(v[4]);
                    var tag = TLSHandler.Utils.HexDecode(v[5]);
                    var cipher_truth = cipher.Concat(tag).ToArray();

                    var cipher_result = aes.Encrypt(plain_truth, key, iv, aad);
                    CollectionAssert.AreEqual(cipher_result, cipher_truth);
                    var plain = aes.Decrypt(cipher_truth, key, iv, aad);
                    CollectionAssert.AreEqual(plain, plain_truth);
                }
            }
            
        }

        [TestMethod]
        public void Test_ChaCha20_Poly1305()
        {
            ChaCha20_Poly1305_Case1();
            ChaCha20_Poly1305_Case2();
        }

        public void ChaCha20_Poly1305_Case1()
        {
            var key = new byte[]
            {
                0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
                0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0
            };
            var iv = new byte[]
            {
                0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
            };
            var aad = new byte[]
            {
                0xf3, 0x33, 0x88, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4e, 0x91
            };
            var cipher_truth = new byte[]
            {
                0x64, 0xa0, 0x86, 0x15, 0x75, 0x86, 0x1a, 0xf4, 0x60, 0xf0, 0x62, 0xc7, 0x9b, 0xe6, 0x43, 0xbd,
                0x5e, 0x80, 0x5c, 0xfd, 0x34, 0x5c, 0xf3, 0x89, 0xf1, 0x08, 0x67, 0x0a, 0xc7, 0x6c, 0x8c, 0xb2,
                0x4c, 0x6c, 0xfc, 0x18, 0x75, 0x5d, 0x43, 0xee, 0xa0, 0x9e, 0xe9, 0x4e, 0x38, 0x2d, 0x26, 0xb0,
                0xbd, 0xb7, 0xb7, 0x3c, 0x32, 0x1b, 0x01, 0x00, 0xd4, 0xf0, 0x3b, 0x7f, 0x35, 0x58, 0x94, 0xcf,
                0x33, 0x2f, 0x83, 0x0e, 0x71, 0x0b, 0x97, 0xce, 0x98, 0xc8, 0xa8, 0x4a, 0xbd, 0x0b, 0x94, 0x81,
                0x14, 0xad, 0x17, 0x6e, 0x00, 0x8d, 0x33, 0xbd, 0x60, 0xf9, 0x82, 0xb1, 0xff, 0x37, 0xc8, 0x55,
                0x97, 0x97, 0xa0, 0x6e, 0xf4, 0xf0, 0xef, 0x61, 0xc1, 0x86, 0x32, 0x4e, 0x2b, 0x35, 0x06, 0x38,
                0x36, 0x06, 0x90, 0x7b, 0x6a, 0x7c, 0x02, 0xb0, 0xf9, 0xf6, 0x15, 0x7b, 0x53, 0xc8, 0x67, 0xe4,
                0xb9, 0x16, 0x6c, 0x76, 0x7b, 0x80, 0x4d, 0x46, 0xa5, 0x9b, 0x52, 0x16, 0xcd, 0xe7, 0xa4, 0xe9,
                0x90, 0x40, 0xc5, 0xa4, 0x04, 0x33, 0x22, 0x5e, 0xe2, 0x82, 0xa1, 0xb0, 0xa0, 0x6c, 0x52, 0x3e,
                0xaf, 0x45, 0x34, 0xd7, 0xf8, 0x3f, 0xa1, 0x15, 0x5b, 0x00, 0x47, 0x71, 0x8c, 0xbc, 0x54, 0x6a,
                0x0d, 0x07, 0x2b, 0x04, 0xb3, 0x56, 0x4e, 0xea, 0x1b, 0x42, 0x22, 0x73, 0xf5, 0x48, 0x27, 0x1a,
                0x0b, 0xb2, 0x31, 0x60, 0x53, 0xfa, 0x76, 0x99, 0x19, 0x55, 0xeb, 0xd6, 0x31, 0x59, 0x43, 0x4e,
                0xce, 0xbb, 0x4e, 0x46, 0x6d, 0xae, 0x5a, 0x10, 0x73, 0xa6, 0x72, 0x76, 0x27, 0x09, 0x7a, 0x10,
                0x49, 0xe6, 0x17, 0xd9, 0x1d, 0x36, 0x10, 0x94, 0xfa, 0x68, 0xf0, 0xff, 0x77, 0x98, 0x71, 0x30,
                0x30, 0x5b, 0xea, 0xba, 0x2e, 0xda, 0x04, 0xdf, 0x99, 0x7b, 0x71, 0x4d, 0x6c, 0x6f, 0x2c, 0x29,
                0xa6, 0xad, 0x5c, 0xb4, 0x02, 0x2b, 0x02, 0x70, 0x9b
            };
            var tag_truth = new byte[]
            {
                0xee, 0xad, 0x9d, 0x67, 0x89, 0x0c, 0xbb, 0x22, 0x39, 0x23, 0x36, 0xfe, 0xa1, 0x85, 0x1f, 0x38
            };
            var plain_truth = new byte[]
            {
                0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2d, 0x44, 0x72, 0x61, 0x66, 0x74, 0x73, 0x20,
                0x61, 0x72, 0x65, 0x20, 0x64, 0x72, 0x61, 0x66, 0x74, 0x20, 0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65,
                0x6e, 0x74, 0x73, 0x20, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x61, 0x20,
                0x6d, 0x61, 0x78, 0x69, 0x6d, 0x75, 0x6d, 0x20, 0x6f, 0x66, 0x20, 0x73, 0x69, 0x78, 0x20, 0x6d,
                0x6f, 0x6e, 0x74, 0x68, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x6d, 0x61, 0x79, 0x20, 0x62, 0x65,
                0x20, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x2c, 0x20, 0x72, 0x65, 0x70, 0x6c, 0x61, 0x63,
                0x65, 0x64, 0x2c, 0x20, 0x6f, 0x72, 0x20, 0x6f, 0x62, 0x73, 0x6f, 0x6c, 0x65, 0x74, 0x65, 0x64,
                0x20, 0x62, 0x79, 0x20, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x20, 0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65,
                0x6e, 0x74, 0x73, 0x20, 0x61, 0x74, 0x20, 0x61, 0x6e, 0x79, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x2e,
                0x20, 0x49, 0x74, 0x20, 0x69, 0x73, 0x20, 0x69, 0x6e, 0x61, 0x70, 0x70, 0x72, 0x6f, 0x70, 0x72,
                0x69, 0x61, 0x74, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x75, 0x73, 0x65, 0x20, 0x49, 0x6e, 0x74, 0x65,
                0x72, 0x6e, 0x65, 0x74, 0x2d, 0x44, 0x72, 0x61, 0x66, 0x74, 0x73, 0x20, 0x61, 0x73, 0x20, 0x72,
                0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x20, 0x6d, 0x61, 0x74, 0x65, 0x72, 0x69, 0x61,
                0x6c, 0x20, 0x6f, 0x72, 0x20, 0x74, 0x6f, 0x20, 0x63, 0x69, 0x74, 0x65, 0x20, 0x74, 0x68, 0x65,
                0x6d, 0x20, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x20, 0x74, 0x68, 0x61, 0x6e, 0x20, 0x61, 0x73, 0x20,
                0x2f, 0xe2, 0x80, 0x9c, 0x77, 0x6f, 0x72, 0x6b, 0x20, 0x69, 0x6e, 0x20, 0x70, 0x72, 0x6f, 0x67,
                0x72, 0x65, 0x73, 0x73, 0x2e, 0x2f, 0xe2, 0x80, 0x9d
            };
            var cipherBlock_Truth = cipher_truth.Concat(tag_truth).ToArray();

            using(var chacha = new TLSHandler.Internal.Crypto.ChaCha20_Poly1305())
            {
                var cipher = chacha.Encrypt(plain_truth, key, iv, aad);
                CollectionAssert.AreEqual(cipher, cipherBlock_Truth);
                var plain = chacha.Decrypt(cipherBlock_Truth, key, iv, aad);
                CollectionAssert.AreEqual(plain, plain_truth);
            }
            
        }

        public void ChaCha20_Poly1305_Case2()
        {
            var plain_truth = new byte[]
            {
                0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
                0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
                0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
                0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
                0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
                0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
                0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
                0x74, 0x2e
            };
            var key = new byte[]
            {
                0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
            };
            var iv = new byte[]
            {
                0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
            };
            var aad = new byte[]
            {
                0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7
            };
            var cipher_truth = new byte[]
            {
                0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
                0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
                0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
                0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
                0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
                0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
                0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
                0x61, 0x16
            };
            var tag_truth = new byte[]
            {
                0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
            };

            var cipherBlock_Truth = cipher_truth.Concat(tag_truth).ToArray();

            using (var chacha = new TLSHandler.Internal.Crypto.ChaCha20_Poly1305())
            {
                var plain = chacha.Decrypt(cipherBlock_Truth, key, iv, aad);
                CollectionAssert.AreEqual(plain, plain_truth);
                var cipher = chacha.Encrypt(plain_truth, key, iv, aad);
                CollectionAssert.AreEqual(cipher, cipherBlock_Truth);
            }
        }
    }


}
