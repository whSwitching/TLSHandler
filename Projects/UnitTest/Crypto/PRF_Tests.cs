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
    public class PRF_Tests
    {
        [TestMethod]
        public void Test_PRF()
        {
            var secret = TLSHandler.Utils.HexDecode("9bbe436ba940f017b17652849a71db35");
            var salt = TLSHandler.Utils.HexDecode("a0ba9f936cda311827a6f796ffd5198c");
            var label = Encoding.ASCII.GetString(TLSHandler.Utils.HexDecode("74657374206c6162656c"));
            var output_truth = TLSHandler.Utils.HexDecode("e3f229ba727be17b8d122620557cd453c2aab21d07c3d49532" +
                                        "9b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa0" +
                                        "22f7077def17abfd3797c0564bab4fbc91666e9def9b97fce3" +
                                        "4f796789baa48082d122ee42c5a72e5a5110fff70187347b66");

            var output = TLSHandler.Internal.Crypto.PRF.GetBytes_HMACSHA256(secret, label, salt, output_truth.Length);
            CollectionAssert.AreEqual(output, output_truth);
        }
    }
}

