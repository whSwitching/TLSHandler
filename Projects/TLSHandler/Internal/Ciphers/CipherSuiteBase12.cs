using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Internal.Ciphers
{
    abstract class CipherSuiteBase12 : CipherSuiteBase
    {
        #region CipherSuiteBase
        
        public override int GetMacLength()
        {
            using (var mac = GetHmacFunction())
            {
                return mac.HashSize / 8;
            }
        }

        public override byte[] GetVerifyData(string label, byte[] handshakeMessages)
        {
            if (MasterSecret == null)
                throw new InvalidOperationException("master-secret null");

            var handshakeHash = RandomFunction.PRF.Hash(handshakeMessages);

            return RandomFunction.PRF.GetBytes_HMACSHA256(MasterSecret, label, handshakeHash, this.VerifyDataLength);
        }

        public override byte[] ClientMessageAuthCode(byte[] message)
        {
            using (var mac = GetHmacFunction())
            {
                mac.Key = Client_Handshake_Key;
                return mac.ComputeHash(message);
            }
        }

        public override byte[] ServerMessageAuthCode(byte[] message)
        {
            using (var mac = GetHmacFunction())
            {
                mac.Key = Server_Handshake_Key;
                return mac.ComputeHash(message);
            }
        }

        #endregion

        protected byte[] Pad_Pkcs7(byte[] msgAndMac, int aesBlockSize = 128)
        {
            var wrap = new List<byte>();
            wrap.AddRange(msgAndMac);
            var paddingLen = (aesBlockSize - (wrap.Count * 8) % aesBlockSize) / 8 - 1;
            for (int i = 0; i < paddingLen; i++)
                wrap.Add((byte)paddingLen);
            wrap.Add((byte)paddingLen);
            return wrap.ToArray();
        }

        protected byte[] UnPad_Pkcs7(byte[] decryptedMsg)
        {
            var paddingLen = decryptedMsg.Last() + 1;
            return decryptedMsg.Take(decryptedMsg.Length - paddingLen).ToArray();
        }
    }
}
