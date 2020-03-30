using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Internal.Ciphers
{
    abstract class CipherSuiteBase
    {
        public abstract bool IsRsaKeyExchange { get; }
        public abstract Enums.CipherSuite CipherSuite { get; }
        public virtual int VerifyDataLength { get { return 12; } }

        protected virtual byte[] MasterSecret { get; set; }
        protected virtual byte[] Client_Handshake_Key { get; set; }
        protected virtual byte[] Server_Handshake_Key { get; set; }
        protected virtual byte[] Client_Application_Key { get; set; }
        protected virtual byte[] Server_Application_Key { get; set; }

        protected abstract HMAC GetHmacFunction();

        public abstract int GetMacLength();

        public abstract void KeyExchange(byte[] encryptedPreMasterSecret, byte[] clientRandom, byte[] serverRandom, object privateParameters);

        public abstract byte[] GetVerifyData(string label, byte[] handshakeMessages);

        public abstract byte[] BulkEncrypt(byte[] msg_WithoutPadding, byte[] iv);

        public abstract byte[] BulkDecrypt(byte[] secret, byte[] iv);

        public abstract byte[] ClientMessageAuthCode(byte[] message);

        public abstract byte[] ServerMessageAuthCode(byte[] message);

        public virtual byte[] Signature(byte[] data, Enums.SignatureAlgorithm algorithm, object privateParameters)
        {
            var parameters = (RSAParameters)privateParameters;
            return Utils.RSA_SignData(data, parameters, algorithm);
        }
    }
}
