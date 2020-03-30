using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Internal.Ciphers
{
    abstract class CipherSuiteBase13 : CipherSuiteBase
    {
        protected byte[] ECDHE_Shared_secret { get; set; }
        protected byte[] Handshake_secret { get; set; }
        protected byte[] Exporter_Master_Secret { get; set; }
        protected byte[] Resumption_Master_Secret { get; set; }
        protected byte[] Client_application_secret { get; set; }
        protected byte[] Server_application_secret { get; set; }
        protected byte[] Client_handshake_secret { get; set; }
        protected byte[] Server_handshake_secret { get; set; }
        protected ulong Client_Handshake_Iv_Seq { get; set; } = 0;
        protected ulong Server_Handshake_Iv_Seq { get; set; } = 0;
        protected ulong Client_Application_Iv_Seq { get; set; } = 0;
        protected ulong Server_Application_Iv_Seq { get; set; } = 0;
        protected byte[] Client_Handshake_Iv { get; set; }
        protected byte[] Server_Handshake_Iv { get; set; }
        protected byte[] Client_Application_Iv { get; set; }
        protected byte[] Server_Application_Iv { get; set; }


        #region CipherSuiteBase
        public override bool IsRsaKeyExchange { get { return false; } }

        public override void KeyExchange(byte[] clientEcdhPubkey, byte[] cRandomNotused, byte[] sRandomNotused, object privateParameters)
        {
            using (var keyex = new KeyExchange.KeyExchange13())
            {
                keyex.Exchange(clientEcdhPubkey, null, null, privateParameters);
                this.ECDHE_Shared_secret = Utils.CopyBuffer(keyex.SharedSecret);
            }
        }

        public override byte[] GetVerifyData(string label, byte[] clienthello_certverify) // label = "finished"
        {
            var hash = GetHashAlgorithm();
            var hmac = GetHmacFunction();
            var empty_STRING = new byte[0];

            var finished_key = RandomFunction.HKDF.ExpandLabel(hmac, Server_handshake_secret, "finished", empty_STRING, (ushort)(hmac.HashSize / 8));
            var finished_hash = hash.ComputeHash(clienthello_certverify);

            hmac.Key = finished_key;
            return hmac.ComputeHash(finished_hash);
        }

        public override byte[] ClientMessageAuthCode(byte[] message)
        {
            throw new NotImplementedException("Not used, TLS 1.3 use AEAD BulkEncrypt which has MAC already");
        }

        public override byte[] ServerMessageAuthCode(byte[] message)
        {
            throw new NotImplementedException("Not used, TLS 1.3 use AEAD BulkEncrypt which has MAC already");
        }
        #endregion


        //https://tools.ietf.org/html/rfc8446#page-81
        protected void GetPlainTextForEncryption(byte[] message, Enums.RecordType recType, out byte[] plain, out byte[] aad)
        {
            // message + recordType + mac
            var outputSize = message.Length + 1 + this.GetMacLength();
            // applicationData,Tls1.2
            aad = new byte[] { 0x17, 0x03, 0x03, (byte)(outputSize >> 8), (byte)(outputSize & 0x00FF) };
            plain = message.Concat(new[] { (byte)recType }).ToArray();
        }

        public virtual void Calculate_ResumptionSecret(byte[] clienthello_clientfinished)
        {
            var hmac = GetHmacFunction();
            var transcriptHash = GetHashAlgorithm();
            Resumption_Master_Secret = RandomFunction.HKDF.DeriveSecret(hmac, MasterSecret, "exp master", clienthello_clientfinished, transcriptHash);
        }

        //https://tools.ietf.org/html/rfc8446#page-93
        public abstract void Calculate_HandshakeSecret(byte[] clientHello_serverHello, byte[] psk = null);

        public abstract void Calculate_ApplicationSecret(byte[] clienthello_serverfinished);

        public abstract byte[] BulkEncrypt_Handshake(byte[] handshakeFragments);

        public abstract byte[] BulkDecrypt_Handshake(byte[] messages, byte[] applicationRecHeader);

        public virtual bool VerifyClientFinished(byte[] clientVerifyData, byte[] clientHello_serverfinish)
        {
            var hash = GetHashAlgorithm();
            var hmac = GetHmacFunction();
            var empty_STRING = new byte[0];

            var finished_key = RandomFunction.HKDF.ExpandLabel(hmac, Client_handshake_secret, "finished", empty_STRING, (ushort)(hmac.HashSize / 8));
            var finished_hash = hash.ComputeHash(clientHello_serverfinish);

            hmac.Key = finished_key;
            var calculatedVerifyData = hmac.ComputeHash(finished_hash);
            return Utils.BytesEqual(calculatedVerifyData, clientVerifyData);
        }

        protected void UpdateIv(byte[] iv, ulong seq)
        {
            for (var i = 0; i < 8; i++)
            {
                iv[iv.Length - 1 - i] ^= ((byte)((seq >> (i * 8)) & 0xFF));
            }
        }

        public abstract HashAlgorithm GetHashAlgorithm();
    }
}
