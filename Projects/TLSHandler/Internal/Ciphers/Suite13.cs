using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Internal.Ciphers
{
    abstract class Suite13<bulkencryption, hmac, hash> : CipherSuiteBase13
        where bulkencryption : IBulkEncryption, IAead
        where hmac : HMAC
        where hash : HashAlgorithm
    {
        #region CipherSuiteBase
        
        public override int GetMacLength()
        {
            using (var enc = GetBulkEncryption())
            {
                return enc.MacSize / 8;
            }
        }

        public override byte[] BulkEncrypt(byte[] rawMsgToSend, byte[] iv = null)
        {
            GetPlainTextForEncryption(rawMsgToSend, Enums.RecordType.ApplicationData, out byte[] plain, out byte[] aad);

            using (var cipher = GetBulkEncryption())
            {
                var nonce = DeriveNonce(Server_Application_Iv, Server_Application_Iv_Seq);
                var ret = cipher.Encrypt(plain, Server_Application_Key, nonce, aad, null);
                Server_Application_Iv_Seq++;
                return ret;
            }
        }

        public override byte[] BulkDecrypt(byte[] secret, byte[] additional_data)
        {
            using (var cipher = GetBulkEncryption())
            {
                var nonce = DeriveNonce(Client_Application_Iv, Client_Application_Iv_Seq);
                var ret = cipher.Decrypt(secret, Client_Application_Key, nonce, additional_data, null);
                Client_Application_Iv_Seq++;
                return ret;
            }
        }

        #endregion

        //https://tools.ietf.org/html/rfc8446#page-93
        public override void Calculate_HandshakeSecret(byte[] clientHello_serverHello, byte[] psk = null)
        {
            var keysize = GetBulkEncryption().KeySize / 8;
            var ivsize = 12;
            Client_Handshake_Key = new byte[keysize];
            Client_Handshake_Iv = new byte[ivsize];
            Server_Handshake_Key = new byte[keysize];
            Server_Handshake_Iv = new byte[ivsize];

            var empty_STRING = new byte[0];
            var hmac = GetHmacFunction();
            var transcriptHash = GetHashAlgorithm();
            var ikm = psk ?? new byte[hmac.HashSize / 8];

            var early_secret = RandomFunction.HKDF.Extract(hmac, new byte[hmac.HashSize / 8], ikm);
            var derived_secret = RandomFunction.HKDF.DeriveSecret(hmac, early_secret, "derived", empty_STRING, transcriptHash);
            Handshake_secret = RandomFunction.HKDF.Extract(hmac, derived_secret, ECDHE_Shared_secret);

            Client_handshake_secret = RandomFunction.HKDF.DeriveSecret(hmac, Handshake_secret, "c hs traffic", clientHello_serverHello, transcriptHash);
            Server_handshake_secret = RandomFunction.HKDF.DeriveSecret(hmac, Handshake_secret, "s hs traffic", clientHello_serverHello, transcriptHash);

            Client_Handshake_Key = RandomFunction.HKDF.ExpandLabel(hmac, Client_handshake_secret, "key", empty_STRING, (ushort)Client_Handshake_Key.Length);
            Client_Handshake_Iv = RandomFunction.HKDF.ExpandLabel(hmac, Client_handshake_secret, "iv", empty_STRING, (ushort)Client_Handshake_Iv.Length);
            Server_Handshake_Key = RandomFunction.HKDF.ExpandLabel(hmac, Server_handshake_secret, "key", empty_STRING, (ushort)Server_Handshake_Key.Length);
            Server_Handshake_Iv = RandomFunction.HKDF.ExpandLabel(hmac, Server_handshake_secret, "iv", empty_STRING, (ushort)Server_Handshake_Iv.Length);
        }

        public override void Calculate_ApplicationSecret(byte[] clienthello_serverfinished)
        {
            var keysize = GetBulkEncryption().KeySize / 8;
            var ivsize = 12;
            Client_Application_Key = new byte[keysize];
            Client_Application_Iv = new byte[ivsize];
            Server_Application_Key = new byte[keysize];
            Server_Application_Iv = new byte[ivsize];

            var empty_STRING = new byte[0];
            var hmac = GetHmacFunction();
            var transcriptHash = GetHashAlgorithm();

            var derived_secret = RandomFunction.HKDF.DeriveSecret(hmac, Handshake_secret, "derived", empty_STRING, transcriptHash);
            MasterSecret = RandomFunction.HKDF.Extract(hmac, derived_secret, new byte[hmac.HashSize / 8]);

            Client_application_secret = RandomFunction.HKDF.DeriveSecret(hmac, MasterSecret, "c ap traffic", clienthello_serverfinished, transcriptHash);
            Server_application_secret = RandomFunction.HKDF.DeriveSecret(hmac, MasterSecret, "s ap traffic", clienthello_serverfinished, transcriptHash);

            Client_Application_Key = RandomFunction.HKDF.ExpandLabel(hmac, Client_application_secret, "key", empty_STRING, (ushort)Client_Application_Key.Length);
            Client_Application_Iv = RandomFunction.HKDF.ExpandLabel(hmac, Client_application_secret, "iv", empty_STRING, (ushort)Client_Application_Iv.Length);
            Server_Application_Key = RandomFunction.HKDF.ExpandLabel(hmac, Server_application_secret, "key", empty_STRING, (ushort)Server_Application_Key.Length);
            Server_Application_Iv = RandomFunction.HKDF.ExpandLabel(hmac, Server_application_secret, "iv", empty_STRING, (ushort)Server_Application_Iv.Length);

            Exporter_Master_Secret = RandomFunction.HKDF.DeriveSecret(hmac, MasterSecret, "exp master", clienthello_serverfinished, transcriptHash);
        }

        public override byte[] BulkEncrypt_Handshake(byte[] handshakeFragments)
        {
            GetPlainTextForEncryption(handshakeFragments, Enums.RecordType.Handshake, out byte[] plain, out byte[] aad);

            using (var cipher = GetBulkEncryption())
            {
                var nonce = DeriveNonce(Server_Handshake_Iv, Server_Handshake_Iv_Seq);
                var ret = cipher.Encrypt(plain, Server_Handshake_Key, nonce, aad, null);
                Server_Handshake_Iv_Seq++;
                return ret;
            }
        }

        public override byte[] BulkDecrypt_Handshake(byte[] messages, byte[] applicationRecHeader)
        {
            using (var cipher = GetBulkEncryption())
            {
                var nonce = DeriveNonce(Client_Handshake_Iv, Client_Handshake_Iv_Seq);
                var ret = cipher.Decrypt(messages, Client_Handshake_Key, nonce, applicationRecHeader, null);
                Client_Handshake_Iv_Seq++;
                return ret;
            }
        }


        protected abstract bulkencryption GetBulkEncryption();
    }
}
