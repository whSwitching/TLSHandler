using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.Ciphers
{
    abstract class Suite12<keyexchange, bulkencryption, hmac> : CipherSuiteBase12
        where keyexchange : KeyExchange.KeyExchange12
        where bulkencryption : IEmBulkEncryption
        where hmac : HMAC
    {

        #region CipherSuiteBase
        public override bool IsRsaKeyExchange { get { return GetKeyExchange().IsRsaKeyExchange; } }

        public override void KeyExchange(byte[] encryptedPreMasterSecret, byte[] clientRandom, byte[] serverRandom, object privateParameters)
        {
            using (var keyex = GetKeyExchange())
            {
                keyex.Exchange(encryptedPreMasterSecret, clientRandom, serverRandom, privateParameters);
                if (keyex is KeyExchange.KeyExchange12 key)
                {
                    this.MasterSecret = Utils.CopyBuffer(key.MasterSecret);
                    this.Client_Handshake_Key = Utils.CopyBuffer(key.Client_Handshake_Key);
                    this.Client_Application_Key = Utils.CopyBuffer(key.Client_Application_Key);
                    this.Server_Handshake_Key = Utils.CopyBuffer(key.Server_Handshake_Key);
                    this.Server_Application_Key = Utils.CopyBuffer(key.Server_Application_Key);
                }
            }
        }

        public override byte[] BulkEncrypt(byte[] msg_WithoutPadding, byte[] iv)
        {
            using (var cipher = GetBulkEncryption())
            {
                var withpadding = Pad_Pkcs7(msg_WithoutPadding);
                return cipher.Encrypt(withpadding, Server_Application_Key, iv);
            }
        }

        public override byte[] BulkDecrypt(byte[] secret, byte[] iv)
        {
            using (var cipher = GetBulkEncryption())
            {
                var msg = cipher.Decrypt(secret, Client_Application_Key, iv);
                return UnPad_Pkcs7(msg);
            }
        }

        #endregion

        protected abstract bulkencryption GetBulkEncryption();
        protected abstract keyexchange GetKeyExchange();
    }
}
