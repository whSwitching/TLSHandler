using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace TLSHandler.Internal.KeyExchange
{
    abstract class KeyExchange12 : IKeyExchange
    {
        public abstract bool IsRsaKeyExchange { get; }
        public byte[] MasterSecret { get; protected set; } = new byte[48];
        public byte[] Client_Handshake_Key { get; protected set; }
        public byte[] Server_Handshake_Key { get; protected set; }
        public byte[] Client_Application_Key { get; protected set; }
        public byte[] Server_Application_Key { get; protected set; }

        public KeyExchange12(int handshakeKeyLen, int applicationKeyLen)
        {
            Client_Handshake_Key = new byte[handshakeKeyLen];
            Server_Handshake_Key = new byte[handshakeKeyLen];
            Client_Application_Key = new byte[applicationKeyLen];
            Server_Application_Key = new byte[applicationKeyLen];
        }

        public virtual void Exchange(byte[] encryptedPreMasterSecret, byte[] clientRandom, byte[] serverRandom, object privateParameters)
        {
            GenerateMasterSecret(encryptedPreMasterSecret, clientRandom, serverRandom, privateParameters);

            CreateKeyBlocks(serverRandom.Concat(clientRandom).ToArray());
        }

        protected abstract void GenerateMasterSecret(byte[] encryptedPreMasterSecret, byte[] clientRandom, byte[] serverRandom, object privateParameters);

        protected virtual void CreateKeyBlocks(byte[] serverRandomClientRandom)
        {
            var keyblock = RandomFunction.PRF.GetBytes_HMACSHA256(MasterSecret, "key expansion", serverRandomClientRandom, 96);
            Buffer.BlockCopy(keyblock, 0, Client_Handshake_Key, 0, Client_Handshake_Key.Length);
            Buffer.BlockCopy(keyblock, Client_Handshake_Key.Length, Server_Handshake_Key, 0, Server_Handshake_Key.Length);
            Buffer.BlockCopy(keyblock, Client_Handshake_Key.Length + Server_Handshake_Key.Length, Client_Application_Key, 0, Client_Application_Key.Length);
            Buffer.BlockCopy(keyblock, Client_Handshake_Key.Length + Server_Handshake_Key.Length + Client_Application_Key.Length, Server_Application_Key, 0, Server_Application_Key.Length);
        }

        public void Dispose()
        {
            Utils.EmptyBuffer(MasterSecret);
            Utils.EmptyBuffer(Client_Handshake_Key);
            Utils.EmptyBuffer(Server_Handshake_Key);
            Utils.EmptyBuffer(Client_Application_Key);
            Utils.EmptyBuffer(Server_Application_Key);
        }
    }
}
