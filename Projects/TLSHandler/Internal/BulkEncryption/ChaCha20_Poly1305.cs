using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Engines = Org.BouncyCastle.Crypto.Engines;
using Macs = Org.BouncyCastle.Crypto.Macs;
using Parameters = Org.BouncyCastle.Crypto.Parameters;

namespace TLSHandler.Internal.BulkEncryption
{
    //https://tools.ietf.org/html/rfc8439#section-2.8
    class ChaCha20_Poly1305 : IAeadBulkEncryption
    {
        public int KeySize { get { return 256; } }
        public int MacSize { get { return 128; } }

        public byte[] Decrypt(byte[] cipher, byte[] key, byte[] iv, byte[] aad = null, byte[] associated = null)
        {
            if (key.Length * 8 != this.KeySize)
                throw new InvalidOperationException($"the given key has invalid size {key.Length * 8}, expect {this.KeySize}");
            if (iv.Length != 12)
                throw new InvalidOperationException($"chacha20 requires 96 bits IV, got {iv.Length * 8}");
            if (cipher.Length <= 16)
                throw new ArgumentException($"incorrect argument [cipher] size");
            // split cipher and mac
            var cipherText = cipher.Take(cipher.Length - 16).ToArray();
            var macText = cipher.Skip(cipher.Length - 16).ToArray();

            var engine = new Engines.ChaCha7539Engine();
            engine.Init(false, new Parameters.ParametersWithIV(new Parameters.KeyParameter(key), iv));
            // calculate mac key
            var mackeyBlock = new byte[64];
            engine.ProcessBytes(mackeyBlock, 0, mackeyBlock.Length, mackeyBlock, 0);
            var mackey = mackeyBlock.Take(32).ToArray();
            // calculate mac
            var poly = new Macs.Poly1305();
            poly.Init(new Parameters.KeyParameter(mackey));
            PolyUpdateMacText(poly, aad);
            PolyUpdateMacText(poly, cipherText);
            PolyUpdateMacLength(poly, aad.Length);
            PolyUpdateMacLength(poly, cipherText.Length);
            var myMac = PolyDoFinal(poly);
            if (!Utils.BytesEqual(myMac, macText))
                throw new ArgumentException("bad record mac");
            // decrypt
            var plain = new byte[cipherText.Length];
            engine.ProcessBytes(cipherText, 0, cipherText.Length, plain, 0);
            return plain;
        }

        public byte[] Encrypt(byte[] plain, byte[] key, byte[] iv, byte[] aad = null, byte[] associated = null)
        {
            if (key.Length * 8 != this.KeySize)
                throw new InvalidOperationException($"the given key has invalid size {key.Length * 8}, expect {this.KeySize}");
            if (iv.Length != 12)
                throw new InvalidOperationException($"chacha20 requires 96 bits IV, got {iv.Length * 8}");

            var engine = new Engines.ChaCha7539Engine();
            engine.Init(true, new Parameters.ParametersWithIV(new Parameters.KeyParameter(key), iv));
            // calculate mac key
            var mackeyBlock = new byte[64];
            engine.ProcessBytes(mackeyBlock, 0, mackeyBlock.Length, mackeyBlock, 0);
            var mackey = mackeyBlock.Take(32).ToArray();
            // encrypt
            var cipher = new byte[plain.Length];
            engine.ProcessBytes(plain, 0, plain.Length, cipher, 0);
            // calculate mac
            var poly = new Macs.Poly1305();
            poly.Init(new Parameters.KeyParameter(mackey));
            PolyUpdateMacText(poly, aad);
            PolyUpdateMacText(poly, cipher);
            PolyUpdateMacLength(poly, aad.Length);
            PolyUpdateMacLength(poly, cipher.Length);
            var myMac = PolyDoFinal(poly);
            var cipherBlock = new byte[cipher.Length + myMac.Length];
            Buffer.BlockCopy(cipher, 0, cipherBlock, 0, cipher.Length);
            Buffer.BlockCopy(myMac, 0, cipherBlock, cipher.Length, myMac.Length);
            return cipherBlock;
        }

        static void PolyUpdateMacText(Macs.Poly1305 poly, byte[] buf)
        {
            poly.BlockUpdate(buf, 0, buf.Length);
            int partial = buf.Length % 16;
            if (partial != 0)
            {
                var zeroPadding = new byte[15];
                poly.BlockUpdate(zeroPadding, 0, 16 - partial);
            }
        }
        static void PolyUpdateMacLength(Macs.Poly1305 poly, int len)
        {
            byte[] longLen = BitConverter.GetBytes((ulong)len);
            poly.BlockUpdate(longLen, 0, longLen.Length);
        }
        static byte[] PolyDoFinal(Macs.Poly1305 poly)
        {
            byte[] b = new byte[poly.GetMacSize()];
            poly.DoFinal(b, 0);
            return b;
        }

        public void Dispose()
        {
        }
    }
}
