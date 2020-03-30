using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;
using TLS = TLSHandler.Internal.TLS;
using Ciphers = TLSHandler.Internal.Ciphers;
using Records = TLSHandler.Internal.TLS.Records;
using Fragments = TLSHandler.Internal.TLS.Fragments;
using Handshakes = TLSHandler.Internal.TLS.Handshakes;

namespace TLSHandler.Handler
{
    class Session13 : Session12
    {
        public Session13(NegotiationParams para, string pub_crt_filepath, string prv_pfx_filepath) : base(para, pub_crt_filepath, prv_pfx_filepath)
        {
        }

        #region Record process override
        protected override Result Record_ChangeCipherSpec(Records.ChangeCipherSpec rec)
        {
            if (State == TLSSessionState.Server_Finished)
            {
                State = TLSSessionState.Client_ChangeCipherSpec;
                return null;
            }
            else
            {
                return Result.FatalAlert(AlertDescription.unexpected_message, $"State [{State}] check failed on Client_ChangeCipherSpec message");
            }
        }

        protected override Result Record_ApplicationData(Records.ApplicationData rec)
        {
            if (State == TLSSessionState.Client_ChangeCipherSpec)
            {
                var clientFinish = (_params.Cipher as Ciphers.CipherSuiteBase13).BulkDecrypt_Handshake(rec.Payload, rec.GetHeaderBytes());
                var recType = (RecordType)clientFinish.Last();
                var recPayload = clientFinish.Take(clientFinish.Length - 1).ToArray();
                var decodedRec = Records.TLSRecord.Factory(recType, recPayload);
                Console.WriteLine($">>>>>>>> RECEIVE encrypted TLS {recType}");
                return Process_Record(decodedRec);
            }
            else if (State == TLSSessionState.Client_Finished)
            {
                var appdata = (_params.Cipher as Ciphers.CipherSuiteBase13).BulkDecrypt(rec.Payload, rec.GetHeaderBytes());
                var recType = (RecordType)appdata.Last();
                var recPayload = appdata.Take(appdata.Length - 1).ToArray();
                if (recType == RecordType.ApplicationData)
                    return new ApplicationResult(recPayload);
                else
                {
                    var decodedRec = Records.TLSRecord.Factory(recType, recPayload);
                    Console.WriteLine($">>>>>>>> RECEIVE encrypted TLS {recType}");
                    return Process_Record(decodedRec);
                }
            }
            return Result.FatalAlert(AlertDescription.unexpected_message, $"State [{State}] check failed on Client_ApplicationData message");
        }

        public override Result GetEncryptedPacket(byte[] rawDataToSend)
        {
            var encrypted = (_params.Cipher as Ciphers.CipherSuiteBase13).BulkEncrypt(rawDataToSend, null);
            return new PacketResult(new [] { new Records.ApplicationData(encrypted) });
        }
        #endregion

        #region fragment process override
        protected override Result Fragment_Handshake(Handshakes.Fragment frag)
        {
            LogSessionInfo(frag.Body);

            if (frag.Body is Fragments.ClientHello ch)
                return Fragment_ClientHello(ch);
            else if (frag.Body is Fragments.ClientKeyExchange cke)
                return Fragment_ClientKeyExchange(cke);
            else if (frag.Body is Fragments.Finished cf)
                return Fragment_ClientFinished(cf);
            else if (frag.Body is Fragments.KeyUpdate ku)
                return Fragment_ClientKeyUpdate(ku);
            else
                return Result.FatalAlert(AlertDescription.unexpected_message, $"Unhandled TLS HandshakeFragment.Body {frag.Body.GetType().Name}");
        }

        protected override Result Fragment_ClientHello(Fragments.ClientHello frag)
        {
            State = TLSSessionState.Client_Hello;

            _params.ClientRandom = frag.Random;
            _params.ServerRandom = new TLS.ValueTypes.Random();
            _params.Session = new TLS.ValueTypes.Session(frag.Session.ID);

            if (frag.PreSharedKeys != null && frag.PreSharedKeys.Identities != null && frag.PreSharedKeys.Identities.Length > 0)
                Console.WriteLine($"PreSharedKeys: {string.Join("", frag.PreSharedKeys.Identities[0].Identity.Select(a => a.ToString("X2")))}");

            //if (frag.PreSharedKeys == null || frag.PreSharedKeys.Identities == null || frag.PreSharedKeys.Identities.Length == 0)
            //{
            var result = Fragment_ClientHello_New(frag);
            State = TLSSessionState.Server_Finished;
            return result;
            //}
            //else
            //{
            //    var result = Fragment_ClientHello_Resumption(frag);
            //    State = TLSSessionState.Server_Finished;
            //    return result;
            //}
        }

        Result Fragment_ClientHello_New(Fragments.ClientHello frag)
        {
            var ecdhpub = GeneratePubKey();
            var extensions = new TLS.Extensions.Extension[]
            {
                new TLS.Extensions.KeyShare(_params.KeyShare.Group, ecdhpub),
                new TLS.Extensions.SupportedVersions(ProtocolVersion.TLSv1_3)
            };
            var serverhelloBody = new Fragments.ServerHello(ProtocolVersion.TLSv1_2, _params.ServerRandom, _params.Session, _params.Cipher.CipherSuite, extensions);
            var serverhelloFragment = new Handshakes.Fragment(HandshakeType.Server_Hello, serverhelloBody);
            var encryptedExtFragment = new Handshakes.Fragment(HandshakeType.Encrypted_Extensions, new Fragments.EncryptedExtensions());
            var certificateFragment = new Handshakes.Fragment(HandshakeType.Certificate, new Fragments.Certificate(new[] { new X509Certificate2(_pubkeyfile) }, true));

            // add [ServerHello] to list
            AppendHandshakeMessages(serverhelloFragment);
            // get (clienthello + serverhello)
            var clientHello_serverHello = GetHandshakeMessages();
            // calculate shared_secret and HandshakeSecret
            (_params.Cipher as Ciphers.CipherSuiteBase13).KeyExchange(_params.KeyShare.KeyExchange, null, null, _params.ServerKey.Private);
            (_params.Cipher as Ciphers.CipherSuiteBase13).Calculate_HandshakeSecret(clientHello_serverHello);
            // add [EncryptedExtensions] to list
            AppendHandshakeMessages(encryptedExtFragment);
            // add [Certificate] to list
            AppendHandshakeMessages(certificateFragment);
            // get (clienthello + serverhello + encryptedExtensions + certificate)
            var clientHello_cert = GetHandshakeMessages();
            // get signature for CertificateVerify
            var signature = MakeCertificateVerifySignature(clientHello_cert);
            var certVerifyFragment = new Handshakes.Fragment(HandshakeType.Certificate_Verify, new Fragments.CertificateVerify(_params.SignatureAlgorithm, signature));
            // add [CertificateVerify] to list
            AppendHandshakeMessages(certVerifyFragment);
            // get (clienthello + serverhello + encryptedExtensions + certificate + certificateVerify)
            var clientHello_certVerify = GetHandshakeMessages();
            // get verifyData for ServerFinished
            var verifyData = (_params.Cipher as Ciphers.CipherSuiteBase13).GetVerifyData("finished", clientHello_certVerify);
            var finishFragment = new Handshakes.Fragment(HandshakeType.Finished, new Fragments.Finished(verifyData));
            // add [ServerFinished] to list
            AppendHandshakeMessages(finishFragment);
            // before return, calculate ApplicationSecret
            // get (clienthello + serverhello + encryptedExtensions + certificate + certificateVerify + serverFinished)
            var clientHello_serverfinish = GetHandshakeMessages();
            (_params.Cipher as Ciphers.CipherSuiteBase13).Calculate_ApplicationSecret(clientHello_serverfinish);
            // wrap 4 fragments in applicationRecord
            var plainPayload = new List<byte>();
            plainPayload.AddRange(encryptedExtFragment.Data);
            plainPayload.AddRange(certificateFragment.Data);
            plainPayload.AddRange(certVerifyFragment.Data);
            plainPayload.AddRange(finishFragment.Data);

            // log info
            LogSessionInfo(serverhelloFragment.Body);
            LogSessionInfo(encryptedExtFragment.Body);
            LogSessionInfo(certificateFragment.Body);
            LogSessionInfo(certVerifyFragment.Body);
            LogSessionInfo(finishFragment.Body);

            var encryptedPayload = (_params.Cipher as Ciphers.CipherSuiteBase13).BulkEncrypt_Handshake(plainPayload.ToArray());

            return new PacketResult(new Records.TLSRecord[]
            {
                new Records.Handshake(new [] {serverhelloFragment }),  // ServerHello
                new Records.ChangeCipherSpec(),                        // ChangeCipherSpec
                new Records.ApplicationData(encryptedPayload)          // ApplicationData (EncryptedExtensions,Certificate,CertificateVerify,Finished)
            });
        }

        Result Fragment_ClientHello_Resumption(Fragments.ClientHello frag)
        {
            throw new NotImplementedException();
        }

        byte[] MakeCertificateVerifySignature(byte[] handshakeMsg)
        {
            var handshakeHash = (_params.Cipher as Ciphers.CipherSuiteBase13).GetHashAlgorithm().ComputeHash(handshakeMsg);
            var contextString = "TLS 1.3, server CertificateVerify"; // or "TLS 1.3, client CertificateVerify"
            var dataToSign = new List<byte>
            {
                0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,
                0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,
                0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,
                0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,
            };
            dataToSign.AddRange(Encoding.ASCII.GetBytes(contextString));
            dataToSign.Add(0x00);
            dataToSign.AddRange(handshakeHash);
            var prvParams = ((RSACryptoServiceProvider)(new X509Certificate2(_prvkeyfile, "", X509KeyStorageFlags.Exportable)).PrivateKey).ExportParameters(true);
            return _params.Cipher.Signature(dataToSign.ToArray(), _params.SignatureAlgorithm, prvParams);
        }

        protected override Result Fragment_ClientFinished(Fragments.Finished frag)
        {
            if (State == TLSSessionState.Client_ChangeCipherSpec)
            {
                var clientVerify = frag.Data;
                var clientHello_serverfinish = GetHandshakeMessages(true);  // without this finished itself
                var verified = (_params.Cipher as Ciphers.CipherSuiteBase13).VerifyClientFinished(clientVerify, clientHello_serverfinish);
                if (verified)
                {
                    State = TLSSessionState.Client_Finished;

                    var clientHello_clientfinish = GetHandshakeMessages();
                    (_params.Cipher as Ciphers.CipherSuiteBase13).Calculate_ResumptionSecret(clientHello_clientfinish);

                    //// NewSessionTicket? may not needed
                    //var fragmentBytes = new TLS.Fragment.HandshakeFragment(HandshakeType.NewSessionTicket, TLS.Handshake.NewSessionTicket.Random(0)).GetBytes();
                    //// encrypt
                    //(_params.Cipher as Ciphers.CipherSuiteBase13).GetPlainTextForEncryption(fragmentBytes, RecordType.Handshake, out byte[] plain, out byte[] aad);
                    //var encrypted = (_params.Cipher as Ciphers.CipherSuiteBase13).BulkEncrypt(plain, null, aad);
                    //return new Result(new TLSRecord[] {  new TLSRecord(RecordType.ApplicationData, encrypted) });

                    return null;
                }
                else
                    return Result.FatalAlert(AlertDescription.illegal_parameter, $"ClientFinished verify data check failed");
            }
            else
                return Result.FatalAlert(AlertDescription.unexpected_message, $"State [{State}] check failed on Client_Finished message");
        }

        protected Result Fragment_ClientKeyUpdate(Fragments.KeyUpdate frag)
        {
            throw new NotImplementedException();
        }
        #endregion
    }
}
