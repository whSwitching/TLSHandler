using SuperSocket.SocketBase.Command;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using BMDS.FSQL.Enums.TDS;
using BMDS.FSQL.Enums.TLS;

namespace BMDS.FSQL.Server.Handler
{
    public class PreLoginHandler
    {
        public static void Process_PreloginOptions(TcpSession session, TDSRequest req)
        {
            session.State = SessionState.Client_Prelogin;

            var clientOptions = TDS.OptionsPayload.Parse(req.Body);
            var serverEncryption = clientOptions[PreLoginOptionToken.ENCRYPTION][0] == 0x02 ? EncryptionOption.Available_OFF : EncryptionOption.Required;

            var responseBody = TDS.OptionsPayload.CreateResponse(serverEncryption);
            var response = new TDS.TDSPacket(PacketType.TabularResult, PacketStatus.EndOfMessage, req.SPID, req.PacketID, req.Window, responseBody.GetBytes());
            if(serverEncryption == EncryptionOption.Required)
                LogHelper.Debug(session, $"Client Encryption Available, UseEncryption");
            session.UseEncryption(serverEncryption);
            session.Send(response);
            session.State = SessionState.Server_PreloginResponse;
        }

        public static void Process_Handshake(TcpSession session, TDSRequest req)
        {
            var tlsRecords = TLS.TLSPacket.Extract(req.Body);

            foreach (var tls in tlsRecords)
            {
                LogHelper.Debug(session, $"  Record: {tls.Type}");
                if (tls is TLS.Record.Handshake hs)
                {
                    foreach(var frag in hs.Fragments)
                    {
                        LogHelper.Debug(session, $"    Fragment: {frag.GetType().Name}");
                        if (frag is TLS.Fragment.HandshakeFragment hf)
                        {
                            session.AppendHandshakeMessages(frag);

                            if (hf.Body is TLS.Handshake.ClientHello ch)
                                Process_ClientHello(session, req, ch);
                            else if (hf.Body is TLS.Handshake.ClientKeyExchange cke)
                                Process_ClientKeyExchange(session, req, cke);
                            else
                            {
                                LogHelper.Error(session, $"unhandled TLS Handshake.Fragment.Body Type {hf.Body.GetType()}");
                                session.Close(SuperSocket.SocketBase.CloseReason.ApplicationError);
                                return;
                            }
                        }
                        else if (frag is TLS.Fragment.EncryptedHandshake ehs)
                            Process_EncryptedHandshake(session, req, ehs);
                        else
                        {
                            LogHelper.Error(session, $"unhandled TLS Handshake.Fragment.Type {frag.GetType()}");
                            session.Close(SuperSocket.SocketBase.CloseReason.ApplicationError);
                            return;
                        }

                    }
                }
                else if (tls is TLS.Record.ChangeCipherSpec ccs)
                {
                    Process_ChangeCipherSpec(session, req, ccs);
                }
                else
                {
                    LogHelper.Error(session, $"unhandled TLS RecordType {tls.Type}");
                    session.Close(SuperSocket.SocketBase.CloseReason.ApplicationError);
                    return;
                }
            }
        }

        static void Process_ClientHello(TcpSession session, TDSRequest tds, TLS.Handshake.ClientHello frag)
        {
            session.State = SessionState.Client_Hello;
            session.ClientRandom = frag.Random;
            session.ServerRandom = new TLS.ValueTypes.Random();
            session.TSession = new TLS.ValueTypes.Session(session.SessionGuid);
            session.CipherSuite = new TLS.Cipher.TLS_RSA_WITH_AES128_CBC_SHA256();

            var serverhelloBody = new TLS.Handshake.ServerHello(ProtocolVersion.TLSv1_2, session.ServerRandom, session.TSession, session.CipherSuite.CipherSuite);
            var certificateBody = new TLS.Handshake.Certificate(((TDSServer)session.AppServer).PublicKey);
            var serverhellodoneBody = new TLS.Handshake.ServerHelloDone();

            var responseFragments = new []
            {
                new TLS.Fragment.HandshakeFragment(HandshakeType.ServerHello, serverhelloBody),
                new TLS.Fragment.HandshakeFragment(HandshakeType.Certificate, certificateBody),
                new TLS.Fragment.HandshakeFragment(HandshakeType.Server_hello_done, serverhellodoneBody)
            };

            var recordsBytes = TLS.Record.Handshake.GetTLSPacketBytes(responseFragments);
            var response = new TDS.TDSPacket(PacketType.PreLogin, PacketStatus.EndOfMessage, tds.SPID, tds.PacketID, tds.Window, recordsBytes);

            session.Send(response);
            session.State = SessionState.Server_HelloDone;

            foreach (var f in responseFragments)
            {
                session.AppendHandshakeMessages(f);
                LogHelper.Debug(session, $"  {f.Body.GetType().Name}");
            }
        }

        static void Process_ClientKeyExchange(TcpSession session, TDSRequest tds, TLS.Handshake.ClientKeyExchange frag)
        {
            var prvPfx = ((TDSServer)session.AppServer).PrivateKey;
            var parameters = ((System.Security.Cryptography.RSACryptoServiceProvider)prvPfx.PrivateKey).ExportParameters(true);
            var pre_master_secret = session.CipherSuite.KeyExchange(frag.RSA_PreMasterSecret, parameters);
            if (pre_master_secret.Length != 48 || (ProtocolVersion)Utils.ToUInt16(pre_master_secret[0], pre_master_secret[1]) != ProtocolVersion.TLSv1_2)
            {
                LogHelper.Error(session, $"invalid ClientKeyExchange message");
                session.Close(SuperSocket.SocketBase.CloseReason.ProtocolError);
                return;
            }
            else
            {
                session.State = SessionState.Client_KeyExchange;
                var masterSecretSeed = session.ClientRandom.GetBytes().Concat(session.ServerRandom.GetBytes()).ToArray();
                var keyExpansionSeed = session.ServerRandom.GetBytes().Concat(session.ClientRandom.GetBytes()).ToArray();
                session.CipherSuite.CreateMasterSecret(pre_master_secret, masterSecretSeed);
                session.CipherSuite.CreateKeyBlocks(keyExpansionSeed);
            }
        }

        static void Process_ChangeCipherSpec(TcpSession session, TDSRequest tds, TLS.Record.ChangeCipherSpec rec)
        {
            if (session.State == SessionState.Client_KeyExchange)
                session.State = SessionState.Client_ChangeCipherSpec;
            else
            {
                LogHelper.Error(session, $"State [{session.State}] check failed on ChangeCipherSpec message");
                session.Close(SuperSocket.SocketBase.CloseReason.ProtocolError);
                return;
            }
        }

        static void Process_EncryptedHandshake(TcpSession session, TDSRequest tds, TLS.Fragment.EncryptedHandshake ehf)
        {
            if (session.State == SessionState.Client_ChangeCipherSpec)
            {
                var encrypt = ehf.EncryptedData;
                var decryptedHandshake = session.CipherSuite.BulkDecrypt(encrypt, ehf.IV);
                // 14 00 00 0C
                // 12-bytes-verify-data
                // 32-bytes-mac
                // 15-bytes-padding
                // 0x0F(padding-length)
                if (decryptedHandshake[0] == 0x14 && Utils.ToUInt24(decryptedHandshake[1], decryptedHandshake[2], decryptedHandshake[3]) == 12)
                {
                    var finished = new TLS.Handshake.Finished(decryptedHandshake.Skip(4).ToArray());

                    var allMessages = session.GetHandshakeMessages();
                    var myVerify = session.CipherSuite.GetVerifyData("client finished", allMessages);
                    if (!Utils.BytesEqual(myVerify, finished.VerifyData))
                    {
                        LogHelper.Error(session, $"unmatched VerifyData in TLS EncryptedHandshake message");
                        session.Close(SuperSocket.SocketBase.CloseReason.ApplicationError);
                        return;
                    }

                    var macseed = Utils.GetMacSeed(session.ReceiveSeqNum, (byte)RecordType.Handshake, decryptedHandshake.Take(16).ToArray());
                    var myMac = session.CipherSuite.ClientMessageAuthCode(macseed);
                    if (!Utils.BytesEqual(myMac, finished.Mac))
                    {
                        LogHelper.Error(session, $"unmatched MAC in TLS EncryptedHandshake message");
                        session.Close(SuperSocket.SocketBase.CloseReason.ApplicationError);
                        return;
                    }
                    session.ReceiveSeqNum++;
                    session.State = SessionState.Client_Finished;
                    // add client decrypted handshake to list
                    session.AppendHandshakeMessages(new TLS.Fragment.EncryptedHandshake(decryptedHandshake.Take(16).ToArray()));
                    // send changeCipherSpec, encrypted handshake
                    SendServerChangeCipherSpecAndFinished(session, tds);
                }
                else
                {
                    LogHelper.Error(session, $"invalid EncryptedHandshake message");
                    session.Close(SuperSocket.SocketBase.CloseReason.ProtocolError);
                    return;
                }
            }
            else
            {
                LogHelper.Error(session, $"State [{session.State}] check failed on EncryptedHandshake message");
                session.Close(SuperSocket.SocketBase.CloseReason.ProtocolError);
                return;
            }
        }

        static void SendServerChangeCipherSpecAndFinished(TcpSession session, TDSRequest tds)
        {
            if (session.State == SessionState.Client_Finished)
            {
                var changeCipherRecord = new TLS.Record.ChangeCipherSpec();

                var allMessages = session.GetHandshakeMessages();
                var finishedVerify = session.CipherSuite.GetVerifyData("server finished", allMessages);

                var finishedMessage = new byte[] { 0x14, 0x00, 0x00, 0x0C }.Concat(finishedVerify).ToArray();
                var macSeed = Utils.GetMacSeed(session.SendSeqNum, (byte)RecordType.Handshake, finishedMessage);
                var myMac = session.CipherSuite.ServerMessageAuthCode(macSeed);

                var finished = new List<byte>();
                finished.AddRange(finishedMessage);
                finished.AddRange(myMac);

                var serverIv = Utils.Random(16);
                var encryptedFinished = session.CipherSuite.BulkEncrypt(finished.ToArray(), serverIv);

                var serverFinishFragment = new TLS.Fragment.EncryptedHandshake(serverIv.Concat(encryptedFinished).ToArray());
                var serverFinishRecordBytes = TLS.Record.Handshake.GetTLSPacketBytes(new[] { serverFinishFragment });

                var recordsBytes = new List<byte>();
                recordsBytes.AddRange(changeCipherRecord.GetBytes());
                recordsBytes.AddRange(serverFinishRecordBytes);

                var response = new TDS.TDSPacket(PacketType.PreLogin, PacketStatus.EndOfMessage, tds.SPID, tds.PacketID, tds.Window, recordsBytes.ToArray());
                session.Send(response);
                session.SendSeqNum++;
                session.State = SessionState.Server_Finished;
            }
            else
            {
                LogHelper.Error(session, $"State [{session.State}] check failed on SendServerChangeCipherSpecAndFinished");
                session.Close(SuperSocket.SocketBase.CloseReason.ProtocolError);
                return;
            }
        }
    }
}
