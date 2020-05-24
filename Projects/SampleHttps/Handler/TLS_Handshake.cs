using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SuperSocket.SocketBase.Protocol;
using SuperSocket.SocketBase.Command;
using TLSHandler.Enums;
using TLSHandler.Handler;
using TLSHandler.Internal.TLS.Records;

namespace Https.Handler
{
    public class TLS_Handshake : CommandBase<TcpSession, Request.TLSRequest>
    {
        public override string Name => RecordType.Handshake.ToString();

        public override void ExecuteCommand(TcpSession session, Request.TLSRequest tlsRec)
        {
            var record = new Handshake(tlsRec.Payload);

            if (session.TLSContext == null)
            {
                var svr = (HttpServer)session.AppServer;
                session.TLSContext = new Context(svr.PublicKeyFile, svr.PrivateKeyFile, svr.ForceClientCertificate, svr.ForceServerNameCheck, svr.EnableTLS13)
                {
                    ClientCertificatesCallback = (chain) => On_ClientCertificate_Verify(svr.PrivateKeyFile, chain)
                };

                var response = session.TLSContext.Initialize(record);
                session.Send(response);
            }
            else
            {
                session.Receive(record);
            }
        }
        
        bool On_ClientCertificate_Verify(string pfxFilePath, System.Security.Cryptography.X509Certificates.X509Certificate2[] client_certs)
        {
            /*
            if (client_certs != null && client_certs.Length > 0)
            {
                var server_ca = new System.Security.Cryptography.X509Certificates.X509Certificate2(pfxFilePath);
                var ca_chain = System.Security.Cryptography.X509Certificates.X509Chain.Create();
                ca_chain.ChainPolicy.ExtraStore.Add(server_ca);
                ca_chain.ChainPolicy.VerificationFlags = System.Security.Cryptography.X509Certificates.X509VerificationFlags.AllowUnknownCertificateAuthority;
                foreach (var cert in client_certs)
                {
                    if (!ca_chain.Build(cert))
                        return false;
                }
                return true;
            }
            else
                return false;
            */
            return true;
        }
    }
}
