using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using SuperSocket.SocketBase;
using SuperSocket.SocketBase.Config;
using SuperSocket.SocketBase.Protocol;

namespace Https
{
    public class HttpServer : AppServer<TcpSession, Request.TLSRequest>
    {
        public readonly int Port;
        public readonly string PublicKeyFile;
        public readonly string PrivateKeyFile;

        public HttpServer()
        {
            var port = ConfigurationManager.AppSettings["ServerPort"];
            var pubkey = ConfigurationManager.AppSettings["ServerCertFilepath"];
            var pvtkey = ConfigurationManager.AppSettings["ServerPfxFilepath"];

            if (!Path.IsPathRooted(pubkey))
                pubkey = GetFilePath(pubkey);
            if (!Path.IsPathRooted(pvtkey))
                pvtkey = GetFilePath(pvtkey);

            if (!int.TryParse(port, out Port))
                throw new ArgumentException($"AppSetting [ServerPort] ({port}) invalid");
            if (!File.Exists(pubkey))
                throw new ArgumentException($"AppSetting [ServerCertFilepath] ({pubkey}) does not exist");
            if (!File.Exists(pvtkey))
                throw new ArgumentException($"AppSetting [ServerPfxFilepath] ({pvtkey}) does not exist");

            this.ReceiveFilterFactory = new DefaultReceiveFilterFactory<Filter.TLSPacketFilter, Request.TLSRequest>();
            this.PublicKeyFile = pubkey;
            this.PrivateKeyFile = pvtkey;
        }

        public bool Setup()
        {
            var cfg = new ServerConfig
            {
                Ip = "127.0.0.1",
                Port = this.Port,
                MaxRequestLength = 100 * 1024,    // 100k
                ClearIdleSession = true,
                ClearIdleSessionInterval = 60,
                IdleSessionTimeOut = 30,
                DisableSessionSnapshot = true,
            };
            return base.Setup(cfg);
        }
    }
}
