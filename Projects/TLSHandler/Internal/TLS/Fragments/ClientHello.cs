using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.TLS.Fragments
{
    //https://tools.ietf.org/html/rfc5246#section-7.4.1.2
    public class ClientHello : FragmentBody
    {
        public ProtocolVersion ProtocolVersion { get; private set; }

        public ValueTypes.Random Random { get; private set; }

        public ValueTypes.Session Session { get; private set; }

        public ValueTypes.CipherSuites CipherSuites { get; private set; }

        public ValueTypes.CompressionMethods CompressionMethods { get; private set; }

        public Extensions.Extension[] Extensions { get; private set; }

        public ushort ExtensionsLength { get; private set; }

        public ushort Length { get { return (ushort)Data.Length; } }

        public ClientHello(byte[] clientHelloBytes) : base(clientHelloBytes)
        {
            var index = 0;

            var _protocolVersion = Utils.ToUInt16(clientHelloBytes, index);
            index += 2;

            var bytes_random = new byte[32];
            Buffer.BlockCopy(clientHelloBytes, index, bytes_random, 0, bytes_random.Length);
            index += 32;

            var _sessionIDLength = clientHelloBytes[index];
            byte[] _sessionID = null;
            index++;

            // if sessionID exists
            if (_sessionIDLength > 0)
            {
                _sessionID = new byte[_sessionIDLength];
                Buffer.BlockCopy(clientHelloBytes, index, _sessionID, 0, _sessionIDLength);
                index += _sessionIDLength;
            }

            var _cipherSuiteLen = Utils.ToUInt16(clientHelloBytes, index);
            _cipherSuiteLen = (ushort)(_cipherSuiteLen / 2);
            index += 2;
            CipherSuite[] _cipherSuites = new CipherSuite[_cipherSuiteLen];
            for (int csi = 0; csi < _cipherSuiteLen; csi++)
            {
                _cipherSuites[csi] = (CipherSuite)Utils.ToUInt16(clientHelloBytes, index);
                index += 2;
            }

            var _compressionMethodLen = clientHelloBytes[index];
            index++;
            CompressionMethod[] _compressionMethods = new CompressionMethod[_compressionMethodLen];
            for (int cmi = 0; cmi < _compressionMethodLen; cmi++)
            {
                _compressionMethods[cmi] = (CompressionMethod)clientHelloBytes[index];
                index++;
            }

            var _extensionsLength = Utils.ToUInt16(clientHelloBytes, index);
            index += 2;

            var bytes_extensions = new byte[_extensionsLength];
            Buffer.BlockCopy(clientHelloBytes, index, bytes_extensions, 0, _extensionsLength);
            var _extensions = TLS.Extensions.Extension.Extract(bytes_extensions);

            this.ProtocolVersion = (ProtocolVersion)_protocolVersion;
            this.Random = new ValueTypes.Random(bytes_random);
            this.Session = new ValueTypes.Session(_sessionID);
            this.CipherSuites = new ValueTypes.CipherSuites(_cipherSuites);
            this.CompressionMethods = new ValueTypes.CompressionMethods(_compressionMethods);
            this.Extensions = _extensions;
            this.ExtensionsLength = TLS.Extensions.Extension.GetLength(_extensions);
        }

        #region Extensions GET
        public string[] ServerName
        {
            get
            {
                var ex = this.Extensions.FirstOrDefault(a => a.Type == ExtensionType.SERVER_NAME);
                return ex != null ? ((Extensions.ServerName)ex).Entries.Select(a => a.Name).ToArray() : null;
            }
        }
        public ProtocolVersion[] SupportedVersions
        {
            get
            {
                var ex = this.Extensions.FirstOrDefault(a => a.Type == ExtensionType.SUPPORTED_VERSIONS);
                return ex != null ? ((Extensions.SupportedVersions)ex).Versions : null;
            }
        }
        public Extensions.KeyShareEntry[] KeyShare
        {
            get
            {
                var ex = this.Extensions.FirstOrDefault(a => a.Type == ExtensionType.KEY_SHARE);
                return ex != null ? ((Extensions.KeyShare)ex).Entries : null;
            }
        }
        public Extensions.ClientOfferedPsks PreSharedKeys
        {
            get
            {
                var ex = this.Extensions.FirstOrDefault(a => a.Type == ExtensionType.PRE_SHARED_KEY);
                return ex != null ? ((Extensions.PreSharedKey)ex).ClientOffered : null;
            }
        }
        public PskKeyExchangeMode[] PskKeyExchangeModes
        {
            get
            {
                var ex = this.Extensions.FirstOrDefault(a => a.Type == ExtensionType.PSK_KEY_EXCHANGE_MODES);
                return ex != null ? ((Extensions.PskKeyExchangeModes)ex).ExchangeModes : null;
            }
        }
        public NamedGroup[] SupportedGroups
        {
            get
            {
                var sg = this.Extensions.FirstOrDefault(a => a.Type == ExtensionType.SUPPORTED_GROUPS);
                return sg != null ? ((Extensions.SupportedGroups)sg).EllipticCurvesGroups : null;
            }
        }
        public SignatureAlgorithm[] SignatureAlgorithms
        {
            get
            {
                var ex = this.Extensions.FirstOrDefault(a => a.Type == ExtensionType.SIGNATURE_ALGORITHMS);
                return ex != null ? ((Extensions.SignatureAlgorithms)ex).HashSignatureAlgorithms : null;
            }
        }
        public ECPointFormat[] EcPointFormats
        {
            get
            {
                var ex = this.Extensions.FirstOrDefault(a => a.Type == ExtensionType.EC_POINTS_FORMATS);
                return ex != null ? ((Extensions.EcPointFormats)ex).PointFormats : null;
            }
        }
        #endregion
    }
}
