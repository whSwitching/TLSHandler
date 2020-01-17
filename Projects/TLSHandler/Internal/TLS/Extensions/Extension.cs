using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TLSHandler.Enums;

namespace TLSHandler.Internal.TLS.Extensions
{
    public abstract class Extension : PacketData
    {
        public abstract ExtensionType Type { get; }

        protected Extension(byte[] data)
        {
            Data = data;
        }

        public static Extension[] Extract(byte[] extensionsBytes)
        {
            List<Extension> extensions = new List<Extension>();

            byte[] buffer;
            int index = 0;
            while (index < extensionsBytes.Length)
            {
                // read type
                var _type = Utils.ToUInt16(extensionsBytes, index);
                index += 2;

                // read length
                int length = Utils.ToUInt16(extensionsBytes, index);
                index += 2;

                // skip over payload
                index += length;

                // if still in range, it means we have an extension
                if (index <= extensionsBytes.Length)
                {
                    buffer = new byte[length + 4];
                    Buffer.BlockCopy(extensionsBytes, index - length - 4, buffer, 0, buffer.Length);

                    if (Enum.IsDefined(typeof(ExtensionType), (ExtensionType)_type))
                    {
                        switch (_type)
                        {
                            case (ushort)ExtensionType.EXTENDED_MASTER_SECRET:
                                extensions.Add(new ExtendedMasterSecret(buffer));
                                break;
                            case (ushort)ExtensionType.RENEGOTIATION_INFO:
                                extensions.Add(new RenegotiationInfo(buffer));
                                break;
                            case (ushort)ExtensionType.EC_POINTS_FORMATS:
                                extensions.Add(new EcPointFormats(buffer));
                                break;
                            case (ushort)ExtensionType.KEY_SHARE:
                                extensions.Add(new KeyShare(buffer));
                                break;
                            case (ushort)ExtensionType.PRE_SHARED_KEY:
                                extensions.Add(new PreSharedKey(buffer));
                                break;
                            case (ushort)ExtensionType.PSK_KEY_EXCHANGE_MODES:
                                extensions.Add(new PskKeyExchangeModes(buffer));
                                break;
                            case (ushort)ExtensionType.SERVER_NAME:
                                extensions.Add(new ServerName(buffer));
                                break;
                            case (ushort)ExtensionType.SIGNATURE_ALGORITHMS:
                                extensions.Add(new SignatureAlgorithms(buffer));
                                break;
                            case (ushort)ExtensionType.SIGNATURE_ALGORITHMS_CERT:
                                extensions.Add(new SignatureAlgorithmsCert(buffer));
                                break;
                            case (ushort)ExtensionType.SUPPORTED_GROUPS:
                                extensions.Add(new SupportedGroups(buffer));
                                break;
                            case (ushort)ExtensionType.SUPPORTED_VERSIONS:
                                extensions.Add(new SupportedVersions(buffer));
                                break;
                        }
                    }
                }
            }

            return extensions.ToArray();
        }

        public static ushort GetLength(Extension[] extensions)
        {
            if (extensions == null || extensions.Length == 0)
                return 0;

            int total = 0;
            for (int i = 0; i < extensions.Length; i++)
            {
                total += extensions[i].Data.Length;
            }
            return (ushort)total;
        }
    }
}
