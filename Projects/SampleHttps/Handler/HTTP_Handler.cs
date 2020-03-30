using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Https.Handler
{
    class HTTP_Handler
    {
        public static byte[] GetResponseData(TcpSession session, string[] requests)
        {
            var data = MakeStatusResponse(session, requests);

            var header = $"HTTP/1.1 200 OK\r\n" +
                         $"Content-Type: text/html\r\n" +
                         $"Content-Length: {data.Length}\r\n" +
                         $"Server: a fake HTTPS server\r\n" +
                         $"Connection: close\r\n" +
                         $"\r\n\r\n";

            return Encoding.ASCII.GetBytes(header).Concat(data).ToArray();
        }

        static byte[] MakeStatusResponse(TcpSession session, string[] rawReq)
        {
            var info = session.TLSContext.GetSessionInfo();

            var sb = new StringBuilder();
            sb.AppendLine("<html>");
            sb.AppendLine("<head>");
            sb.AppendLine("<meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\">");
            sb.AppendLine("<style type=\"text/css\"> table{width:95%;margin:0 auto;} .c1{width:15%} </style>");
            sb.AppendLine("</head>");
            sb.AppendLine("<body>");
            foreach (var title in info.Keys)
            {
                sb.AppendLine($"<h4>{title}</h4>");
                sb.AppendLine("<div><table border='1' cellspacing='0'>");
                foreach (var kv in info[title])
                {
                    sb.AppendLine($"<tr>");
                    sb.AppendLine($"<td class=\"c1\">{kv.Key}</td>");
                    sb.AppendLine($"<td>{kv.Value}</td>");
                    sb.AppendLine($"</tr>");
                }
                sb.AppendLine("</table></div>");
                sb.AppendLine("<hr/>");
            }
            sb.AppendLine("<h4>Raw Request</h4>");
            sb.AppendLine("<pre>");
            foreach (var line in rawReq)
                sb.AppendLine(line);
            sb.AppendLine("</pre>");
            sb.AppendLine("<hr/>");
            sb.AppendLine("</body>");
            sb.AppendLine("</html>");

            return Encoding.UTF8.GetBytes(sb.ToString());
        }
    }
}
