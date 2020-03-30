using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Https
{
    class Program
    {
        static void Main(string[] args)
        {
            log4net.Config.XmlConfigurator.Configure();

            var svr = new Https.HttpServer();
            svr.Setup();
            svr.Start();

            Console.WriteLine("Press Q to Quit");
            var ch = Console.ReadKey();
            while (ch.Key != ConsoleKey.Q)
            {
                Thread.Sleep(100);
                ch = Console.ReadKey();
            }
            svr.Stop();
        }
    }
}
