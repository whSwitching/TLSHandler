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
            var setup = svr.Setup();
            if (!setup)
            {
                Console.WriteLine("Setup Failed, something is wrong. press any key to exit");
                Console.ReadKey();
                return;
            }
            var start = svr.Start();
            if (!start)
            {
                Console.WriteLine("Start Failed, something is wrong. press any key to exit");
                Console.ReadKey();
                return;
            }
            else
                Console.WriteLine($"Service Started, https://{svr.IP}:{svr.Port}");

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
