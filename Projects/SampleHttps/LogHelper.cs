using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Https
{
    public class LogHelper
    {
        private static object _locker = new object();
        private static Dictionary<string, log4net.ILog> _loggers = new Dictionary<string, log4net.ILog>();

        static log4net.ILog GetLogger(object cls)
        {
            var name = cls.GetType().Name;
            lock(_locker)
            {
                if (!_loggers.ContainsKey(name))
                    _loggers.Add(name, log4net.LogManager.GetLogger(name));
            }
            return _loggers[name];
        }

        public static void Info(object cls, object message)
        {
            var logger = GetLogger(cls);

            logger.Info(message);
        }

        public static void Debug(object cls, object message)
        {
            var logger = GetLogger(cls);

            logger.Debug(message);
        }

        public static void Error(object cls, object message)
        {
            var logger = GetLogger(cls);

            logger.Error(message);
        }
    }
}
