using NLog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ILogger = NLog.ILogger;


namespace VaultInitializer
{
    public class AuctionCoreLogger
    {
        public static ILogger Logger { get; } = LogManager.GetCurrentClassLogger();
    }
}
