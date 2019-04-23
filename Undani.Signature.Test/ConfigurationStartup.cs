using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using System;
using Newtonsoft.Json;

[assembly: HostingStartup(typeof(Undani.Signature.Test.ConfigurationStartup))]
namespace Undani.Signature.Test
{
    internal class ConfigurationStartup : IHostingStartup
    {
        public void Configure(IWebHostBuilder builder)
        {
            builder.ConfigureAppConfiguration(config =>
            {
                var dict = Undani.Configuration.Load(
                    Environment.GetEnvironmentVariable("CONFIGURATION_ENVIRONMENT"),
                    Environment.GetEnvironmentVariable("CONFIGURATION_SYSTEM")
                    );

                config.AddInMemoryCollection(dict);
            });
        }
    }
}
