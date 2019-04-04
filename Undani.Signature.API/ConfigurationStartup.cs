using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using System;

[assembly: HostingStartup(typeof(Undani.Signature.API.ConfigurationStartup))]
namespace Undani.Signature.API
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
