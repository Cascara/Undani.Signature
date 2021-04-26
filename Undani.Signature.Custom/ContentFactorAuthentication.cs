using Newtonsoft.Json.Linq;
using System;
using System.Net.Http;

namespace Undani.Signature.Custom
{
    public class ContentFactorAuthentication
    {
        public ValidateContentFactorAuthentication(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public bool Validate (JToken jtContent)
        {
            using (var client = new HttpClient())
            {
                string url = "https://apifonacotintegrationprod.azurewebsites.net/Integration/ValidaDatosCT?reg=" + reader.GetString(1) + "&rfc=" + reader.GetString(2);

                HttpResponseMessage response = client.GetAsync(url).Result;

                if (response.StatusCode != HttpStatusCode.OK)
                    Console.WriteLine(reader.GetString(1));

                string json = response.Content.ReadAsStringAsync().Result;

                Console.WriteLine(json);

                SaidSuccess(reader.GetGuid(3), json.Replace("clienteIDField", "folioClienteField"), "{}");
            }
        }
    }
}
