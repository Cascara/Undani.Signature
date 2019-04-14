using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.Dynamic;
using System.Net;
using System.Net.Http;
using System.Text;

namespace Undani.Signature.Core.Resource
{
    internal class TemplateCall : Call
    {
        public TemplateCall(IConfiguration configuration, User user) : base(configuration, user) { }

        public bool SignatureGraphicRepresentation(Guid environmentId, string xml)
        {
            string url = Configuration["ApiTemplate"] + "/Excecution/Template/SignatureGraphicRepresentation";

            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("Authorization", "Bearer " + User.Token);

                dynamic formInstanceSign = new { EnviromentId = environmentId, Xml = xml };

                StringContent stringContent = new StringContent(JsonConvert.SerializeObject(formInstanceSign), Encoding.UTF8, "application/json");

                HttpResponseMessage httpResponseMessage = client.PostAsync(url, stringContent).Result;

                if (httpResponseMessage.StatusCode != HttpStatusCode.OK)
                    throw new Exception("There was an error when trying to consume the resource apiform");

                dynamic response = JsonConvert.DeserializeObject<ExpandoObject>(httpResponseMessage.Content.ReadAsStringAsync().Result, new ExpandoObjectConverter());

                return !response.Error;
            }
        }
    }
}
