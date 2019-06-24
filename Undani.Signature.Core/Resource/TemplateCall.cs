using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Net;
using System.Net.Http;
using System.Text;

namespace Undani.Signature.Core.Resource
{
    internal class TemplateCall : Call
    {
        public TemplateCall(IConfiguration configuration, User user) : base(configuration, user) { }

        public List<ActivityInstanceDocumentSigned> SignatureGraphicRepresentation(Guid systemName, string originalName, Guid environmentId, string template, string xml)
        {
            string url = Configuration["ApiTemplate"] + "/Excecution/Template/SignatureGraphicRepresentation";

            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("Authorization", User.Token);

                string jsonFormInstanceSign = JsonConvert.SerializeObject(new { SystemName = systemName, OriginalName = originalName, DocumentType = template, Xml = xml });
                
                StringContent stringContent = new StringContent(jsonFormInstanceSign, Encoding.UTF8, "application/json");

                HttpResponseMessage httpResponseMessage = client.PostAsync(url, stringContent).Result;

                if (httpResponseMessage.StatusCode != HttpStatusCode.OK)
                    throw new Exception("S905");

                string json = httpResponseMessage.Content.ReadAsStringAsync().Result;

                List<ActivityInstanceDocumentSigned> response = JsonConvert.DeserializeObject<List<ActivityInstanceDocumentSigned>>(json);

                return response;
            }
        }
    }
}
