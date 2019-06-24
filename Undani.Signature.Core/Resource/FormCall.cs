using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Net;
using System.Net.Http;
using System.Text;

namespace Undani.Signature.Core.Resource
{
    internal class FormCall : Call
    {
        public FormCall(IConfiguration configuration, User user) : base(configuration, user) { }

        public JObject GetJsonFormInstance(Guid formInstanceId)
        {
            string url = Configuration["ApiForm"] + "/Execution/GetJsonInstance?instanceId=" + formInstanceId;

            string json;
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("Authorization", User.Token);

                HttpResponseMessage response = client.GetAsync(url).Result;

                if (response.StatusCode != HttpStatusCode.OK)
                    throw new Exception("S903");

                json = response.Content.ReadAsStringAsync().Result;
            }            
                       
            return JObject.Parse(json);
        }

        public bool UpdateSign(Guid formInstanceId, string xml)
        {
            string url = Configuration["ApiForm"] + "/Execution/Form/updateSign";

            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("Authorization", User.Token);

                dynamic formInstanceSign = new { Instance = formInstanceId, Sign = xml };

                StringContent stringContent = new StringContent(JsonConvert.SerializeObject(formInstanceSign), Encoding.UTF8, "application/json");

                HttpResponseMessage response = client.PostAsync(url, stringContent).Result;

                if (response.StatusCode != HttpStatusCode.OK)
                    throw new Exception("S903");

                return bool.Parse(response.Content.ReadAsStringAsync().Result);
            }
        }
    }
}
