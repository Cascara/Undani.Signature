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

        public string GetJsonFormInstance(Guid formInstanceId)
        {
            string url = Configuration["ApiForm"] + "/Execution/GetJsonInstance?instanceId=" + formInstanceId;

            string json;
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("Authorization", "Bearer " + User.Token);

                HttpResponseMessage response = client.GetAsync(url).Result;

                if (response.StatusCode != HttpStatusCode.OK)
                    throw new Exception("There was an error when trying to consume the resource apiform");

                json = response.Content.ReadAsStringAsync().Result;
            }

            dynamic oJson = JsonConvert.DeserializeObject<ExpandoObject>(json, new ExpandoObjectConverter());
                       
            return JsonConvert.SerializeObject(oJson.Integration);
        }

        public bool UpdateSign(Guid formInstanceId, string xml)
        {
            string url = Configuration["ApiForm"] + "/Execution/Form/updateSign";

            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("Authorization", "Bearer " + User.Token);

                dynamic formInstanceSign = new { Instance = formInstanceId, Sign = xml };

                StringContent stringContent = new StringContent(JsonConvert.SerializeObject(formInstanceSign), Encoding.UTF8, "application/json");

                HttpResponseMessage response = client.PostAsync(url, stringContent).Result;

                if (response.StatusCode != HttpStatusCode.OK)
                    throw new Exception("There was an error when trying to consume the resource apiform");

                return bool.Parse(response.Content.ReadAsStringAsync().Result);
            }
        }
    }
}
