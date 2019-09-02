using Microsoft.Extensions.Configuration;
using Microsoft.WindowsAzure.Storage.Blob;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.Collections.Generic;
using System.Dynamic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;

namespace Undani.Signature.Core.Resource
{
    class BoxCall : Call
    {
        public BoxCall(IConfiguration configuration, User user) : base(configuration, user) { }

        public Stream DownloadWithTraceabilitySheet(string systemName, string codeVerify)
        {
            Stream result;
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("Authorization", User.Token);

                string url = Configuration["ApiBox"] + "/Execution/Box/AddNewTraceabilitySheet?systemName=" + systemName + "&verifyCode=" + codeVerify;

                HttpResponseMessage response = client.GetAsync(url).Result;

                if (response.StatusCode != HttpStatusCode.OK)
                    throw new Exception("S901");

                result = response.Content.ReadAsStreamAsync().Result;
            }

            return result;
        }

        public void Upload(string systemName, string filePath)
        {
            dynamic saasResult;
            using (var client = new HttpClient())
            {
                string url = Configuration["ApiBox"] + "/Execution/Box/saas?id=" + systemName;

                HttpResponseMessage response = client.GetAsync(url).Result;

                if (response.StatusCode != HttpStatusCode.OK)
                    throw new Exception("S902");

                string json = response.Content.ReadAsStringAsync().Result;

                saasResult = JsonConvert.DeserializeObject<ExpandoObject>(json, new ExpandoObjectConverter());
            }

            CloudBlockBlob blob = new CloudBlockBlob(new Uri(saasResult.url));

            FileStream signed = new FileStream(filePath, FileMode.Open);
            using (signed)
            {
                blob.UploadFromStreamAsync(signed).Wait();
            }
        }
    }
}
