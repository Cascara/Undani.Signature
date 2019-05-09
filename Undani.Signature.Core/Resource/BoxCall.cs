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
                string url = Configuration["ApiBox"] + "/Execution/Box/AddNewTraceabilitySheet?systemName=" + systemName + "&verifyCode=" + codeVerify;

                HttpResponseMessage response = client.GetAsync(url).Result;

                if (response.StatusCode != HttpStatusCode.OK)
                    throw new Exception("It was not possible to add the traceability page in box");

                result = response.Content.ReadAsStreamAsync().Result;
            }

            return result;
        }

        public void Upload(string systemName, string filePath)
        {
            dynamic saasResult;
            using (var client = new HttpClient())
            {
                string url = Configuration["ApiBox"] + "/Excecution/Box/saas?id=" + systemName;

                HttpResponseMessage response = client.GetAsync(url).Result;

                if (response.StatusCode != HttpStatusCode.OK)
                    throw new Exception("It was not possible to connect with saas");

                saasResult = JsonConvert.DeserializeObject<ExpandoObject>(response.Content.ReadAsStringAsync().Result, new ExpandoObjectConverter());
            }

            CloudBlockBlob blob = new CloudBlockBlob(new Uri(saasResult.Url));

            FileStream signed = new FileStream(filePath, FileMode.Open);
            using (signed)
            {
                blob.UploadFromStreamAsync(signed).Wait();
            }
        }
    }
}
