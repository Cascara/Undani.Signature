using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;

namespace Undani.Signature.Core.Resource
{
    internal class TrackingCall : Call
    {
        public TrackingCall(IConfiguration configuration, User user) : base(configuration, user) { }

        public void CreateUser(Guid userId, Guid ownerId, string userName, string givenName, string familyName, string email, string rfc, string content)
        {           
            var user = new { content = content };

            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("Authorization", "Bearer " + User.Token);

                string url = Configuration["ApiTracking"] + "/Execution/User/Create?userId=" + userId.ToString() + "&ownerId=" + ownerId.ToString() + "&userName=" + userName + "&givenName=" + givenName + "&rfc=" + rfc;

                var formParameters = new List<KeyValuePair<string, string>>();
                formParameters.Add(new KeyValuePair<string, string>("content", content));
                var formContent = new FormUrlEncodedContent(formParameters);

                HttpResponseMessage response = client.PostAsync(url, formContent).Result;

                if (response.StatusCode != HttpStatusCode.OK)
                    throw new Exception("It was not possible to add the traceability page in box");
            }
        }

        public ActivityInstanceSignature GetActivityInstanceSignature(Guid activityInstanceRefId)
        {
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("Authorization", User.Token);

                string url = Configuration["ApiTracking"] + "/Execution/ActivityInstance/GetSignature?elementInstanceRefId=" + activityInstanceRefId.ToString();

                var content = client.GetStringAsync(url);

                string json = content.Result;

                return JsonConvert.DeserializeObject<ActivityInstanceSignature>(json);
            }            
        }


        public ActivityInstanceSignature GetActivityInstanceSignatureTemplate(Guid activityInstanceRefId, string template)
        {
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("Authorization", User.Token);

                string url = Configuration["ApiTracking"] + "/Execution/ActivityInstance/GetSignatureTemplate?elementInstanceRefId=" + activityInstanceRefId.ToString() + "&template=" + template;

                var content = client.GetStringAsync(url);

                string json = content.Result;

                return JsonConvert.DeserializeObject<ActivityInstanceSignature>(json);
            }
        }

        public bool SetActivityInstanceDocumentSigned(Guid activityInstanceRefId, string key, DocumentSigned documentSigned)
        {
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("Authorization", User.Token);

                string url = Configuration["ApiTracking"] + "/Execution/ActivityInstance/SetDocumentSigned?elementInstanceRefId=" + activityInstanceRefId.ToString() + "&key=" + key + "&documentSigned=" + JsonConvert.SerializeObject(documentSigned);

                HttpResponseMessage httpResponseMessage = client.GetAsync(url).Result;

                if (httpResponseMessage.StatusCode != HttpStatusCode.OK)
                    throw new Exception("There was an error when trying to set the document signed");

                return true;
            }
        }
    }
}
