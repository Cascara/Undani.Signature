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
                client.DefaultRequestHeaders.Add("Authorization", User.Token);

                string url = Configuration["ApiTracking"] + "/Execution/User/Create?userId=" + userId.ToString() + "&ownerId=" + ownerId.ToString() + "&userName=" + userName + "&givenName=" + givenName + "&rfc=" + rfc;

                var formParameters = new List<KeyValuePair<string, string>>();
                formParameters.Add(new KeyValuePair<string, string>("content", content));
                var formContent = new FormUrlEncodedContent(formParameters);

                HttpResponseMessage response = client.PostAsync(url, formContent).Result;

                if (response.StatusCode != HttpStatusCode.OK)
                    throw new Exception("S906-1");
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

        public bool SetActivityInstanceDocumentsSigned(Guid activityInstanceRefId, string key, List<ActivityInstanceDocumentSigned> activityInstanceDocumentsSigned)
        {
            string url = Configuration["ApiTracking"] + "/Execution/ActivityInstance/SetDocumentSigned?elementInstanceRefId=" + activityInstanceRefId.ToString() + "&key=" + key;

            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("Authorization", User.Token);
                
                StringContent stringContent = new StringContent(JsonConvert.SerializeObject(activityInstanceDocumentsSigned), Encoding.UTF8, "application/json");

                HttpResponseMessage httpResponseMessage = client.PostAsync(url, stringContent).Result;

                if (httpResponseMessage.StatusCode != HttpStatusCode.OK)
                    throw new Exception("S906-4");
                
                return true;
            }
        }

        public bool SetProcedureInstanceDocumentsSigned(Guid procedureInstanceRefId, string key, List<ActivityInstanceDocumentSigned> activityInstanceDocumentsSigned)
        {
            string url = Configuration["ApiTracking"] + "/Execution/ProcedureInstance/SetDocumentSigned?procedureInstanceRefId=" + procedureInstanceRefId.ToString() + "&key=" + key;

            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("Authorization", User.Token);

                StringContent stringContent = new StringContent(JsonConvert.SerializeObject(activityInstanceDocumentsSigned), Encoding.UTF8, "application/json");

                HttpResponseMessage httpResponseMessage = client.PostAsync(url, stringContent).Result;

                if (httpResponseMessage.StatusCode != HttpStatusCode.OK)
                    throw new Exception("S906-5");

                return true;
            }
        }
    }
}
