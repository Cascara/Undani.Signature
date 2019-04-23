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
    }
}
