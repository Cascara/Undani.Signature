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
            var user = new { userId = userId, ownerId = ownerId, userName = userName, givenName = givenName, familyName = familyName, email = email, rfc = rfc, content = content };

            using (var client = new HttpClient())
            {           
                string url = Configuration["ApiTracking"] + "/Execution/User/Create";
                StringContent contentJson = new StringContent(JsonConvert.SerializeObject(user), Encoding.UTF8, "application/json");
                HttpResponseMessage response = client.PostAsync(url, contentJson).Result;

                if (response.StatusCode != HttpStatusCode.OK)
                    throw new Exception("It was not possible to add the traceability page in box");
            }
        }
    }
}
