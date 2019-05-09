using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using Undani.Signature.Core.Infra;

namespace Undani.Signature.Core.Resource
{
    internal class IdentityCall : Call
    {

        public IdentityCall(IConfiguration configuration, User user) : base(configuration, user) { }

        public _UserIdentity CreateUser(Guid ownerId, string givenName, string rfc, string password)
        {
            string user = "{\"Email\":\"\",\"UserName\":\"[RFC]\",\"Password\":\"[Password]\",\"GivenName\":\"[GivenName]\",\"FamilyName\":\"\",\"Owners\":[\"[OwnerId]\"]}";

            user = user.Replace("[RFC]", rfc);
            user = user.Replace("[GivenName]", givenName);
            user = user.Replace("[Password]", password);
            user = user.Replace("[OwnerId]", ownerId.ToString());

            using (var client = new HttpClient())
            {
                HttpResponseMessage response;

                string url = Configuration["WebIdentity"] + "/api/AccountService/registry";
                StringContent contentJson = new StringContent(user, Encoding.UTF8, "application/json");
                response = client.PostAsync(url, contentJson).Result;

                if (response.StatusCode != HttpStatusCode.OK)
                    throw new Exception("It was not possible to create de user");

                _UserIdentity _userIdentity = Newtonsoft.Json.JsonConvert.DeserializeObject<_UserIdentity>(response.Content.ReadAsStringAsync().Result);
                _userIdentity.OwnerId = ownerId;
                _userIdentity.RFC = rfc;

                return _userIdentity;
            }
        }
    }
}
