using Microsoft.Extensions.Configuration;
using System;
using System.Net;
using System.Net.Http;
using System.Text;
using Undani.Signature.Core.Infra;

namespace Undani.Signature.Core.Resource
{
    internal class IdentityCall : Call
    {

        public IdentityCall(IConfiguration configuration, User user) : base(configuration, user) { }

        public _UserIdentity CreateUser(Guid ownerId, string givenName, string reference, string password)
        {
            string user = "{\"Email\":\"\",\"UserName\":\"{{Reference}}\",\"Password\":\"{{Password}}\",\"GivenName\":\"{{GivenName}}\",\"FamilyName\":\"\",\"Owners\":[\"{{OwnerId}}\"]}";

            user = user.Replace("{{Reference}}", reference);
            user = user.Replace("{{GivenName}}", givenName);
            user = user.Replace("{{Password}}", password);
            user = user.Replace("{{OwnerId}}", ownerId.ToString());

            using (var client = new HttpClient())
            {
                HttpResponseMessage response;

                string url = Configuration["WebIdentity"] + "/api/AccountService/registry";
                StringContent contentJson = new StringContent(user, Encoding.UTF8, "application/json");
                response = client.PostAsync(url, contentJson).Result;

                if (response.StatusCode != HttpStatusCode.OK)
                    throw new Exception("S904");

                _UserIdentity _userIdentity = Newtonsoft.Json.JsonConvert.DeserializeObject<_UserIdentity>(response.Content.ReadAsStringAsync().Result);
                _userIdentity.OwnerId = ownerId;
                _userIdentity.Reference = reference;

                return _userIdentity;
            }
        }
    }
}
