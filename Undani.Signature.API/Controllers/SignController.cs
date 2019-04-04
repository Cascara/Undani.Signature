using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Undani.JWT;
using Undani.Signature.Core;

namespace Undani.Signature.API.Controllers
{
    [Produces("application/json")]
    [Route("Sign")]
    public class SignController : Controller
    {
        private IConfiguration _configuration;

        public SignController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        #region FormInstance
        [HttpPost]
        [Route("FormInstance/Start")]
        public _Result FormInstanceStart([FromForm]Guid formInstanceId, [FromForm]Guid environmentId, IFormFile publicKey)
        {
            User user = GetUser(Request);

            if (publicKey == null)
                return new _Result() { Error = "Public key no selected" };

            _Result result;
            using (MemoryStream memoryStream = new MemoryStream())
            {
                publicKey.CopyTo(memoryStream);
                var publicKeyBytes = memoryStream.ToArray();
                result = new FormInstanceHelper(_configuration, user, environmentId, publicKeyBytes).StartSignature(formInstanceId);
            }

            return result;
        }
        #endregion

        #region Tools   
        private User GetUser(HttpRequest request)
        {
            User user = new User();
            Payload payload = new Payload();
            if (!request.Headers.ContainsKey("Authorization"))
                throw new Exception("The access is invalid");

            var authHeader = request.Headers["Authorization"][0];
            if (authHeader.StartsWith("Bearer "))
            {
                var token = authHeader.Substring("Bearer ".Length);

                try
                {
                    payload = JWToken.TokenDecode(token);
                    user = new User() { Id = Guid.Parse(payload.UserId), Name = payload.UserName, Token = authHeader };
                }
                catch (Exception e)
                {
                    throw new Exception("The access is invalid");
                }
            }

            if (user.Id == Guid.Empty)
                throw new Exception("The access is invalid");

            return user;
        }
        #endregion
    }
}
