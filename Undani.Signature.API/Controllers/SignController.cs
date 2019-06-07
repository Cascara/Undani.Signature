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
using Undani.Signature.Core.Infra;

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

        #region Sign
        [HttpPost]
        [Route("Start")]
        public List<SignResult> Start([FromForm]Guid elementInstanceRefId, IFormFile publicKey)
        {
            User user = GetUser(Request);

            if (publicKey == null)
                throw new Exception("Public key no selected");

            List<SignResult> signResults = new List<SignResult>();
            using (MemoryStream memoryStream = new MemoryStream())
            {
                publicKey.CopyTo(memoryStream);
                var publicKeyBytes = memoryStream.ToArray();
                signResults = new SignHelper(_configuration, user, Guid.Empty, publicKeyBytes).Start(elementInstanceRefId);
            }

            return signResults;
        }

        [HttpPost]
        [Route("Text/End")]
        public bool SetSignText([FromForm]Guid elementInstanceRefId, [FromForm] string key, [FromForm] string template, IFormFile publicKey, [FromForm]string digitalSignature)
        {
            User user = GetUser(Request);

            if (publicKey == null)
                throw new Exception("Public key no selected");

            if (string.IsNullOrWhiteSpace(digitalSignature))
                throw new Exception("The digital signature is empty");

            bool result = false;
            using (MemoryStream memoryStream = new MemoryStream())
            {
                publicKey.CopyTo(memoryStream);
                var publicKeyBytes = memoryStream.ToArray();
                result = new SignHelper(_configuration, user, Guid.Empty, publicKeyBytes).SetSignText(elementInstanceRefId, key, template, digitalSignature);
            }

            return result;
        }

        [HttpPost]
        [Route("PDF/End")]
        public bool SetSignPDF([FromForm]Guid elementInstanceRefId, [FromForm] string key, [FromForm] string template, IFormFile publicKey, IFormFile privateKey, [FromForm] string pk, [FromForm]string digitalSignature)
        {
            User user = GetUser(Request);

            if (publicKey == null)
                throw new Exception("Public key no selected");

            if (string.IsNullOrWhiteSpace(digitalSignature))
                throw new Exception("The digital signature is empty");

            var msPublicKey = new MemoryStream();
            publicKey.CopyTo(msPublicKey);

            var msPrivateKey = new MemoryStream();
            privateKey.CopyTo(msPrivateKey);

            bool result = false;
            using (MemoryStream memoryStream = new MemoryStream())
            {
                publicKey.CopyTo(memoryStream);
                var publicKeyBytes = memoryStream.ToArray();
                result = new SignHelper(_configuration, user, Guid.Empty, publicKeyBytes).SetSignPDF(elementInstanceRefId, key, template, msPrivateKey.ToArray(), pk.ToCharArray(), digitalSignature);
            }

            return result;
        }
        #endregion

        #region FormInstance
        [HttpPost]
        [Route("FormInstance/Start")]
        public string FormInstanceStart([FromForm]Guid formInstanceId, [FromForm]Guid environmentId, IFormFile publicKey)
        {
            User user = GetUser(Request);

            if (publicKey == null)
                throw new Exception("Public key no selected");

            string result = "";
            using (MemoryStream memoryStream = new MemoryStream())
            {
                publicKey.CopyTo(memoryStream);
                var publicKeyBytes = memoryStream.ToArray();
                result = new FormInstanceHelper(_configuration, user, environmentId, publicKeyBytes).Start(formInstanceId);
            }

            return result;
        }

        [HttpPost]
        [Route("FormInstance/End")]
        public bool SignFormInstanceEnd([FromForm]Guid formInstanceId, [FromForm]Guid environmentId, IFormFile publicKey, [FromForm]string digitalSignature)
        {
            User user = GetUser(Request);

            if (publicKey == null)
                throw new Exception("Public key no selected");

            if (string.IsNullOrWhiteSpace(digitalSignature))
                throw new Exception("The digital signature is empty");

            bool result = false;
            using (MemoryStream memoryStream = new MemoryStream())
            {
                publicKey.CopyTo(memoryStream);
                var publicKeyBytes = memoryStream.ToArray();
                result = new FormInstanceHelper(_configuration, user, environmentId, publicKeyBytes).End(formInstanceId, digitalSignature);
            }

            return result;
        }
        #endregion

        #region Login
        [HttpPost]
        [Route("Login/Start")]
        public string LoginStart(IFormFile publicKey)
        {
            if (publicKey == null)
                throw new Exception("Public key no selected");

            string result = "";
            using (MemoryStream memoryStream = new MemoryStream())
            {
                publicKey.CopyTo(memoryStream);
                var publicKeyBytes = memoryStream.ToArray();
                result = new LoginHelper(_configuration, null, Guid.Empty, publicKeyBytes).Start();
            }

            return result;
        }

        [HttpPost]
        [Route("Login/End")]
        public _UserLogin LoginEnd([FromForm]Guid ownerId, IFormFile publicKey, [FromForm]string digitalSignature, [FromForm]string content)
        {
            if (publicKey == null)
                throw new Exception("Public key no selected");

            if (string.IsNullOrWhiteSpace(digitalSignature))
                throw new Exception("The digital signature is empty");

            _UserLogin result;
            using (MemoryStream memoryStream = new MemoryStream())
            {
                publicKey.CopyTo(memoryStream);
                var publicKeyBytes = memoryStream.ToArray();
                result = new LoginHelper(_configuration, null, Guid.Empty, publicKeyBytes).End(ownerId, digitalSignature, content);
            }

            return result;
        }
        #endregion

        #region Blob
        [HttpPost]
        [Route("Blob/Start")]
        public string BlobStart([FromForm]string systemNames, [FromForm]Guid environmentId, IFormFile publicKey)
        {
            User user = GetUser(Request);

            if (publicKey == null)
                throw new Exception("Public key no selected");

            string result = "";
            using (MemoryStream memoryStream = new MemoryStream())
            {
                publicKey.CopyTo(memoryStream);
                var publicKeyBytes = memoryStream.ToArray();
                result = new BlobHelper(_configuration, user, Guid.Empty, publicKeyBytes).Start(systemNames);
            }

            return result;
        }

        [HttpPost]
        [Route("Blob/End")]
        public bool SignDocumentEnd([FromForm]Guid environmentId, [FromForm]string systemNames, IFormFile publicKey, IFormFile privateKey, [FromForm] string pk, [FromForm]string digitalSignature)
        {
            User user = GetUser(Request);

            if (publicKey == null)
                throw new Exception("Public key no selected");

            if (string.IsNullOrWhiteSpace(digitalSignature))
                throw new Exception("The digital signature is empty");

            var msPublicKey = new MemoryStream();
            publicKey.CopyTo(msPublicKey);

            var msPrivateKey = new MemoryStream();
            privateKey.CopyTo(msPrivateKey);

            bool result = false;
            using (MemoryStream memoryStream = new MemoryStream())
            {
                publicKey.CopyTo(memoryStream);
                var publicKeyBytes = memoryStream.ToArray();
                result = new BlobHelper(_configuration, user, Guid.Empty, publicKeyBytes).End(systemNames, msPrivateKey.ToArray(), pk.ToCharArray(), digitalSignature);
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
            
            user = new UserHelper(_configuration, user).User;

            return user;
        }
        #endregion
    }
}