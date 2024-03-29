﻿using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System;
using System.IO;
using System.Linq;
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
        public Result Start([FromForm]Guid procedureInstanceRefId, [FromForm]Guid elementInstanceRefId, [FromForm]string templates, IFormFile publicKey)
        {
            Result result = new Result();
            try
            {
                User user = GetUser(Request);

                if (publicKey == null)
                    throw new Exception("S501");

                if (templates == null)
                    templates = "";

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    publicKey.CopyTo(memoryStream);
                    var publicKeyBytes = memoryStream.ToArray();

                    result.Value = new SignHelper(_configuration, user, Guid.Empty, publicKeyBytes).Start(procedureInstanceRefId, elementInstanceRefId, templates.Split(',').ToList());
                }
            }
            catch (Exception ex)
            {
                result.Value = null;
                result.Error = ex.Message;
            }

            return result;
        }

        [HttpPost]
        [Route("Text/End")]
        public Result SetSignText([FromForm]Guid procedureInstanceRefId, [FromForm]Guid elementInstanceRefId, [FromForm] string key, [FromForm] string template, [FromForm] string represented, IFormFile publicKey, [FromForm]string digitalSignature)
        {
            Result result = new Result();
            try
            {
                User user = GetUser(Request);

                if (publicKey == null)
                    throw new Exception("S501");

                if (string.IsNullOrWhiteSpace(digitalSignature))
                    throw new Exception("S502");

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    publicKey.CopyTo(memoryStream);
                    var publicKeyBytes = memoryStream.ToArray();
                    result.Value = new SignHelper(_configuration, user, Guid.Empty, publicKeyBytes).SetSignText(procedureInstanceRefId, elementInstanceRefId, key, template, represented, digitalSignature);
                }

            }
            catch (Exception ex)
            {
                result.Value = null;
                result.Error = ex.Message;
            }

            return result;
        }

        [HttpPost]
        [Route("PDF/End")]
        public Result SetSignPDF([FromForm]Guid procedureInstanceRefId, [FromForm]Guid elementInstanceRefId, [FromForm] string key, [FromForm] string template, [FromForm] string represented, IFormFile publicKey, IFormFile privateKey, [FromForm] string pk, [FromForm]string digitalSignature)
        {
            Result result = new Result();
            try
            {
                User user = GetUser(Request);

                if (publicKey == null)
                    throw new Exception("S501");

                if (string.IsNullOrWhiteSpace(digitalSignature))
                    throw new Exception("S502");

                var msPublicKey = new MemoryStream();
                publicKey.CopyTo(msPublicKey);

                var msPrivateKey = new MemoryStream();
                privateKey.CopyTo(msPrivateKey);

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    publicKey.CopyTo(memoryStream);
                    var publicKeyBytes = memoryStream.ToArray();
                    result.Value = new SignHelper(_configuration, user, Guid.Empty, publicKeyBytes).SetSignPDF(procedureInstanceRefId, elementInstanceRefId, key, template, represented, msPrivateKey.ToArray(), pk.ToCharArray(), digitalSignature);
                }

            }
            catch (Exception ex)
            {
                result.Value = null;
                result.Error = ex.Message;
            }

            return result;
        }

        #endregion

        #region Login
        [HttpPost]
        [Route("Login/Start")]
        public Result LoginStart(IFormFile publicKey)
        {

            Result result = new Result();
            try
            {
                if (publicKey == null)
                    throw new Exception("S501");
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    publicKey.CopyTo(memoryStream);
                    var publicKeyBytes = memoryStream.ToArray();
                    result.Value = new LoginHelper(_configuration, null, Guid.Empty, publicKeyBytes).Start();
                }

            }
            catch (Exception ex)
            {
                result.Value = null;
                result.Error = ex.Message;
            }

            return result;
        }

        [HttpPost]
        [Route("Login/End")]
        public Result LoginEnd([FromForm]Guid ownerId, IFormFile publicKey, [FromForm]string digitalSignature, [FromForm]string content)
        {
            Result result = new Result();
            try
            {
                if (publicKey == null)
                    throw new Exception("S501");

                if (string.IsNullOrWhiteSpace(digitalSignature))
                    throw new Exception("S502");

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    publicKey.CopyTo(memoryStream);
                    var publicKeyBytes = memoryStream.ToArray();
                    result.Value = new LoginHelper(_configuration, null, Guid.Empty, publicKeyBytes).End(ownerId, digitalSignature, content);
                }
            }
            catch (Exception ex)
            {
                result.Value = null;
                result.Error = ex.Message;
            }

            return result;
        }

        #endregion

        #region User
        [HttpPost]
        [Route("User/ContentExists")]
        public bool LoginContentExists([FromForm]Guid ownerId, [FromForm]string content)
        {
            return new UserHelper(_configuration, null).ContentExists(ownerId, content);
        }
        #endregion

        #region Document
        [Route("Document/FormInstance/GetContent")]
        public string GetDocumentContent(string key, Guid formInstanceId)
        {
            User user = GetUser(Request);
            return new DocumentHelper(_configuration, user).GetContent(key, formInstanceId);
        }
        #endregion

        #region OCSP
        [HttpPost]
        [Route("OCSP/Validate")]
        public bool OCSPValidate(IFormFile publicKey)
        {
            if (publicKey == null)
                throw new Exception("S501");

            using (MemoryStream memoryStream = new MemoryStream())
            {
                publicKey.CopyTo(memoryStream);
                var publicKeyBytes = memoryStream.ToArray();

                Revocation revocation = new Revocation(_configuration["DataOcspUri"], _configuration["ApiKeyVault"], _configuration["DataOcspStoreName"], _configuration["DataOcspIssuerStoreName"], _configuration["DataOcspClientId"], _configuration["DataOcspClientSecret"]);
                revocation.FileName = publicKey.FileName;
                revocation.ConnectionString = _configuration["CnDbSignature"];

                revocation.Validate(publicKeyBytes);
            }

            return true;
        }
        #endregion

        #region Tools   
        private User GetUser(HttpRequest request)
        {
            User user = new User();
            Payload payload = new Payload();
            if (!request.Headers.ContainsKey("Authorization"))
                throw new Exception("S503");

            var authHeader = request.Headers["Authorization"][0];
            if (authHeader.StartsWith("Bearer "))
            {
                var token = authHeader.Substring("Bearer ".Length);

                try
                {
                    payload = JWToken.TokenDecode(token);
                    user = new User() { Id = Guid.Parse(payload.UserId), Name = payload.UserName, Token = authHeader };
                }
                catch (Exception)
                {
                    throw new Exception("S503");
                }
            }

            if (user.Id == Guid.Empty)
                throw new Exception("S503");

            user = new UserHelper(_configuration, user).User;

            return user;
        }
        #endregion
    }
}