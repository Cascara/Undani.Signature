using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.Collections.Generic;
using System.Data;
using Microsoft.Data.SqlClient;
using System.Dynamic;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Undani.JWT;
using Undani.Signature.Core.Resource;

namespace Undani.Signature.Core
{
    public abstract class Certificate
    {
        private Guid _environmentId;
        private string _number;
        private string _content;
        private string _error = string.Empty;
        private string _populationUniqueIdentifier = "";
        private string _reference;

        public Certificate(IConfiguration configuration, User user, Guid environmentId, byte[] publicKey)
        {
            Configuration = configuration;

            if (user != null)
                User = user;
            else
                User = GetAnonymousUser();

            _environmentId = environmentId;

            PublicKey = publicKey;

            X509PublicKey = new X509Certificate(PublicKey);

            SetCertificateProperties();
        }

        public IConfiguration Configuration { get; }

        public User User { get; }

        public Guid EnvironmentId
        {
            get { return _environmentId; }
        }

        public byte[] PublicKey { get; }

        public X509Certificate X509PublicKey { get; }

        public string Reference
        {
            get {
                if (_reference.Contains("/"))
                {
                    if (_reference == "AAA010101AAA / HEGT7610034S2")
                    {
                        return _reference.Substring(_reference.IndexOf("/") + 1).Trim().ToUpper();
                    }
                    else
                    {
                        return _reference.Substring(0, _reference.IndexOf("/")-1).Trim().ToUpper();
                    }
                    
                }
                else
                    return _reference.ToUpper();
            }
        }

        public string PopulationUniqueIdentifier
        {
            get {
                if (_populationUniqueIdentifier.Contains("/"))
                {
                    return _populationUniqueIdentifier.Replace("/", "").Trim().Replace("\"", "").Trim();
                }
                else
                    return _populationUniqueIdentifier;
            }
        }

        public string Name { get; private set; }

        public DateTime BeginningDate { get; private set; }

        public DateTime ExpirationDate { get; private set; }

        public DateTime DateTimeNow { get; private set; }

        public string SerialNumber { get; private set; }

        public string CertifyingRegistrationAuthority { get; private set; }

        public string CertifyingAuthority { get; private set; }

        private void SetCertificateProperties()
        {
            string[] attributes = X509PublicKey.Subject.Split(',');

            Dictionary<string, string> result = new Dictionary<string, string>();

            string[] values;
            foreach (string attribute in attributes)
            {
                values = attribute.Split('=');
                result.Add(values[0].Trim(), values[1].Trim());
            }

            if (result.Count == 0)
                throw new Exception("S504");


            _reference = result["OID.2.5.4.45"];
            if (Reference.Length != 13 && Reference.Length != 12)
                throw new Exception("S505");

            if (Reference.Length == 13)
            {
                _populationUniqueIdentifier = result["SERIALNUMBER"];
                if (PopulationUniqueIdentifier.Length != 18)
                    throw new Exception("S506");
            }

            Name = result["O"];
            if (Name.Length == 0)
                throw new Exception("S507");

            BeginningDate = DateTime.Parse(X509PublicKey.GetEffectiveDateString());

            ExpirationDate = DateTime.Parse(X509PublicKey.GetExpirationDateString());

            DateTimeNow = GetDateTimeNow();

            if (ExpirationDate < DateTimeNow)
                throw new Exception("S508");

            SerialNumber = GetSerialNumber();

            SetCertifyingAuthorities(); 

        }

        private DateTime GetDateTimeNow()
        {
            using (SqlConnection cn = new SqlConnection(Configuration["CnDbSignature"]))
            {
                cn.Open();

                using (SqlCommand cmd = new SqlCommand("usp_Get_DateTimeNow", cn))
                {
                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.Parameters.Add(new SqlParameter("@DateTime", SqlDbType.DateTime) { Direction = ParameterDirection.Output });

                    cmd.ExecuteNonQuery();

                    return (DateTime)cmd.Parameters["@DateTime"].Value;
                }

            }
        }

        private string GetSerialNumber()
        {
            string result = "";

            string publicKeySerialNumber = X509PublicKey.GetSerialNumberString();

            for (int i = 0; i < publicKeySerialNumber.Length; i = i + 2)
            {
                result = publicKeySerialNumber.Substring(i, 2) + result;
            }

            return result;
        }

        private void SetCertifyingAuthorities()
        {
            if (SerialNumber == "")
                throw new Exception("S515");

            string result = "";

            string publicKeySerialNumber = SerialNumber;

            char[] aPublicKeySerialNumber = publicKeySerialNumber.ToCharArray();

            bool flag = false;

            foreach (char val in aPublicKeySerialNumber)
            {
                if (flag)
                {
                    result += val;
                    flag = false;
                }
                else
                    flag = true;
            }

            CertifyingRegistrationAuthority = result.Substring(0, 6);

            CertifyingAuthority = result.Substring(6, 6);
        }


        public void ValidateRevocation()
        {
            if (int.Parse(Environment.GetEnvironmentVariable("OCSP_ON")) == 1)
            {
                Revocation revocation = new Revocation(Configuration["DataOcspUri"], Configuration["ApiKeyVault"], Configuration["DataOcspStoreName"] + int.Parse(CertifyingAuthority).ToString(), Configuration["DataOcspIssuerStoreName"] + CertifyingAuthority.ToString(), Configuration["DataOcspClientId"], Configuration["DataOcspClientSecret"]);
                revocation.Validate(PublicKey);
            }
        }

        public byte[] GetHash(string text)
        {
            SHA256Managed sha256 = new SHA256Managed();

            UnicodeEncoding encoding = new UnicodeEncoding();

            byte[] data = encoding.GetBytes(text);

            byte[] hash = sha256.ComputeHash(data);

            return hash;
        }

        public bool ValidateSeal(string content, string digitalSignature)
        {
            X509Certificate2 cert = new X509Certificate2(PublicKey);

            RSA csp = (RSA)cert.PublicKey.Key;

            byte[] hash = GetHash(content);

            bool esValida = csp.VerifyHash(hash, Convert.FromBase64String(digitalSignature), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            return esValida;
        }

        public string GetPKCS7()
        {
            X509Certificate2Collection collection = new X509Certificate2Collection();

            collection.Add(new X509Certificate2(PublicKey));

            StringBuilder builder = new StringBuilder();
            builder.Append("-----BEGIN PKCS7-----");
            builder.Append(
                Convert.ToBase64String(collection.Export(X509ContentType.Pkcs7)));
            builder.Append("-----END PKCS7-----");

            return builder.ToString();
        }

        public string PublicKeySerialNumber(string publicKeySerialNumber)
        {
            string result = "";

            char[] aPublicKeySerialNumber = publicKeySerialNumber.ToCharArray();

            bool flag = false;

            foreach (char val in aPublicKeySerialNumber)
            {
                if (flag)
                {
                    result += val;
                    flag = false;
                }
                else
                {
                    flag = true;
                }
            }

            return result;
        }

        public string GetCrc32(string text)
        {
            Crc32 crc32 = new Crc32();

            String hash = String.Empty;

            foreach (byte b in crc32.ComputeHash(Encoding.ASCII.GetBytes(text))) hash += b.ToString("x2").ToLower();

            return hash.ToUpper();
        }

        private User GetAnonymousUser()
        {

            dynamic userAnonymous = JsonConvert.DeserializeObject<ExpandoObject>(Configuration["DataAnonymous"], new ExpandoObjectConverter());

            var claims = new List<Claim>();

            claims.Add(new Claim(ClaimTypes.Name, userAnonymous.Name));
            claims.Add(new Claim(ClaimTypes.NameIdentifier, userAnonymous.NameIdentifier));
            claims.Add(new Claim(ClaimTypes.Email, userAnonymous.Email));
            claims.Add(new Claim(ClaimTypes.GroupSid, userAnonymous.Email));

            var _Identity = new ClaimsIdentity(claims, "Basic");

            return new User() { Id = Guid.Parse(userAnonymous.NameIdentifier), Name = userAnonymous.Name, Token = "Bearer " + JWToken.Token(_Identity) };

        }

        public void ValidateSignatory(string reference = "")
        {
            if (reference != "")
            {
                if (reference.ToUpper() != Reference)
                    throw new Exception("S509-2 " + reference.ToUpper() + " ≠ " + Reference);
            }
            else
            {
                if (User.Reference != Reference)
                    throw new Exception("S509-1 " + User.Reference + " ≠ " + Reference);
            }
        }
    }
}
