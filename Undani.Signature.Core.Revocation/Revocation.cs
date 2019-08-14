using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Undani.Signature.Core
{
    public class Revocation
    {
        private Uri _ocspUrl;
        private String _vaultBaseUrl;
        private string _ocspStoreName;
        private string _issuerStoreName;
        private string _clientId;
        private string _clientSecret;
        private string _fileName;

        public Revocation(string ocspUrl, string vaultBaseUrl, string ocspStoreName, string issuerStoreName, string clientId, string clientSecret)
        {
            _ocspUrl = new Uri(ocspUrl);
            _vaultBaseUrl = vaultBaseUrl;
            _ocspStoreName = ocspStoreName;
            _issuerStoreName = issuerStoreName;
            _clientId = clientId;
            _clientSecret = clientSecret;
        }

        public string FileName { get; set; }

        public string ConnectionString { get; set; }

        public void Validate(byte[] publicKey)
        {
            X509Certificate certificate = new X509CertificateParser().ReadCertificate(publicKey);

            X509Certificate issuerCertificate = GetIssuerCertificate();

            X509Certificate ocspCertificate = GetOcspCertificate();

            ValidateOCSP(ocspCertificate, issuerCertificate, certificate);
        }

        private X509Certificate GetIssuerCertificate()
        {
            return GetKeyVaultCertificate(_issuerStoreName);
        }

        private X509Certificate GetOcspCertificate()
        {
            return GetKeyVaultCertificate(_ocspStoreName);
        }

        private X509Certificate GetKeyVaultCertificate(string vaultStoreName)
        {
            var kv = new KeyVaultClient(async (authority, resource, scope) =>
            {
                var authContext = new AuthenticationContext(authority);
                var clientCred = new ClientCredential(_clientId, _clientSecret);
                var result = await authContext.AcquireTokenAsync(resource, clientCred);

                if (result == null)
                    throw new Exception("S512");

                return result.AccessToken;
            });

            var certificateSecret = kv.GetSecretAsync(_vaultBaseUrl, vaultStoreName);
            
            var privateKeyBytes = Convert.FromBase64String(certificateSecret.Result.Value);

            X509Certificate certificate = new X509CertificateParser().ReadCertificate(privateKeyBytes);

            return certificate;
        }

        private void ValidateOCSP(X509Certificate ocspCertificate, X509Certificate issuerCertificate, X509Certificate certificate)
        {
            var serialNumber = certificate.SerialNumber;

            var ocspReq = GenerateOcspRequest(issuerCertificate, serialNumber);

            var httpWebResponse = QueryOcspResponse(_ocspUrl, ocspReq);

            using (var responseStream = httpWebResponse.GetResponseStream())
            {
                var ocspResp = new OcspResp(responseStream);

                int status = ocspResp.Status;

                if (status != OcspRespStatus.Successful)
                    throw new Exception("S513-1 (" + ocspResp.Status + ")");

                var basicOcspResp = (BasicOcspResp)ocspResp.GetResponseObject();

                if (basicOcspResp == null)
                    throw new Exception("S513-2");

                var singleResps = basicOcspResp.Responses;

                if (singleResps == null || singleResps.Length == 0)
                    throw new Exception("S513-3");

                bool validResponse = basicOcspResp.Verify(ocspCertificate.GetPublicKey());

                if (!validResponse)
                    throw new Exception("S513-4");

                var certificateStatus = singleResps[0].GetCertStatus();

                var certificateId = singleResps[0].GetCertID();
                
                bool certificateCompare = certificateId != null && certificateId.SerialNumber.CompareTo(serialNumber) == 0;

                bool valid = certificateStatus == null && certificateCompare;

                if (!valid)
                    throw new Exception("S516");
            }
        }

        private OcspReq GenerateOcspRequest(X509Certificate issuer, BigInteger certificateSerialNumber)
        {
            var ocspRequestGenerator = new Org.BouncyCastle.Ocsp.OcspReqGenerator();

            ocspRequestGenerator.AddRequest(new Org.BouncyCastle.Ocsp.CertificateID(Org.BouncyCastle.Ocsp.CertificateID.HashSha1, issuer, certificateSerialNumber));

            var ocspRequest = ocspRequestGenerator.Generate();

            return ocspRequest;
        }

        private HttpWebResponse QueryOcspResponse(Uri ocspUrl, OcspReq ocspRequest)
        {
            var ocspRequestBytes = ocspRequest.GetEncoded();

            var httpWebRequest = (HttpWebRequest)HttpWebRequest.Create(ocspUrl);

            httpWebRequest.Method = "POST";

            httpWebRequest.ContentType = "application/ocsp-request";

            httpWebRequest.Accept = "application/ocsp-response";

            httpWebRequest.ContentLength = ocspRequestBytes.Length;

            var requestStream = httpWebRequest.GetRequestStream();

            requestStream.Write(ocspRequestBytes, 0, ocspRequestBytes.Length);

            requestStream.Flush();

            var httpWebResponse = (HttpWebResponse)httpWebRequest.GetResponse();

            if (httpWebResponse.StatusCode != HttpStatusCode.OK)
                throw new Exception("S514");

            return httpWebResponse;
        }

        private void SetLog(System.Security.Cryptography.X509Certificates.X509Certificate cryptographycertificate, string serialNumber, string certStatus, string certId)
        {
            if (ConnectionString != string.Empty)
            {
                using (SqlConnection cn = new SqlConnection(ConnectionString))
                {
                    cn.Open();

                    using (SqlCommand cmd = new SqlCommand("usp_Set_Ocsp", cn) { CommandType = CommandType.StoredProcedure })
                    {
                        cmd.Parameters.Add(new SqlParameter("@FileName", SqlDbType.VarChar, 250) { Value = FileName });
                        cmd.Parameters.Add(new SqlParameter("@BouncyCastle_SerialNumber", SqlDbType.VarChar, 250) { Value = serialNumber });
                        cmd.Parameters.Add(new SqlParameter("@Cryptography_SerialNumber", SqlDbType.VarChar, 250) { Value = cryptographycertificate.GetSerialNumberString() });
                        cmd.Parameters.Add(new SqlParameter("@Issuer", SqlDbType.VarChar, 1000) { Value = cryptographycertificate.Issuer });
                        cmd.Parameters.Add(new SqlParameter("@Subject", SqlDbType.VarChar, 1000) { Value = cryptographycertificate.Subject });
                        cmd.Parameters.Add(new SqlParameter("@CertStatus", SqlDbType.VarChar, 500) { Value = certStatus });
                        cmd.Parameters.Add(new SqlParameter("@CertId", SqlDbType.VarChar, 500) { Value = certId });

                        cmd.ExecuteNonQuery();
                    }

                }
            }

        }
    }
}
