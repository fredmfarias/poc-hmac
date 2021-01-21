﻿using Newtonsoft.Json;
using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace PocHmacClient
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("Calling the back-end API");

            var url = "http://localhost:5000/" + "api/values";

            var customDelegatingHandler = new CustomDelegatingHandler();

            var client = HttpClientFactory.Create(customDelegatingHandler);

            HttpResponseMessage getResponse = await client.GetAsync(url);

            if (getResponse.IsSuccessStatusCode)
            {
                string responseString = await getResponse.Content.ReadAsStringAsync();
                Console.WriteLine(responseString);
                Console.WriteLine("GET - HTTP Status: {0}, Reason {1}", getResponse.StatusCode, getResponse.ReasonPhrase);
            }
            else
            {
                Console.WriteLine("Failed to call the API. HTTP Status: {0}, Reason {1}", getResponse.StatusCode, getResponse.ReasonPhrase);
            }

            //var order = new Order { OrderID = 10248, CustomerName = "Taiseer Joudeh", ShipperCity = "Amman", IsShipped = true };
            var order = new Foo("webhook");
            string json = JsonConvert.SerializeObject(order);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            HttpResponseMessage postResponse = await client.PostAsync(url, content);

            if (postResponse.IsSuccessStatusCode)
            {
                string responseString = await postResponse.Content.ReadAsStringAsync();
                Console.WriteLine("POST - HTTP Status: {0}, Reason {1}. Press ENTER to exit", postResponse.StatusCode, postResponse.ReasonPhrase);
            }
            else
            {
                Console.WriteLine("Failed to call the API. HTTP Status: {0}, Reason {1}", postResponse.StatusCode, postResponse.ReasonPhrase);
            }

            Console.ReadLine();
        }

        public class CustomDelegatingHandler : DelegatingHandler
        {
            //Obtained from the server earlier, APIKey MUST be stored securly and in App.Config
            private string APPId = "4d53bce03ec34c0a911182d4c228ee6c";
            private string APIKey = "A93reRTUJHsCuQSHR+L3GxqOJyDmQpCgps102ciuabc=";

            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                HttpResponseMessage response = null;
                string requestContentBase64String = string.Empty;

                string requestUri = HttpUtility.UrlEncode(request.RequestUri.AbsoluteUri.ToLower());

                string requestHttpMethod = request.Method.Method;

                //Calculate UNIX time
                DateTime epochStart = new DateTime(1970, 01, 01, 0, 0, 0, 0, DateTimeKind.Utc);
                TimeSpan timeSpan = DateTime.UtcNow - epochStart;
                string requestTimeStamp = Convert.ToUInt64(timeSpan.TotalSeconds).ToString();

                //create random nonce for each request
                string nonce = Guid.NewGuid().ToString("N");

                //Checking if the request contains body, usually will be null wiht HTTP GET and DELETE
                if (request.Content != null)
                {
                    byte[] content = await request.Content.ReadAsByteArrayAsync();
                    MD5 md5 = MD5.Create();
                    //Hashing the request body, any change in request body will result in different hash, we'll incure message integrity
                    byte[] requestContentHash = md5.ComputeHash(content);
                    requestContentBase64String = Convert.ToBase64String(requestContentHash);
                }

                //Creating the raw signature string
                string signatureRawData =
                    $"{APPId}{requestHttpMethod}{requestUri}{requestTimeStamp}{nonce}{requestContentBase64String}";

                Console.WriteLine(signatureRawData);

                var secretKeyByteArray = Convert.FromBase64String(APIKey);

                byte[] signature = Encoding.UTF8.GetBytes(signatureRawData);

                using (var hmac = new HMACSHA256(secretKeyByteArray))
                {
                    byte[] signatureBytes = hmac.ComputeHash(signature);
                    string requestSignatureBase64String = Convert.ToBase64String(signatureBytes);
                    //Setting the values in the Authorization header using custom scheme (amx)
                    request.Headers.Authorization = new AuthenticationHeaderValue("hmac",
                        $"{APPId}:{requestSignatureBase64String}:{nonce}:{requestTimeStamp}");
                }

                response = await base.SendAsync(request, cancellationToken);
                return response;
            }
        }

        private void GenerateAPPKey()
        {
            using (var cryptoProvider = new RNGCryptoServiceProvider())
            {
                byte[] secretKeyByteArray = new byte[32]; //256 bit
                cryptoProvider.GetBytes(secretKeyByteArray);
                var APIKey = Convert.ToBase64String(secretKeyByteArray);
            }
        }
    }
}