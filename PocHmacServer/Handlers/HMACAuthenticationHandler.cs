﻿using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using System.Web;

namespace PocHmacServer.Handlers
{
    public class HMACAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private const ulong _REQUEST_MAX_AGE_IN_SECONDS = 300; //5 mins
        private const string _AUTHENTICATION_SCHEME = "hmac";

        private static readonly DateTime _1970 = new DateTime(1970, 01, 01, 0, 0, 0, 0, DateTimeKind.Utc);
        private static readonly Dictionary<string, string> _AllowedApps = new Dictionary<string, string>();
        private readonly IMemoryCache _cache;

        public HMACAuthenticationHandler(IMemoryCache memoryCache, IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
        {
            _cache = memoryCache;

            if (_AllowedApps.Count == 0)
            {
                _AllowedApps.Add("4d53bce03ec34c0a911182d4c228ee6c", "A93reRTUJHsCuQSHR+L3GxqOJyDmQpCgps102ciuabc=");
            }
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var headers = Context.Request.Headers;
            var authorization = headers["Authorization"].ToString();

            if (authorization != null)
            {
                if (authorization.StartsWith(_AUTHENTICATION_SCHEME))
                {
                    var autherizationHeaderArray = GetAutherizationHeaderValues(authorization);

                    if (autherizationHeaderArray != null)
                    {
                        var appId = autherizationHeaderArray[0];
                        var incomingBase64Signature = autherizationHeaderArray[1];
                        var nonce = autherizationHeaderArray[2];
                        var requestTimeStamp = autherizationHeaderArray[3];

                        var request = Context.Request;
                        var isValid = await IsValidRequestAsync(request, appId, incomingBase64Signature, nonce, requestTimeStamp);

                        if (isValid)
                        {
                            var identity = new ClaimsIdentity("api");
                            var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), null, "api");
                            return AuthenticateResult.Success(ticket);
                        }

                        return AuthenticateResult.Fail("Incorrect'Authorization' header.");
                    }
                }
            }

            return AuthenticateResult.Fail("Missing or malformed 'Authorization' header.");
        }

        private async Task<bool> IsValidRequestAsync(HttpRequest request, string appId, string incomingBase64Signature, string nonce,
            string requestTimeStamp)
        {
            string requestContentBase64String = "";
            string requestUri =
                HttpUtility.UrlEncode(request.Scheme + "://" + request.Host +
                                      request.Path); //http://localhost:43326/api/values
            string requestHttpMethod = request.Method;

            if (!_AllowedApps.ContainsKey(appId)) return false;

            var sharedKey = _AllowedApps[appId];

            if (IsReplayRequest(nonce, requestTimeStamp)) return false;

            request.EnableBuffering();
            byte[] hash = await ComputeHashAsync(request.Body);
            request.Body.Position = 0;

            if (hash != null)
            {
                requestContentBase64String = Convert.ToBase64String(hash);
            }

            var data = $"{appId}{requestHttpMethod}{requestUri}{requestTimeStamp}{nonce}{requestContentBase64String}";

            var secretKeyBytes = Convert.FromBase64String(sharedKey);

            byte[] signature = Encoding.UTF8.GetBytes(data);

            using (var hmac = new HMACSHA256(secretKeyBytes))
            {
                byte[] signatureBytes = hmac.ComputeHash(signature);
                return incomingBase64Signature.Equals(Convert.ToBase64String(signatureBytes), StringComparison.Ordinal);
            }
        }

        private bool IsReplayRequest(string nonce, string requestTimeStamp)
        {
            if (_cache.TryGetValue(nonce, out object _)) return true;

            TimeSpan currentTs = DateTime.UtcNow - _1970;
            var serverTotalSeconds = Convert.ToUInt64(currentTs.TotalSeconds);
            var requestTotalSeconds = Convert.ToUInt64(requestTimeStamp);

            if (serverTotalSeconds - requestTotalSeconds > _REQUEST_MAX_AGE_IN_SECONDS) return true;

            _cache.Set(nonce, requestTimeStamp, DateTimeOffset.UtcNow.AddSeconds(_REQUEST_MAX_AGE_IN_SECONDS));

            return false;
        }

        private static string[] GetAutherizationHeaderValues(string rawAuthzHeader)
        {
            var credArray = rawAuthzHeader.Split(' ')[1].Split(':');
            return credArray.Length == 4 ? credArray : null;
        }

        private static async Task<byte[]> ComputeHashAsync(Stream body)
        {
            using (var md5 = MD5.Create())
            {
                var content = await GetBytesAsync(body);

                byte[] hash = content.Length != 0
                    ? md5.ComputeHash(content)
                    : null;
                return hash;
            }
        }

        private static async Task<byte[]> GetBytesAsync(Stream input)
        {
            byte[] buffer = new byte[16 * 1024];
            using (var ms = new MemoryStream())
            {
                int read;
                while ((read = await input.ReadAsync(buffer, 0, buffer.Length)) > 0)
                {
                    ms.Write(buffer, 0, read);
                }
                return ms.ToArray();
            }
        }
    }
}