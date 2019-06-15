using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using IdentityModel;
using static Owin.Security.Providers.Geocaching.GeocachingAuthenticationConstants;

namespace Owin.Security.Providers.Geocaching
{
    public class GeocachingAuthenticationHandler : AuthenticationHandler<GeocachingAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private const string PkceCodeVerifierKey = "PkceCodeVerifier";

        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public GeocachingAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                string code = null;
                string state = null;

                var query = Request.Query;
                var values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }
                values = query.GetValues("state");
                if (values != null && values.Count == 1)
                {
                    state = values[0];
                }

                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                var requestPrefix = Request.Scheme + "://" + this.GetHostName();
                var redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

                // Build up the body for the token request
                var body = new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("redirect_uri", redirectUri),
                    new KeyValuePair<string, string>("client_id", Options.ClientId),
                    new KeyValuePair<string, string>("client_secret", Options.ClientSecret)
                };

                if (Options.RequirePkce)
                {
                    if (properties.Dictionary.ContainsKey(PkceCodeVerifierKey))
                    {
                        string codeVerifier = properties.Dictionary[PkceCodeVerifierKey];
                        body.Add(new KeyValuePair<string, string>("code_verifier", codeVerifier));
                    }
                    else
                    {
                        return new AuthenticationTicket(null, properties);
                    }
                }

                // Request the token
                var tokenResponse = await _httpClient.PostAsync(Options.Endpoints.TokenEndpoint, new FormUrlEncodedContent(body));
                tokenResponse.EnsureSuccessStatusCode();
                var text = await tokenResponse.Content.ReadAsStringAsync();

                // Deserializes the token response
                dynamic response = JsonConvert.DeserializeObject<dynamic>(text);
                string accessToken = (string)response.access_token;
                string tokenType = (string)response.token_type;
                string expires = (string)response.expires_in;
                string refreshToken = (string)response.refresh_token;

                // Get the Geocaching user
                var userInfoEndpoint = Options.Endpoints.UserInfoEndpoint + "/me?fields=" + string.Join("%2C", Options.ProfileFields.Distinct().ToArray());

                var userRequest = new HttpRequestMessage(HttpMethod.Get, userInfoEndpoint);
                userRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                var graphResponse = await _httpClient.SendAsync(userRequest, Request.CallCancelled);
                graphResponse.EnsureSuccessStatusCode();
                text = await graphResponse.Content.ReadAsStringAsync();
                var user = JObject.Parse(text);

                var context = new GeocachingAuthenticatedContext(Context, user, accessToken, refreshToken, expires)
                {
                    Identity = new ClaimsIdentity(
                        Options.AuthenticationType,
                        ClaimsIdentity.DefaultNameClaimType,
                        ClaimsIdentity.DefaultRoleClaimType)
                };

                if (!string.IsNullOrEmpty(context.ReferenceCode))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.ReferenceCode, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Username))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Name, context.Username, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.RefreshToken))
                {
                    context.Identity.AddClaim(new Claim(Claims.RefreshToken, context.RefreshToken, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.AccessToken))
                {
                    context.Identity.AddClaim(new Claim(Claims.AccessToken, context.AccessToken, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.MembershipLevelId))
                {
                    context.Identity.AddClaim(new Claim(Claims.MembershipLevelId, context.MembershipLevelId, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.AvatarUrl))
                {
                    context.Identity.AddClaim(new Claim(Claims.AvatarUrl, context.AvatarUrl, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.BannerUrl))
                {
                    context.Identity.AddClaim(new Claim(Claims.BannerUrl, context.BannerUrl, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Url))
                {
                    context.Identity.AddClaim(new Claim(Claims.Url, context.Url, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.FindCount))
                {
                    context.Identity.AddClaim(new Claim(Claims.FindCount, context.FindCount, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.HideCount))
                {
                    context.Identity.AddClaim(new Claim(Claims.HideCount, context.HideCount, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.FavoritePoints))
                {
                    context.Identity.AddClaim(new Claim(Claims.FavoritePoints, context.FavoritePoints, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.ProfileText))
                {
                    context.Identity.AddClaim(new Claim(Claims.ProfileText, context.ProfileText, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.HomeCoordinates))
                {
                    context.Identity.AddClaim(new Claim(Claims.HomeCoordinates, context.HomeCoordinates, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.GeocacheLimits))
                {
                    context.Identity.AddClaim(new Claim(Claims.GeocacheLimits, context.GeocacheLimits, XmlSchemaString, Options.AuthenticationType));
                }
                context.Properties = properties;

                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteError(ex.Message);
            }
            return new AuthenticationTicket(null, properties);
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge == null)
            {
                return Task.FromResult<object>(null);
            }

            string baseUri = Request.Scheme + Uri.SchemeDelimiter + this.GetHostName() + Request.PathBase;
            string currentUri = baseUri + Request.Path + Request.QueryString;
            string redirectUri = baseUri + Options.CallbackPath;

            var properties = challenge.Properties;

            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = currentUri;
            }

            string codeVerifier = string.Empty;
            string codeChallenge = string.Empty;

            if (Options.RequirePkce)
            {
                codeVerifier = CryptoRandom.CreateUniqueId(32);
                codeChallenge = codeVerifier.ToSha256().TrimEnd('=').Replace('+', '-').Replace('/', '_');

                properties.Dictionary.Add(PkceCodeVerifierKey, codeVerifier);
            }

            // OAuth2 10.12 CSRF
            GenerateCorrelationId(properties);

            string state = Options.StateDataFormat.Protect(properties);

            string authorizationEndpoint =
                Options.Endpoints.AuthorizationEndpoint +
                "?response_type=code" +
                "&scope=*" +
                "&client_id=" + Uri.EscapeDataString(Options.ClientId) +
                "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                "&state=" + Uri.EscapeDataString(state);

            if (Options.RequirePkce)
            {
                authorizationEndpoint += "&code_challenge=" + codeChallenge + "&code_challenge_method=S256";
            }

            var redirectContext = new GeocachingApplyRedirectContext(
                Context, Options,
                properties, authorizationEndpoint);

            Options.Provider.ApplyRedirect(redirectContext);

            return Task.FromResult<object>(null);
        }

        public override async Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync();
        }

        private async Task<bool> InvokeReplyPathAsync()
        {
            if (!Options.CallbackPath.HasValue || Options.CallbackPath != Request.Path)
            {
                return false;
            }
            // TODO: error responses

            var ticket = await AuthenticateAsync();
            if (ticket == null)
            {
                _logger.WriteWarning("Invalid return state, unable to redirect.");
                Response.StatusCode = 500;
                return true;
            }

            var context = new GeocachingReturnEndpointContext(Context, ticket)
            {
                SignInAsAuthenticationType = Options.SignInAsAuthenticationType,
                RedirectUri = ticket.Properties.RedirectUri
            };

            await Options.Provider.ReturnEndpoint(context);

            if (context.SignInAsAuthenticationType != null &&
                context.Identity != null)
            {
                var grantIdentity = context.Identity;
                if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                {
                    grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
                }
                Context.Authentication.SignIn(context.Properties, grantIdentity);
            }

            if (context.IsRequestCompleted || context.RedirectUri == null) return context.IsRequestCompleted;
            var redirectUri = context.RedirectUri;
            if (context.Identity == null)
            {
                // add a redirect hint that sign-in failed in some way
                redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
            }
            Response.Redirect(redirectUri);
            context.RequestCompleted();

            return context.IsRequestCompleted;
        }

        /// <summary>
        ///     Gets proxy host name from <see cref="GeocachingAuthenticationOptions"/> if it is set.
        ///     If proxy host name is not set, gets application request host name.
        /// </summary>
        /// <returns>Host name.</returns>
        private string GetHostName()
        {
            string hostName = string.IsNullOrWhiteSpace(Options.ProxyHost) ? Request.Host.ToString() : Options.ProxyHost;
            return hostName;
        }
    }
}