using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace Owin.Security.Providers.Geocaching
{
    public class GeocachingAuthenticationOptions : AuthenticationOptions
    {
        public class GeocachingAuthenticationEndpoints
        {
            /// <summary>
            /// Endpoint which is used to redirect users to Geocaching access
            /// </summary>
            public string AuthorizationEndpoint { get; set; }

            /// <summary>
            /// Endpoint which is used to exchange code for access token
            /// </summary>
            public string TokenEndpoint { get; set; }

            public string UserInfoEndpoint { get; set; }
        }

        const string AuthenticationEndpoint = "https://www.geocaching.com/oauth/authorize.aspx";
        const string TokenEndPoint = "https://oauth.geocaching.com/token";
        const string UserInfoEndpoint = "https://api.groundspeak.com/v1.0/users";

        const string StagingAuthenticationEndpoint = "https://staging.geocaching.com/oauth/authorize.aspx";
        const string StagingTokenEndPoint = "https://oauth-staging.geocaching.com/token";
        const string StagingUserInfoEndpoint = "https://staging.api.groundspeak.com/v1.0/users";

        /// <summary>
        ///     Gets or sets the a pinned certificate validator to use to validate the endpoints used
        ///     in back channel communications belong to Geocaching.
        /// </summary>
        /// <value>
        ///     The pinned certificate validator.
        /// </value>
        /// <remarks>
        ///     If this property is null then the default certificate checks are performed,
        ///     validating the subject name and if the signing chain is a trusted party.
        /// </remarks>
        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        /// <summary>
        ///     The HttpMessageHandler used to communicate with Geocaching.
        ///     This cannot be set at the same time as BackchannelCertificateValidator unless the value
        ///     can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        ///     Gets or sets timeout value in milliseconds for back channel communications with Geocaching.
        /// </summary>
        /// <value>
        ///     The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        ///     The request path within the application's base path where the user-agent will be returned.
        ///     The middleware will process this request when it arrives.
        ///     Default value is "/signin-Geocaching".
        /// </summary>
        public PathString CallbackPath { get; set; }

        /// <summary>
        ///     Gets or sets the middleware host name.
        ///     The middleware processes the <see cref="CallbackPath"/> on this host name instead of the application's request host.
        ///     If this is not set, the application's request host will be used.
        /// </summary>
        /// <remarks>
        ///     Use this property when running behind a proxy.
        /// </remarks>
        public string ProxyHost { get; set; }

        /// <summary>
        ///     Get or sets the text that the user can display on a sign in user interface.
        /// </summary>
        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }

        /// <summary>
        ///     Gets or sets the Geocaching supplied consumer key
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        ///     Gets or sets the Geocaching supplied consumer secret key
        /// </summary>
        public string ClientSecret { get; set; }

        public GeocachingAuthenticationEndpoints Endpoints { get; set; }

        public bool UseStaging { get; set; }

        /// <summary>
        /// Enables PKCE.
        /// </summary>
        /// <remarks>
        /// Enables Proof Key for Code Exchange support.
        /// See https://tools.ietf.org/html/rfc7636 for more details.
        /// 
        /// Defaults to true.
        /// </remarks>
        public bool RequirePkce { get; set; }

        /// <summary>
        ///     Gets the list of profile fields to retrieve when signing in. 
        /// </summary>
        /// <remarks>
        ///     See https://api.groundspeak.com/api-docs/index#!/Users/Users_GetUser for the list of available User fields. 
        ///     Access to these fields requires that you apply for and are granted access to this information from Geocaching.
        ///     
        ///     The following fields are added to the list by default: referenceCode, membershipLevelId, findCount, hideCount,
        ///     favoritePoints, homeCoordinates, geocacheLimits, username, avatarUrl.
        /// 
        ///     You can access the returned fields through the <see cref="GeocachingAuthenticatedContext.User"/> property.
        /// </remarks>
        public IList<string> ProfileFields { get; private set; }

        /// <summary>
        ///     Gets or sets the <see cref="IGeocachingAuthenticationProvider" /> used in the authentication events
        /// </summary>
        public IGeocachingAuthenticationProvider Provider { get; set; }

        /// <summary>
        ///     Gets or sets the name of another authentication middleware which will be responsible for actually issuing a user
        ///     <see cref="System.Security.Claims.ClaimsIdentity" />.
        /// </summary>
        public string SignInAsAuthenticationType { get; set; }

        /// <summary>
        ///     Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        ///     Initializes a new <see cref="GeocachingAuthenticationOptions" />
        /// </summary>
        public GeocachingAuthenticationOptions(bool useStaging = false)
            : base(Constants.DefaultAuthenticationType)
        {
            UseStaging = useStaging;
            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-" + Constants.DefaultAuthenticationType);
            AuthenticationMode = AuthenticationMode.Passive;
            ProfileFields = new List<string>
            {
                "username",
                "referenceCode",
                "membershipLevelId",
                "findCount",
                "hideCount",
                "favoritePoints",
                "avatarUrl",
                "homeCoordinates",
                "geocacheLimits",
            };
            Endpoints = new GeocachingAuthenticationEndpoints()
            {
                AuthorizationEndpoint = useStaging ? StagingAuthenticationEndpoint : AuthenticationEndpoint,
                TokenEndpoint = useStaging ? StagingTokenEndPoint : TokenEndPoint,
                UserInfoEndpoint = useStaging ? StagingUserInfoEndpoint : UserInfoEndpoint,
            };
            BackchannelTimeout = TimeSpan.FromSeconds(60);
            RequirePkce = true;
        }

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("Geocaching Authentication Options:")
                .Append(Environment.NewLine).Append("\tCaption: ").Append(Caption)
                .Append(Environment.NewLine).Append("\tClientId: ").Append(ClientId)
                .Append(Environment.NewLine).Append("\tClientSecret: ").Append(ClientSecret)
                .Append(Environment.NewLine).Append("\tEndPoints.AuthorizationEndpoint: ").Append(Endpoints.AuthorizationEndpoint)
                .Append(Environment.NewLine).Append("\tEndPoints.TokenEndpoint: ").Append(Endpoints.TokenEndpoint)
                .Append(Environment.NewLine).Append("\tEndPoints.UserInfoEndpoint: ").Append(Endpoints.UserInfoEndpoint)
                .Append(Environment.NewLine).Append("\tCallbackPath: ").Append(CallbackPath)
                .Append(Environment.NewLine).Append("\tRequirePkce: ").Append(RequirePkce)
                .Append(Environment.NewLine).Append("\tProfileFields: ").Append(string.Join(",", ProfileFields));
            return sb.ToString();
        }
    }
}