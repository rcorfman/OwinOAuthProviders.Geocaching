// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Globalization;
using System.Security.Claims;
using System.Text;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;

namespace Owin.Security.Providers.Geocaching
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class GeocachingAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="GeocachingAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">Geocaching Access token</param>
        /// <param name="expires">Seconds until expiration</param>
        public GeocachingAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string expires, string refreshToken)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;
            RefreshToken = refreshToken;

            if (int.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out int expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }
            else
            {
                ExpiresIn = TimeSpan.Zero;
            }

            ReferenceCode = TryGetValue(user, "referenceCode");
            Username = TryGetValue(user, "username");
            MembershipLevelId = TryGetValue(user, "membershipLevelId");
            AvatarUrl = TryGetValue(user, "avatarUrl");
            FindCount = TryGetValue(user, "findCount");
            HideCount = TryGetValue(user, "hideCount");
            FavoritePoints = TryGetValue(user, "favoritePoints");
            BannerUrl = TryGetValue(user, "bannerUrl");
            Url = TryGetValue(user, "url");
            ProfileText = TryGetValue(user, "profileText");
            HomeCoordinates = TryGetValueAndSerialize(user, "homeCoordinates");
            GeocacheLimits = TryGetValueAndSerialize(user, "geocacheLimits");
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the Geocaching user obtained from the endpoint https://api.Groundspeak.com/v1.0/users/~
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the Geocaching access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Geocaching refresh token
        /// </summary>
        public string RefreshToken { get; private set; }

        /// <summary>
        /// Gets the Geocaching access token expiration time
        /// </summary>
        public TimeSpan? ExpiresIn { get; set; }

        /// <summary>
        /// Gets the Geocaching user's reference code
        /// </summary>
        public string ReferenceCode { get; private set; }

        /// <summary>
        /// Gets the Geocaching username
        /// </summary>
        public string Username { get; private set; }

        /// <summary>
        /// Gets the Geocaching user's membership level id
        /// </summary>
        public string MembershipLevelId { get; private set; }

        /// <summary>
        /// Gets the Geocaching user's url
        /// </summary>
        public string Url { get; private set; }

        /// <summary>
        /// Gets the Geocaching user's avatar url
        /// </summary>
        public string AvatarUrl { get; private set; }

        /// <summary>
        /// Gets the Geocaching user's banner url
        /// </summary>
        public string BannerUrl { get; private set; }

        /// <summary>
        /// Gets the Geocaching user's find count
        /// </summary>
        public string FindCount { get; private set; }

        /// <summary>
        /// Gets the Geocaching user's hide count
        /// </summary>
        public string HideCount { get; private set; }

        /// <summary>
        /// Gets the Geocaching user's favorite points
        /// </summary>
        public string FavoritePoints { get; private set; }

        /// <summary>
        /// Gets the Geocaching user's profile text
        /// </summary>
        public string ProfileText { get; private set; }

        /// <summary>
        /// Gets the Geocaching user's home coordinates
        /// </summary>
        public string HomeCoordinates { get; private set; }

        /// <summary>
        /// Gets the Geocaching user's current geocachache limits
        /// </summary>
        public string GeocacheLimits { get; private set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }

        private static string TryGetValueAndSerialize(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? JsonConvert.SerializeObject(value) : null;
        }

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder("Geocaching Authenticated Context:");

            sb.Append("Geocaching Authenticated Context:");

            if (!string.IsNullOrEmpty(ReferenceCode))
                sb.Append(Environment.NewLine).Append("\tReferenceCode: ").Append(ReferenceCode);

            if (!string.IsNullOrEmpty(Username))
                sb.Append(Environment.NewLine).Append("\tUsername: ").Append(Username);

            sb.Append(Environment.NewLine).Append("\tAccessToken: ").Append(AccessToken);
            sb.Append(Environment.NewLine).Append("\tExpiresIn: ").Append(ExpiresIn);
            sb.Append(Environment.NewLine).Append("\tRefreshToken: ").Append(RefreshToken);

            if (!string.IsNullOrEmpty(MembershipLevelId))
                sb.Append(Environment.NewLine).Append("\tMembershipLevelId: ").Append(MembershipLevelId);

            if (!string.IsNullOrEmpty(AvatarUrl))
                sb.Append(Environment.NewLine).Append("\tAvatarUrl: ").Append(AvatarUrl);

            if (!string.IsNullOrEmpty(BannerUrl))
                sb.Append(Environment.NewLine).Append("\tBannerUrl: ").Append(BannerUrl);

            if (!string.IsNullOrEmpty(Url))
                sb.Append(Environment.NewLine).Append("\tUrl: ").Append(Url);

            if (!string.IsNullOrEmpty(HomeCoordinates))
                sb.Append(Environment.NewLine).Append("\tHomeCoordinates: ").Append(HomeCoordinates);

            if (!string.IsNullOrEmpty(GeocacheLimits))
                sb.Append(Environment.NewLine).Append("\tGeocacheLimits: ").Append(GeocacheLimits);

            if (!string.IsNullOrEmpty(FindCount))
                sb.Append(Environment.NewLine).Append("\tFindCount: ").Append(FindCount);

            if (!string.IsNullOrEmpty(HideCount))
                sb.Append(Environment.NewLine).Append("\tHideCount: ").Append(HideCount);

            if (!string.IsNullOrEmpty(FavoritePoints))
                sb.Append(Environment.NewLine).Append("\tFavoritePoints: ").Append(FavoritePoints);

            if (!string.IsNullOrEmpty(ProfileText))
            {
                sb.Append(Environment.NewLine).Append("\tProfileText: ").Append(ProfileText.Substring(0, 100));
            }

            return sb.ToString();
        }
    }
}