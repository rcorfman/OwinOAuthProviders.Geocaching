using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Owin.Security.Providers.Geocaching
{
    public static class GeocachingAuthenticationConstants
    {
        public static class Claims
        {
            private const string Urn = "urn:geocaching:";

            //public const string Username = ClaimTypes.Name;
            //public const string ReferenceCode = ClaimTypes.NameIdentifier;
            public const string RefreshToken = Urn + "refreshtoken";
            public const string AccessToken = Urn + "accesstoken";
            public const string MembershipLevelId = Urn + "membershiplevelid";
            public const string AvatarUrl = Urn + "avatarurl";
            public const string HomeCoordinates = Urn + "homecoordinates";
            public const string FindCount = Urn + "findcount";
            public const string HideCount = Urn + "hidecount";
            public const string FavoritePoints = Urn + "favoritepoints";
            public const string GeocacheLimits = Urn + "geocachelimits";
            public const string ProfileText = Urn + "profiletext";
            public const string BannerUrl = Urn + "bannerurl";
            public const string Url = Urn + "url";

        }
    }
}
