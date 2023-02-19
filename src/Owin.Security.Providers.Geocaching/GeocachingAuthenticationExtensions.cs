using System;

namespace Owin.Security.Providers.Geocaching
{
    public static class GeocachingAuthenticationExtensions
    {
        public static IAppBuilder UseGeocachingAuthentication(this IAppBuilder app, GeocachingAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            app.Use(typeof(GeocachingAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseGeocachingAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseGeocachingAuthentication(new GeocachingAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}