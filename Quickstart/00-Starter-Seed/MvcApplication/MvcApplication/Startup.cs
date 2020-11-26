using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Host.SystemWeb;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using MvcApplication.Support;
using Owin;
using System;
using System.Configuration;
using System.Security.Claims;
using System.Threading.Tasks;

[assembly: OwinStartup(typeof(MvcApplication.Startup))]

namespace MvcApplication
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            // Configure Auth0 parameters
            string auth0Domain = ConfigurationManager.AppSettings["auth0:Domain"];
            string auth0ClientId = ConfigurationManager.AppSettings["auth0:ClientId"];
            string auth0ClientSecret = ConfigurationManager.AppSettings["auth0:ClientSecret"];
            string auth0RedirectUri = ConfigurationManager.AppSettings["auth0:RedirectUri"];
            string auth0PostLogoutRedirectUri = ConfigurationManager.AppSettings["auth0:PostLogoutRedirectUri"];

            // Set Cookies as default authentication type
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = CookieAuthenticationDefaults.AuthenticationType,
                LoginPath = new PathString("/Account/Login"),

                // Configure SameSite as needed for your app. Lax works well for most scenarios here but
                // you may want to set SameSiteMode.None for HTTPS
                CookieSameSite = SameSiteMode.Lax,
            });

            string auth0Audience = ConfigurationManager.AppSettings["auth0:Audience"];

            // Configure Auth0 authentication
            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                AuthenticationType = "Auth0",

                Authority = $"https://{auth0Domain}",

                ClientId = auth0ClientId,
                ClientSecret = auth0ClientSecret,

                RedirectUri = auth0RedirectUri,
                PostLogoutRedirectUri = auth0PostLogoutRedirectUri,

                ResponseType = OpenIdConnectResponseType.CodeIdTokenToken,
                Scope = "openid profile",

                TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name"
                },

                CookieManager = new SameSiteCookieManager(new SystemWebCookieManager()),

                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    SecurityTokenValidated = notification =>
                    {
                        notification.AuthenticationTicket.Identity.AddClaim(new Claim("id_token", notification.ProtocolMessage.IdToken));
                        notification.AuthenticationTicket.Identity.AddClaim(new Claim("access_token", notification.ProtocolMessage.AccessToken));

                        return Task.FromResult(0);
                    },
                    RedirectToIdentityProvider = notification =>
                    {
                        if (notification.ProtocolMessage.RequestType == OpenIdConnectRequestType.Authentication)
                        {
                            // The context's ProtocolMessage can be used to pass along additional query parameters
                            // to Auth0's /authorize endpoint.
                            // 
                            // Set the audience query parameter to the API identifier to ensure the returned Access Tokens can be used
                            // to call protected endpoints on the corresponding API.
                            notification.ProtocolMessage.SetParameter("audience", auth0Audience);
                        }
                        else if (notification.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout)
                        {
                            var logoutUri = $"https://{auth0Domain}/v2/logout?client_id={auth0ClientId}";

                            var postLogoutUri = notification.ProtocolMessage.PostLogoutRedirectUri;
                            if (!string.IsNullOrEmpty(postLogoutUri))
                            {
                                if (postLogoutUri.StartsWith("/"))
                                {
                                    // transform to absolute
                                    var request = notification.Request;
                                    postLogoutUri = request.Scheme + "://" + request.Host + request.PathBase + postLogoutUri;
                                }
                                logoutUri += $"&returnTo={ Uri.EscapeDataString(postLogoutUri)}";
                            }

                            notification.Response.Redirect(logoutUri);
                            notification.HandleResponse();
 
                            notification.ProtocolMessage.SetParameter("audience", auth0Audience);
                        }
                        return Task.FromResult(0);
                    }
                }
            });
        }
    }
}
