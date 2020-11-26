using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;

namespace MvcApplication.Controllers
{
    public class AccountController : Controller
    {
        public ActionResult Login(string returnUrl)
        {
            HttpContext.GetOwinContext().Authentication.Challenge(new AuthenticationProperties
            {
                RedirectUri = returnUrl ?? Url.Action("Index", "Home")
            },
                "Auth0");
            return new HttpUnauthorizedResult();
        }

        [Authorize]
        public void Logout()
        {
            HttpContext.GetOwinContext().Authentication.SignOut(CookieAuthenticationDefaults.AuthenticationType);
            HttpContext.GetOwinContext().Authentication.SignOut("Auth0");
        }

        /// <summary>
        /// IDトークンとアクセストークンへのアクセス例
        /// https://auth0.com/docs/quickstart/webapp/aspnet-owin#obtain-an-access-token-for-calling-an-api
        /// </summary>
        /// <returns></returns>
        [Authorize]
        public ActionResult Tokens()
        {
            var claimsIdentity = User.Identity as ClaimsIdentity;

            // Extract tokens
            string accessToken = claimsIdentity?.FindFirst(c => c.Type == "access_token")?.Value;
            string idToken = claimsIdentity?.FindFirst(c => c.Type == "id_token")?.Value;

            // Now you can use the tokens as appropriate...
            return View();
        }

        [Authorize]
        public ActionResult Claims()
        {
            return View();
        }
    }
}