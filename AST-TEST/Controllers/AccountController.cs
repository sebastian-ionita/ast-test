using Facebook;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.AspNetCore.Authentication.Twitter;
using AspNet.Security.OAuth.LinkedIn;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace AST_TEST.Controllers
{
    [AllowAnonymous, Route("")]
    public class AccountController : Controller
    {
        [Route("")]
        [AllowAnonymous]
        public IActionResult Login()
        {
            return View("Login");
        }

        [Route("external-login")]
        public IActionResult ExternalLogin(string provider)
        {
            // Configure the external authentication properties
            var properties = new AuthenticationProperties
            {
                RedirectUri = Url.Action("ExternalLoginCallback", "Account")
            };

            // Redirect to the appropriate external authentication provider
            return provider switch
            {
                "Facebook" => Challenge(properties, FacebookDefaults.AuthenticationScheme),
                "LinkedIn" => Challenge(properties, LinkedInAuthenticationDefaults.AuthenticationScheme),
                "Twitter" => Challenge(properties, TwitterDefaults.AuthenticationScheme),
                _ => BadRequest(),
            };
        }


        [Route("account")]
        public async Task<IActionResult> ExternalLoginCallback()
        {
            // Authenticate the user using the external authentication provider
            var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            if (result.Succeeded)
            {
                if(result.Principal.Identity.AuthenticationType == "LinkedIn")
                {
                    var name = User.FindFirstValue(ClaimTypes.Name);
                    var email = User.FindFirstValue(ClaimTypes.Email);
                    var mobilePhone = User.FindFirstValue(ClaimTypes.MobilePhone);
                    return Json(new
                    {
                        Name=name,
                        Email=email,
                        Phone=mobilePhone,
                    }); 
                }
                string accessToken = result.Properties.GetTokenValue("access_token");
                var fb = new FacebookClient(accessToken);

                dynamic userPosts = fb.Get("/me?fields=email,picture,feed,name");
                return Json(userPosts);
            }
            // External authentication failed, redirect to the login page
            return RedirectToAction("Login", "Account");
        }
        [Route("logout")]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Login", "Account");
        }
    }    
}
