using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Web;
using System.Web.Http.Cors;
using System.Web.Mvc;
using WebApplication1.ViewModels;
using WebApplication1.BusinessLogic;
using System.Net.Mail;

namespace WebApplication1.Controllers
{
    [EnableCors(origins: "*", headers: "*", methods: "*")]
    public class HomeController : Controller
    {

        const string EMAIL_CONFIRMATION = "Email Confirmation";
        const string PASSWORD_RESET = "Reset Password";

        [HttpGet]
        public ActionResult Index()
        {
            return View();
        }


        [HttpPost]
        public ActionResult Index(Login login)
        {
            // UserStore and UserManager manages data retreival.
            // For more information on how to configure your application, visit http://go.microsoft.com/fwlink/?LinkID=316888
            UserStore<IdentityUser> userStore = new UserStore<IdentityUser>();
            UserManager<IdentityUser> manager = new UserManager<IdentityUser>(userStore);
            IdentityUser identityUser = manager.Find(login.UserName, login.Password);

            if (ModelState.IsValid)
            {
                    CaptchaHelper captchaHelper = new CaptchaHelper();
                    string captchaResponse = captchaHelper.CheckRecaptcha();
                    ViewBag.CaptchaResponse = captchaResponse;
                //if (identityUser != null) {
                if (ValidLogin(login) && captchaResponse == "You may proceed") {
                    IAuthenticationManager authenticationManager
                                           = HttpContext.GetOwinContext().Authentication;
                    authenticationManager
                   .SignOut(DefaultAuthenticationTypes.ExternalCookie);

                    var identity = new ClaimsIdentity(new[] {
                                            new Claim(ClaimTypes.Name, login.UserName),
                                        },
                                        DefaultAuthenticationTypes.ApplicationCookie,
                                        ClaimTypes.Name, ClaimTypes.Role);
                    // SignIn() accepts ClaimsIdentity and issues logged in cookie. 
                    authenticationManager.SignIn(new AuthenticationProperties
                    {
                        IsPersistent = false
                    }, identity);
                    return RedirectToAction("SecureArea", "Home");
                }
            }
            return View();
        }
        [HttpGet]
        public ActionResult Register()
        {
            return View();
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Register(RegisteredUser newUser)
        {
            var userStore = new UserStore<IdentityUser>();
            //var manager = new UserManager<IdentityUser>(userStore);

            UserManager<IdentityUser> manager = new UserManager<IdentityUser>(userStore)
            {
                UserLockoutEnabledByDefault = true,
                DefaultAccountLockoutTimeSpan = new TimeSpan(0, 1, 0),
                MaxFailedAccessAttemptsBeforeLockout = 5
            };

            var identityUser = new IdentityUser()
            {
                UserName = newUser.UserName,
                Email = newUser.Email
            };
            IdentityResult result = manager.Create(identityUser, newUser.Password);

            if (result.Succeeded)
            {
                //    var authenticationManager
                //                      = HttpContext.Request.GetOwinContext().Authentication;
                //    var userIdentity = manager.CreateIdentity(identityUser,
                //                               DefaultAuthenticationTypes.ApplicationCookie);
                //    authenticationManager.SignIn(new AuthenticationProperties() { },
                //                                 userIdentity);
                //}
                CreateTokenProvider(manager, EMAIL_CONFIRMATION);
                var code = manager.GenerateEmailConfirmationToken(identityUser.Id);
                var callbackUrl = Url.Action("ConfirmEmail", "Home",
                                                new { userId = identityUser.Id, code = code },
                                                    protocol: Request.Url.Scheme);

                string email = "Please confirm your account by clicking this link: <a href=\""
                                + callbackUrl + "\">Confirm Registration</a>";
                ViewBag.FakeConfirmation = email;
            

            //--------------------------------------------------
            EmailMessage msg = new EmailMessage();
            msg.Sender = newUser.Email;
            msg.Subject = "Registration of " + identityUser;
            msg.Body = email;
            Mailer mailer = new Mailer();
            string response = mailer.EmailFromArvixe(new EmailMessage(
                    msg.Sender, msg.Subject, msg.Body));
            ViewBag.Response = response;
            bool success = response.Contains("Success");

            //--------------------------------------------------
              }
            return View();
        }


        [Authorize]
        public ActionResult SecureArea()
        {
            return View();
        }

        public ActionResult Logout()
        {
            var ctx = Request.GetOwinContext();
            var authenticationManager = ctx.Authentication;
            authenticationManager.SignOut();
            return RedirectToAction("Index", "Home");
        }



        bool ValidLogin(Login login)
        {
            UserStore<IdentityUser> userStore = new UserStore<IdentityUser>();
            UserManager<IdentityUser> userManager = new UserManager<IdentityUser>(userStore)
            {
                UserLockoutEnabledByDefault = true,
                DefaultAccountLockoutTimeSpan = new TimeSpan(0, 0, 0),
                MaxFailedAccessAttemptsBeforeLockout = 10
            };
            var user = userManager.FindByName(login.UserName);

            if (user == null)
                return false;

            // User is locked out.
            if (userManager.SupportsUserLockout && userManager.IsLockedOut(user.Id))
                return false;

            // Validated user was locked out but now can be reset.
            //if (userManager.CheckPassword(user, login.Password))
            if (userManager.CheckPassword(user, login.Password)
            && userManager.IsEmailConfirmed(user.Id))
            { if (userManager.SupportsUserLockout
                 && userManager.GetAccessFailedCount(user.Id) > 0)
                {
                    userManager.ResetAccessFailedCount(user.Id);
                }
            }
            // Login is invalid so increment failed attempts.
            else {
                bool lockoutEnabled = userManager.GetLockoutEnabled(user.Id);
                if (userManager.SupportsUserLockout && userManager.GetLockoutEnabled(user.Id))
                {
                    userManager.AccessFailed(user.Id);
                    return false;
                }
            }
            return true;
        }


        void CreateTokenProvider(UserManager<IdentityUser> manager, string tokenType)
        {
            manager.UserTokenProvider = new EmailTokenProvider<IdentityUser>();
        }


        public ActionResult ConfirmEmail(string userID, string code)
        {
            var userStore = new UserStore<IdentityUser>();
            UserManager<IdentityUser> manager = new UserManager<IdentityUser>(userStore);
            var user = manager.FindById(userID);
            CreateTokenProvider(manager, EMAIL_CONFIRMATION);
            try
            {
                IdentityResult result = manager.ConfirmEmail(userID, code);
                if (result.Succeeded)
                    ViewBag.Message = "You are now registered!";
            }
            catch
            {
                ViewBag.Message = "Validation attempt failed!";
            }
            return View();
        }


        [HttpGet]
        public ActionResult AddRole()
        {
            return View();
        }

        [HttpPost]
        public ActionResult AddRole(AspNetRole role)
        {
            Security1Entities context = new Security1Entities();
            context.AspNetRoles.Add(role);
            context.SaveChanges();
            return View();
        }

        [HttpGet]
        public ActionResult AddUserToRole()
        {
            return View();
        }
        [HttpPost]
        public ActionResult AddUserToRole(string userName, string roleName)
        {
            Security1Entities context = new Security1Entities();
            AspNetUser user = context.AspNetUsers
                             .Where(u => u.UserName == userName).FirstOrDefault();
            AspNetRole role = context.AspNetRoles
                             .Where(r => r.Name == roleName).FirstOrDefault();

            user.AspNetRoles.Add(role);
            context.SaveChanges();
            return View();
        }

        [Authorize(Roles = "Admin")]
        // To allow more than one role access use syntax like the following:
        // [Authorize(Roles="Admin, Staff")]
        public ActionResult AdminOnly()
        {
            return View();
        }

        [Authorize(Roles = "Admin, Employee")]
        // To allow more than one role access use syntax like the following:
        // [Authorize(Roles="Admin, Staff")]
        public ActionResult ContractorArea()
        {
            return View();
        }

        [HttpGet]
        public ActionResult ForgotPassword()
        {
            return View();
        }
        [HttpPost]
        public ActionResult ForgotPassword(string email)
        {

            CaptchaHelper captchaHelper = new CaptchaHelper();
            string captchaResponse = captchaHelper.CheckRecaptcha();
            ViewBag.Message = captchaResponse;


            var userStore = new UserStore<IdentityUser>();
            UserManager<IdentityUser> manager = new UserManager<IdentityUser>(userStore);
            var user = manager.FindByEmail(email);

            if (user == null)
            {
                ViewBag.Message = "Email not found.";
                return View();
            }

            if (captchaResponse == "You may proceed")
            {

                CreateTokenProvider(manager, PASSWORD_RESET);

                var code = manager.GeneratePasswordResetToken(user.Id);
                var callbackUrl = Url.Action("ResetPassword", "Home",
                                             new { userId = user.Id, code = code },
                                             protocol: Request.Url.Scheme);
                string emailMessage = "Please reset your password by clicking <a href=\""
                                         + callbackUrl + "\">here</a>";

                ViewBag.EmailMessage = emailMessage;

                //--------------------------------------------------

                EmailMessage msg = new EmailMessage();
                msg.Sender = email;
                msg.Subject = "Password Reset for " + User.Identity.Name + "(" + email + ")";
                msg.Body = emailMessage;
                Mailer mailer = new Mailer();
                string response = mailer.EmailFromArvixe(new EmailMessage(
                        msg.Sender, msg.Subject, msg.Body));
                ViewBag.Message = response + " <a href=\"jamped.com\">jamped.com</a>";
                //bool success = response.Contains("Success");

                //--------------------------------------------------
            }
            return View();
            
        }

        [HttpGet]
        public ActionResult ResetPassword(string userID, string code)
        {
            ViewBag.PasswordToken = code;
            ViewBag.UserID = userID;
            return View();
        }
        [HttpPost]
        public ActionResult ResetPassword(string password, string passwordConfirm,
                                          string passwordToken, string userID)
        {

            var userStore = new UserStore<IdentityUser>();
            UserManager<IdentityUser> manager = new UserManager<IdentityUser>(userStore);
            var user = manager.FindById(userID);
            CreateTokenProvider(manager, PASSWORD_RESET);

            IdentityResult result = manager.ResetPassword(userID, passwordToken, password);
            if (result.Succeeded)
                ViewBag.Message = "The password has been reset.";
            else
                ViewBag.Message = "The password has not been reset.";
            return View();
        }
    }
}
