using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Web.Http.ModelBinding;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using iigtestwebapi.Models;
using iigtestwebapi.Providers;
using iigtestwebapi.Results;
using static iigtestwebapi.ApplicationUserManager;
using System.Web.Hosting;
using System.Configuration;
using System.Linq;
using System.IO;
using System.Net;
using System.Net.Http.Headers;

namespace iigtestwebapi.Controllers
{
   // [Authorize]
    [RoutePrefix("api/Account")]
    public class AccountController : ApiController
    {
        private const string LocalLoginProvider = "Local";
        private ApplicationUserManager _userManager;
       
        private ApplicationSignInManager _signInManager;

        public AccountController()
        {          
        }
        public AccountController(ApplicationUserManager userManager,  ApplicationSignInManager signInManager,
            ISecureDataFormat<AuthenticationTicket> accessTokenFormat)
        {
            UserManager = userManager;
            AccessTokenFormat = accessTokenFormat;
            SignInManager = signInManager;
        }
    
        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? Request.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }
        public ApplicationSignInManager SignInManager
        {
            get
            {
                return _signInManager ?? Request.GetOwinContext().Get<ApplicationSignInManager>();
            }
            private set
            {
                _signInManager = value;
            }
        }
        public ISecureDataFormat<AuthenticationTicket> AccessTokenFormat { get; private set; }

        //// GET api/Account/UserInfo
        //[HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        //[Route("UserInfo")]
        //public UserInfoViewModel GetUserInfo()
        //{
        //    ExternalLoginData externalLogin = ExternalLoginData.FromIdentity(User.Identity as ClaimsIdentity);

        //    return new UserInfoViewModel
        //    {
        //        Email = User.Identity.GetUserName(),
        //        HasRegistered = externalLogin == null,
        //        LoginProvider = externalLogin != null ? externalLogin.LoginProvider : null
        //    };
        //}
        [HttpGet]
        [AllowAnonymous]
        [Route("GetUserNameIsExist")]
        public async Task<bool> GetUserNameIsExist(string username)
        {
            //
            var userdata = await UserManager.FindByNameAsync(username);
            if (userdata != null)
                return true;

            return false;
        }
        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [Route("Login")]
        public async Task<IHttpActionResult> GetLogin(LoginViewModel model)
        {

            var result = await SignInManager.PasswordSignInAsync(model.UserName, model.Password, false, shouldLockout: false);
            switch (result)
            {
                case SignInStatus.Success:
                    return Ok();
                    
            }
            return Ok();
        }
        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
       
        public async Task<IHttpActionResult> Login(LoginViewModel model, string returnUrl)
        {
            // This doesn't count login failures towards account lockout
            // To enable password failures to trigger account lockout, change to shouldLockout: true
            var result = await SignInManager.PasswordSignInAsync(model.UserName, model.Password,false, shouldLockout: false);
            switch (result)
            {
                case SignInStatus.Success:
                    return Ok();
            //    //case SignInStatus.LockedOut:
            //    //    return View("Lockout");
            //    //case SignInStatus.RequiresVerification:
            //    //    return RedirectToAction("SendCode", new { ReturnUrl = returnUrl, RememberMe = model.RememberMe });
            //    //case SignInStatus.Failure:
            //    //default:
            //    //    ModelState.AddModelError("", "Invalid login attempt.");
            //    //    return View(model);
            }
            return Ok();
        }

        // POST api/Account/Logout
        [Route("Logout")]
        public IHttpActionResult Logout()
        {
            Authentication.SignOut(CookieAuthenticationDefaults.AuthenticationType);
            return Ok();
        }
        [HttpGet]
        [Route("GetUserInfo")]
        public async Task<ApplicationUser> GetUserInfo(string userId)
        {
            var userData = await UserManager.FindByIdAsync(userId);

            return userData;

        }
        [HttpGet]
        [Route("GetProfileImage")]
        public  HttpResponseMessage GetProfileImage(string userId)
        {
            try
            {
                string filePath = HostingEnvironment.MapPath(ConfigurationManager.AppSettings["FileUploadLocation"]);
                HttpResponseMessage response = new HttpResponseMessage();
                var userData =  UserManager.FindById(userId);
                if (userData != null)
                {

                    MemoryStream stream = new MemoryStream(userData.profileImage);
                    response.Content = new StreamContent(stream);

                }
                return response;
            }
            catch (Exception ex)
            {
                return  Request.CreateResponse(HttpStatusCode.BadRequest, ex);
            }

        }
        [HttpPost]
        [Route("UploadProfileImage")]
        public async Task<ApplicationUser> UploadProfileImage()
        {

            ApplicationUser userInfo = null;
            try
            {
                var fileuploadPath = HostingEnvironment.MapPath(ConfigurationManager.AppSettings["FileUploadLocation"]);

                var provider = new MultipartFormDataStreamProvider(fileuploadPath);

                var content = new StreamContent(HttpContext.Current.Request.GetBufferlessInputStream(true));
                foreach (var header in Request.Content.Headers)
                {
                    content.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }

                await content.ReadAsMultipartAsync(provider);


                //Code for renaming the random file to Original file name
                string userId = provider.FormData.GetValues("userId").SingleOrDefault();
                string uploadingFileName = provider.FileData.Select(x => x.LocalFileName).FirstOrDefault();
                string originalFileName = String.Concat(fileuploadPath, "\\" + userId + "_" + (provider.Contents[0].Headers.ContentDisposition.FileName).Trim(new Char[] { '"' }));
                string fileName = userId + "_" + provider.Contents[0].Headers.ContentDisposition.FileName.Trim(new Char[] { '"' });



                if (File.Exists(originalFileName))
                {
                    File.Delete(originalFileName);
                }

                File.Move(uploadingFileName, originalFileName);
                //Code renaming ends...

                //update path name to user profile 
                if (userId != null && userId != "")
                {
                     userInfo = await UserManager.FindByIdAsync(userId);
                    byte[] imageData = null;

                
                    if (userInfo != null)
                    {
                      
                        using (FileStream fs = new FileStream(originalFileName, FileMode.Open, FileAccess.Read))
                        {
                            imageData = new Byte[fs.Length];
                            fs.Read(imageData, 0, (int)fs.Length);
                        }

                        if (imageData != null)
                        {
                            userInfo.profileImage = imageData;
                        }

                        await UserManager.UpdateAsync(userInfo);
                    }

                    //Delete temp
                    if (File.Exists(originalFileName))
                    {
                        File.Delete(originalFileName);
                    }
                }

                return userInfo;
            }
            catch (Exception ex)
            {
                return null;
            }

        }

       

        // GET api/Account/ManageInfo?returnUrl=%2F&generateState=true
        [Route("ManageInfo")]
        public async Task<ManageInfoViewModel> GetManageInfo(string returnUrl, bool generateState = false)
        {
            IdentityUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

            if (user == null)
            {
                return null;
            }

            List<UserLoginInfoViewModel> logins = new List<UserLoginInfoViewModel>();

            foreach (IdentityUserLogin linkedAccount in user.Logins)
            {
                logins.Add(new UserLoginInfoViewModel
                {
                    LoginProvider = linkedAccount.LoginProvider,
                    ProviderKey = linkedAccount.ProviderKey
                });
            }

            if (user.PasswordHash != null)
            {
                logins.Add(new UserLoginInfoViewModel
                {
                    LoginProvider = LocalLoginProvider,
                    ProviderKey = user.UserName,
                });
            }

            return new ManageInfoViewModel
            {
                LocalLoginProvider = LocalLoginProvider,
                Email = user.UserName,
                Logins = logins,
               // ExternalLoginProviders = GetExternalLogins(returnUrl, generateState)
            };
        }

        // POST api/Account/ChangePassword
        [Route("ChangePassword")]
        public async Task<IHttpActionResult> ChangePassword(ChangePasswordBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result = await UserManager.ChangePasswordAsync(User.Identity.GetUserId(), model.OldPassword,
                model.NewPassword);
            
            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // POST api/Account/SetPassword
        [Route("SetPassword")]
        public async Task<IHttpActionResult> SetPassword(SetPasswordBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result = await UserManager.AddPasswordAsync(User.Identity.GetUserId(), model.NewPassword);

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("Register")]
        public async Task<IHttpActionResult> RegisterUpload()
        {

            try
            {
                RegisterBindingModel model = new RegisterBindingModel();
                var fileuploadPath = HostingEnvironment.MapPath(ConfigurationManager.AppSettings["FileUploadLocation"]);

                var provider = new MultipartFormDataStreamProvider(fileuploadPath);

                var content = new StreamContent(HttpContext.Current.Request.GetBufferlessInputStream(true));
                foreach (var header in Request.Content.Headers)
                {
                    content.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }

                await content.ReadAsMultipartAsync(provider);

                string uploadingFileName = provider.FileData.Select(x => x.LocalFileName).FirstOrDefault();
                string originalFileName = String.Concat(fileuploadPath, "\\" + model.UserName + "_" + (provider.Contents[0].Headers.ContentDisposition.FileName).Trim(new Char[] { '"' }));
                string fileName = model.UserName + "_" + provider.Contents[0].Headers.ContentDisposition.FileName.Trim(new Char[] { '"' });


                model.Email = provider.FormData.GetValues("Email").SingleOrDefault();
                model.UserName = provider.FormData.GetValues("UserName").SingleOrDefault();
                model.LastName = provider.FormData.GetValues("LastName").SingleOrDefault();
                model.FirstName = provider.FormData.GetValues("FirstName").SingleOrDefault();
                model.Password = provider.FormData.GetValues("Password").SingleOrDefault();
                model.ConfirmPassword = provider.FormData.GetValues("ConfirmPassword").SingleOrDefault();

                if (File.Exists(originalFileName))
                {
                    File.Delete(originalFileName);
                }

                File.Move(uploadingFileName, originalFileName);
                //Code renaming ends...

                //update path name to company profile 
                if (model.UserName != null && model.UserName != "")
                {
                    byte[] imageData = null;


                    using (FileStream fs = new FileStream(originalFileName, FileMode.Open, FileAccess.Read))
                    {
                        imageData = new Byte[fs.Length];
                        fs.Read(imageData, 0, (int)fs.Length);
                    }

                    if (imageData != null)
                    {
                        model.ProfileImage = imageData;
                    }


                }
                //Delete temp file
                if (File.Exists(originalFileName))
                {
                    File.Delete(originalFileName);
                }

                var user = new ApplicationUser() { UserName = model.UserName, Email = model.Email, firstName = model.FirstName, lastName = model.LastName, profileImage = model.ProfileImage };

                IdentityResult result = await UserManager.CreateAsync(user, model.Password);

                if (!result.Succeeded)
                {
                    if (result.Errors != null)
                    {
                        string errMsg = "";
                        foreach (string error in result.Errors)
                        {
                            errMsg=errMsg+" "+error;
                        }
                        return Ok(errMsg);
                    }
                   
                }

            }
            catch (Exception ex)
            {
                return Ok(ex.Message);
            }


            return Ok("Success");
        }
        //// POST api/Account/RegisterExternal
        //[OverrideAuthentication]
        //[HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        //[Route("RegisterExternal")]
        //public async Task<IHttpActionResult> RegisterExternal(RegisterExternalBindingModel model)
        //{
        //    if (!ModelState.IsValid)
        //    {
        //        return BadRequest(ModelState);
        //    }

        //    var info = await Authentication.GetExternalLoginInfoAsync();
        //    if (info == null)
        //    {
        //        return InternalServerError();
        //    }

        //    var user = new ApplicationUser() { UserName = model.Email, Email = model.Email };

        //    IdentityResult result = await UserManager.CreateAsync(user);
        //    if (!result.Succeeded)
        //    {
        //        return GetErrorResult(result);
        //    }

        //    result = await UserManager.AddLoginAsync(user.Id, info.Login);
        //    if (!result.Succeeded)
        //    {
        //        return GetErrorResult(result); 
        //    }
        //    return Ok();
        //}

        protected override void Dispose(bool disposing)
        {
            if (disposing && _userManager != null)
            {
                _userManager.Dispose();
                _userManager = null;
            }

            base.Dispose(disposing);
        }

        #region Helpers

        private IAuthenticationManager Authentication
        {
            get { return Request.GetOwinContext().Authentication; }
        }

        private IHttpActionResult GetErrorResult(IdentityResult result)
        {
            if (result == null)
            {
                return InternalServerError();
            }

            if (!result.Succeeded)
            {
                if (result.Errors != null)
                {
                    foreach (string error in result.Errors)
                    {
                        ModelState.AddModelError("", error);
                    }
                }

                if (ModelState.IsValid)
                {
                    // No ModelState errors are available to send, so just return an empty BadRequest.
                    return BadRequest();
                }

                return BadRequest(ModelState);
            }

            return null;
        }

        private class ExternalLoginData
        {
            public string LoginProvider { get; set; }
            public string ProviderKey { get; set; }
            public string UserName { get; set; }

            public IList<Claim> GetClaims()
            {
                IList<Claim> claims = new List<Claim>();
                claims.Add(new Claim(ClaimTypes.NameIdentifier, ProviderKey, null, LoginProvider));

                if (UserName != null)
                {
                    claims.Add(new Claim(ClaimTypes.Name, UserName, null, LoginProvider));
                }

                return claims;
            }

            public static ExternalLoginData FromIdentity(ClaimsIdentity identity)
            {
                if (identity == null)
                {
                    return null;
                }

                Claim providerKeyClaim = identity.FindFirst(ClaimTypes.NameIdentifier);

                if (providerKeyClaim == null || String.IsNullOrEmpty(providerKeyClaim.Issuer)
                    || String.IsNullOrEmpty(providerKeyClaim.Value))
                {
                    return null;
                }

                if (providerKeyClaim.Issuer == ClaimsIdentity.DefaultIssuer)
                {
                    return null;
                }

                return new ExternalLoginData
                {
                    LoginProvider = providerKeyClaim.Issuer,
                    ProviderKey = providerKeyClaim.Value,
                    UserName = identity.FindFirstValue(ClaimTypes.Name)
                };
            }
        }

        private static class RandomOAuthStateGenerator
        {
            private static RandomNumberGenerator _random = new RNGCryptoServiceProvider();

            public static string Generate(int strengthInBits)
            {
                const int bitsPerByte = 8;

                if (strengthInBits % bitsPerByte != 0)
                {
                    throw new ArgumentException("strengthInBits must be evenly divisible by 8.", "strengthInBits");
                }

                int strengthInBytes = strengthInBits / bitsPerByte;

                byte[] data = new byte[strengthInBytes];
                _random.GetBytes(data);
                return HttpServerUtility.UrlTokenEncode(data);
            }
        }


        #endregion
    }
}
