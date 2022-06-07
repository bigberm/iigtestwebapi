﻿using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using iigtestwebapi.Models;
using iigtestwebapi.Providers;
using Microsoft.Owin.Security;
using System.Security.Claims;
using System.Linq;

namespace iigtestwebapi
{
    // Configure the application user manager used in this application. UserManager is defined in ASP.NET Identity and is used by the application.

    public class ApplicationUserManager : UserManager<ApplicationUser>
    {
        private const int PASSWORD_HISTORY_LIMIT = 5;//Used password limit 5 times
        public ApplicationUserManager(IUserStore<ApplicationUser> store)
            : base(store)
        {
        }

        public static ApplicationUserManager Create(IdentityFactoryOptions<ApplicationUserManager> options, IOwinContext context)
        {
            var manager = new ApplicationUserManager(new UserStore<ApplicationUser>(context.Get<ApplicationDbContext>()));
            
            // Configure validation logic for usernames
            manager.UserValidator = new UserValidator<ApplicationUser>(manager)
            {
                AllowOnlyAlphanumericUserNames = false,
                RequireUniqueEmail = true
            };
            // Configure validation logic for passwords
            manager.PasswordValidator = new PasswordValidator
            {
                RequiredLength = 6,
                RequireNonLetterOrDigit = true,
                RequireDigit = true,
                RequireLowercase = true,
                RequireUppercase = true
            };
            var dataProtectionProvider = options.DataProtectionProvider;
            if (dataProtectionProvider != null)
            {
                manager.UserTokenProvider = new DataProtectorTokenProvider<ApplicationUser>(dataProtectionProvider.Create("ASP.NET Identity"));
            }
            return manager;
        }

        //By customize
     

        public override async Task<IdentityResult> ChangePasswordAsync(string userId, string currentPassword, string newPassword)
        {
            if (await IsPasswordHistory(userId, newPassword))
                return await Task.FromResult(IdentityResult.Failed("Cannot reuse old password"));
            var result = await base.ChangePasswordAsync(userId, currentPassword, newPassword);
            if (result.Succeeded)
            {
                ApplicationUser user = await FindByIdAsync(userId);
                user.UserPasswordHistory.Add(new UserPasswordHistory() { UserID = user.Id, HashPassword = PasswordHasher.HashPassword(newPassword) });
                return await UpdateAsync(user);
            }
            return result;
        }

        public override async Task<IdentityResult> ResetPasswordAsync(string userId, string token, string newPassword)
        {
            if (await IsPasswordHistory(userId, newPassword))
                return await Task.FromResult(IdentityResult.Failed("Cannot reuse old password"));
            var result = await base.ResetPasswordAsync(userId, token, newPassword);
            if (result.Succeeded)
            {
                ApplicationUser user = await FindByIdAsync(userId);
                user.UserPasswordHistory.Add(new UserPasswordHistory() { UserID = user.Id, HashPassword = PasswordHasher.HashPassword(newPassword) });
                return await UpdateAsync(user);
            }
            return result;
        }

        private async Task<bool> IsPasswordHistory(string userId, string newPassword)
        {
            var user = await FindByIdAsync(userId);
            if (user.UserPasswordHistory.OrderByDescending(o => o.CreatedDate).Select(s => s.HashPassword)
                .Take(PASSWORD_HISTORY_LIMIT)
                .Where(w => PasswordHasher.VerifyHashedPassword(w, newPassword) != PasswordVerificationResult.Failed).Any())
                return true;
            return false;
        }

        public Task AddToPasswordHistoryAsync(ApplicationUser user, string password)
        {
            user.UserPasswordHistory.Add(new UserPasswordHistory() { UserID = user.Id, HashPassword = password });
            return UpdateAsync(user);
        }

        //public  async Task CreatePasswordHistoryAsync(ApplicationUser appuser)
        //{
        //   // await base.CreateAsync(appuser);
        //    await AddToUsedPasswordAsync(appuser, appuser.PasswordHash);
        //}

        //public Task AddToUsedPasswordAsync(ApplicationUser appuser, string userpassword)
        //{
        //    appuser.UserPasswordHistory.Add(new UserPasswordHistory() { UserID = appuser.Id, HashPassword = userpassword });
        //    return UpdateAsync(appuser);
        //}



        // Configure the application sign-in manager which is used in this application.
        public class ApplicationSignInManager : SignInManager<ApplicationUser, string>
        {
            public ApplicationSignInManager(ApplicationUserManager userManager, IAuthenticationManager authenticationManager)
                : base(userManager, authenticationManager)
            {
            }

            public override Task<ClaimsIdentity> CreateUserIdentityAsync(ApplicationUser user)
            {
                return user.GenerateUserIdentityAsync((ApplicationUserManager)UserManager);
            }

            public static ApplicationSignInManager Create(IdentityFactoryOptions<ApplicationSignInManager> options, IOwinContext context)
            {
                return new ApplicationSignInManager(context.GetUserManager<ApplicationUserManager>(), context.Authentication);
            }
        }
    }
}
