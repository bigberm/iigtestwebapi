using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Data.Entity;

using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;


namespace iigtestwebapi.Models
{
    // You can add profile data for the user by adding more properties to your ApplicationUser class, please visit https://go.microsoft.com/fwlink/?LinkID=317594 to learn more.
    public class ApplicationUser : IdentityUser
    {

        public ApplicationUser()
        {
            UserPasswordHistory = new List<UserPasswordHistory>();
        }
        public async Task<ClaimsIdentity> GenerateUserIdentityAsync(UserManager<ApplicationUser> manager, string authenticationType)
        {
            // Note the authenticationType must match the one defined in CookieAuthenticationOptions.AuthenticationType
            var userIdentity = await manager.CreateIdentityAsync(this, authenticationType);
            // Add custom user claims here
           // userIdentity.AddClaim(new Claim("userId", this.Id));
            

            return userIdentity;
        }

        public string firstName { get; set; }
        public string lastName { get; set; }
        public byte[] profileImage { get; set; }
        public virtual IList<UserPasswordHistory> UserPasswordHistory { get; set; }
        public async Task<ClaimsIdentity> GenerateUserIdentityAsync(UserManager<ApplicationUser> manager)
        {
            // Note the authenticationType must match the one defined in CookieAuthenticationOptions.AuthenticationType
            var userIdentity = await manager.CreateIdentityAsync(this, DefaultAuthenticationTypes.ApplicationCookie);
            // Add custom user claims here
            return userIdentity;
        }
    }

    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext()
            : base("DefaultConnection", throwIfV1Schema: false)
        {

        }
        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Properties<string>().Where(x => x.Name == "UserID").Configure(c => c.HasMaxLength(128));

            modelBuilder.Entity<UserPasswordHistory>().ToTable("UserPasswordHistory");

        }
        public static ApplicationDbContext Create()
        {

            return new ApplicationDbContext();
        }
       
    }
    public class UserPasswordHistory
    {
        public UserPasswordHistory()
        {
            CreatedDate = DateTimeOffset.Now;
        }

        [Key, Column(Order = 0)]
        public string HashPassword { get; set; }
        public DateTimeOffset CreatedDate { get; set; }
        [Key, Column(Order = 1)]
        public string UserID { get; set; }
        public virtual ApplicationUser AppUser { get; set; }
    }

}