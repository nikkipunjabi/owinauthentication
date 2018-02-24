using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Sitecore.Diagnostics;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Identity;
using Sitecore.Owin.Authentication.Services;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Web;

namespace OWINAuthentication.Models
{
    public class CreateUniqueUser : DefaultExternalUserBuilder
    {

        public CreateUniqueUser(bool isPersistentUser) : base(isPersistentUser)
        {
        }

        [SuppressMessage("Microsoft.Naming", "CA1726:UsePreferredTerms", MessageId = "Login")]
        protected override string CreateUniqueUserName(UserManager<ApplicationUser> userManager, ExternalLoginInfo externalLoginInfo)
        {
            Assert.ArgumentNotNull((object)userManager, nameof(userManager));
            Assert.ArgumentNotNull((object)externalLoginInfo, nameof(externalLoginInfo));
            IdentityProvider identityProvider = this.FederatedAuthenticationConfiguration.GetIdentityProvider(externalLoginInfo.ExternalIdentity);
            if (identityProvider == null)
                throw new InvalidOperationException("Unable to retrieve identity provider for given identity");
            string domain = identityProvider.Domain;
            return domain + "\\" + externalLoginInfo.Email;

        }
    }
}