using Microsoft.Owin;
using Microsoft.Owin.Security.Google;
using Owin;
using Sitecore.Diagnostics;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using Sitecore.Owin.Authentication.Services;
using System.Security.Claims;
using System.Web;

namespace OWINAuthentication.IdentityProviders
{
    public class GoogleAuthentication : IdentityProvidersProcessor
    {
        public GoogleAuthentication(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration) : base(federatedAuthenticationConfiguration)
        {

        }

        /// <summary>
        /// Identityprovidr name. Has to match the configuration
        /// </summary>
        protected override string IdentityProviderName
        {
            get { return "Google"; }
        }

        protected override void ProcessCore(IdentityProvidersArgs args)
        {
            Assert.ArgumentNotNull(args, "args");
            IdentityProvider identityProvider = this.GetIdentityProvider();
            string authenticationType = this.GetAuthenticationType();

            //Google
            var googleProvider = new GoogleOAuth2AuthenticationProvider()
            {
                OnAuthenticated = (context) =>
                {
                    // transform all claims
                    ClaimsIdentity identity = context.Identity;
                    foreach (Transformation current in identityProvider.Transformations)
                    {
                        current.Transform(identity, new TransformationContext(FederatedAuthenticationConfiguration, identityProvider));
                    }
                    return System.Threading.Tasks.Task.FromResult(0);
                },

                OnReturnEndpoint = (context) =>
                {
                    if (context.Request.Query["state"] != null)
                    {
                        var state = HttpUtility.ParseQueryString(context.Request.Query["state"]);
                        //todo: do something with it.
                    }

                    return System.Threading.Tasks.Task.FromResult(0);
                }
            };

            GoogleOAuth2AuthenticationOptions googleOptions = new GoogleOAuth2AuthenticationOptions();
            googleOptions.ClientId = "56239192454-rab6l2919d24umtvv2lim3te6h8rgo77.apps.googleusercontent.com";
            googleOptions.ClientSecret = "38AbD8PNy8bw8oaBvhHDyH8W";
            googleOptions.Provider = googleProvider;
            googleOptions.CallbackPath = new PathString("/signin-google");

            args.App.UseGoogleAuthentication(googleOptions);
        }
    }
}