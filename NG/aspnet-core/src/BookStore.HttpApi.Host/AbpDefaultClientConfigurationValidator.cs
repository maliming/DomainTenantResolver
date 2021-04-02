using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using IdentityServer4.Configuration;
using IdentityServer4.Models;
using IdentityServer4.Validation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Volo.Abp.DependencyInjection;
using Volo.Abp.Text.Formatting;

namespace BookStore
{
    [Dependency(ReplaceServices = true)]
    [ExposeServices(typeof(IClientConfigurationValidator))]
    public class AbpDefaultClientConfigurationValidator : DefaultClientConfigurationValidator, ITransientDependency
    {
        public AbpDefaultClientConfigurationValidator(IdentityServerOptions options)
            : base(options)
        {
        }

        protected override Task ValidateAllowedCorsOriginsAsync(ClientConfigurationValidationContext context)
        {
            context.Client.AllowedCorsOrigins.RemoveAll(x => x.Contains("{0}", StringComparison.OrdinalIgnoreCase));
            return base.ValidateAllowedCorsOriginsAsync(context);
        }
    }

    public static class AbpIdentityServerServiceCollectionExtensions
    {
        public static void AddAbpStrictRedirectUriValidatorPatch(this IServiceCollection services)
        {
            services.Replace(ServiceDescriptor.Transient<IRedirectUriValidator, MyStrictRedirectUriValidator>());
        }
    }

    public class MyStrictRedirectUriValidator : StrictRedirectUriValidator
    {
        public override async Task<bool> IsRedirectUriValidAsync(string requestedUri, Client client)
        {
            var isAllowed = await base.IsRedirectUriValidAsync(requestedUri, client);
            return isAllowed || await IsRedirectUriValidWithDomainFormatsAsync(client.RedirectUris, requestedUri);
        }

        public override async Task<bool> IsPostLogoutRedirectUriValidAsync(string requestedUri, Client client)
        {
            var isAllowed = await base.IsPostLogoutRedirectUriValidAsync(requestedUri, client);
            return isAllowed || await IsRedirectUriValidWithDomainFormatsAsync(client.PostLogoutRedirectUris, requestedUri);
        }

        protected virtual Task<bool> IsRedirectUriValidWithDomainFormatsAsync(IEnumerable<string> uris, string requestedUri)
        {
            if (uris == null)
            {
                return Task.FromResult(false);
            }

            foreach (var url in uris)
            {
                var extractResult = FormattedStringValueExtracter.Extract(requestedUri, url, ignoreCase: true);
                if (extractResult.IsMatch)
                {
                    return Task.FromResult(true);
                }

                if (requestedUri.Contains(url.Replace("{0}.", ""), StringComparison.OrdinalIgnoreCase))
                {
                    return Task.FromResult(true);
                }
            }

            return Task.FromResult(false);
        }
    }
}
