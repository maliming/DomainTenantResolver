using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentityServer4.Configuration;
using IdentityServer4.Models;
using IdentityServer4.Validation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Volo.Abp.DependencyInjection;
using Volo.Abp.Text.Formatting;

namespace Acme.BookStore
{
    //https://github.com/abpframework/abp/pull/7783/
    public static class AbpIdentityServerServiceCollectionExtensions
    {
        public static void AddAbpStrictRedirectUriValidator(this IServiceCollection services)
        {
            services.Replace(ServiceDescriptor.Transient<IRedirectUriValidator, AbpStrictRedirectUriValidator>());
        }
    }

    //https://github.com/abpframework/abp/pull/7783/
    public class AbpStrictRedirectUriValidator : StrictRedirectUriValidator
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

                if (url.Replace("{0}.", "").Equals(requestedUri))
                {
                    return Task.FromResult(true);
                }
            }

            return Task.FromResult(false);
        }
    }

    //TODO: PR?
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
            if (context.Client.AllowedCorsOrigins?.Any() == true)
            {
                foreach (var origin in context.Client.AllowedCorsOrigins)
                {
                    var fail = true;

                    if (!string.IsNullOrWhiteSpace(origin) && Uri.TryCreate(origin, UriKind.Absolute, out var uri))
                    {
                        if (uri.AbsolutePath == "/" && !origin.EndsWith("/"))
                        {
                            fail = false;
                        }
                    }

                    if (!string.IsNullOrWhiteSpace(origin) && origin.Contains("{0}"))
                    {
                        fail = false;
                    }

                    if (fail)
                    {
                        if (!string.IsNullOrWhiteSpace(origin))
                        {
                            context.SetError($"AllowedCorsOrigins contains invalid origin: {origin}");
                        }
                        else
                        {
                            context.SetError($"AllowedCorsOrigins contains invalid origin. There is an empty value.");
                        }
                        return Task.CompletedTask;
                    }
                }
            }

            return Task.CompletedTask;
        }
    }
}
