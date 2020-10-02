using DiscourseAuthentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
	public static class DiscourseExtensions
	{
		public static AuthenticationBuilder AddDiscourse(this AuthenticationBuilder builder, string authenticationScheme, Action<DiscourseOptions> configureOptions)
			=> builder.AddDiscourse<DiscourseOptions, DiscourseHandler<DiscourseOptions>>(authenticationScheme, configureOptions);

		public static AuthenticationBuilder AddDiscourse(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<DiscourseOptions> configureOptions)
			=> builder.AddDiscourse<DiscourseOptions, DiscourseHandler<DiscourseOptions>>(authenticationScheme, displayName, configureOptions);

		public static AuthenticationBuilder AddDiscourse<TOptions, THandler>(this AuthenticationBuilder builder, string authenticationScheme, Action<TOptions> configureOptions)
			where TOptions : DiscourseOptions, new()
			where THandler : DiscourseHandler<TOptions>
			=> builder.AddDiscourse<TOptions, THandler>(authenticationScheme, DiscourseDefaults.DisplayName, configureOptions);

		public static AuthenticationBuilder AddDiscourse<TOptions, THandler>(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<TOptions> configureOptions)
			where TOptions : DiscourseOptions, new()
			where THandler : DiscourseHandler<TOptions>
		{
			builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<TOptions>, DiscoursePostConfigureOptions<TOptions, THandler>>());
			return builder.AddRemoteScheme<TOptions, THandler>(authenticationScheme, displayName, configureOptions);
		}
	}
}
