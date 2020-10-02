using Microsoft.AspNetCore.Authentication;
using System;
using System.Threading.Tasks;

namespace DiscourseAuthentication
{
	public class DiscourseEvents : RemoteAuthenticationEvents
	{
		public Func<RedirectContext<DiscourseOptions>, Task> OnRedirectToAuthorizationEndpoint { get; set; } = context =>
		{
			context.Response.Redirect(context.RedirectUri);
			return Task.CompletedTask;
		};

		public virtual Task RedirectToAuthorizationEndpoint(RedirectContext<DiscourseOptions> context) => OnRedirectToAuthorizationEndpoint(context);
	}
}
