using Microsoft.AspNetCore.Authentication;
using System;

namespace DiscourseAuthentication
{
	public class DiscourseOptions : RemoteAuthenticationOptions
	{
		public DiscourseOptions()
		{
			Events = new DiscourseEvents();
		}

		public override void Validate()
		{
			base.Validate();

			if (string.IsNullOrEmpty(AuthenticationSecret))
			{
				throw new ArgumentException("Authentication secret is required");
			}

			if (string.IsNullOrEmpty(AuthorizationEndpoint))
			{
				throw new ArgumentException("Authorization endpoint is required");
			}
		}

		/// <summary>
		/// Gets or sets the URI where the client will be redirected to authenticate.
		/// </summary>
		public string AuthorizationEndpoint { get; set; }

		public string AuthenticationSecret { get; set; }

		public new DiscourseEvents Events
		{
			get { return (DiscourseEvents)base.Events; }
			set { base.Events = value; }
		}

		public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }
	}
}