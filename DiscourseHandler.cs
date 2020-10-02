using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using System.Web;
using Base64UrlTextEncoder = Microsoft.AspNetCore.WebUtilities.Base64UrlTextEncoder;

namespace DiscourseAuthentication
{
	public class DiscourseHandler<TOptions> : RemoteAuthenticationHandler<TOptions> where TOptions : DiscourseOptions, new()
	{
		protected HttpClient Backchannel => Options.Backchannel;

		public DiscourseHandler(IOptionsMonitor<TOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
			: base(options, logger, encoder, clock)
		{ }

		protected new DiscourseEvents Events
		{
			get { return (DiscourseEvents)base.Events; }
			set { base.Events = value; }
		}

		protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new DiscourseEvents());

		protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
		{
			var query = Request.Query;

			byte[] challengeBytes;
			using var sha256mac = new HMACSHA256(Encoding.UTF8.GetBytes(Options.AuthenticationSecret));
			challengeBytes = sha256mac.ComputeHash(Encoding.UTF8.GetBytes(query["sso"]));

			byte[] signatureBytes = HexStringToByteArray(query["sig"]);

			if (signatureBytes.Length != challengeBytes.Length)
			{
				return HandleRequestResult.Fail("Signature mismatch");
			}

			for (int ix = 0; ix < signatureBytes.Length; ++ix)
			{
				if (signatureBytes[ix] != challengeBytes[ix])
				{
					return HandleRequestResult.Fail("Signature mismatch");
				}
			}

			var properties = Options.StateDataFormat.Unprotect(Request.Cookies["StateCookie"]);

			if (!ValidateCorrelationId(properties))
			{
				//return HandleRequestResult.Fail("Discourse correlation failed.", properties);
				Logger.LogError("Discourse correlation failed.");
			}

			string encodedData = Encoding.UTF8.GetString(Base64UrlTextEncoder.Decode(query["sso"]));

			var userInfo = HttpUtility.ParseQueryString(encodedData);

			var identity = new ClaimsIdentity(ClaimsIssuer);

			foreach (var key in userInfo.AllKeys)
			{
				switch (key)
				{
					case "groups":
						{
							var groups = userInfo[key].Split(",");
							foreach (var group in groups)
							{
								identity.AddClaim(new Claim(ClaimTypes.Role, group));
							}
							break;
						}
					case "name":
						{
							identity.AddClaim(new Claim(ClaimTypes.Name, Uri.UnescapeDataString(userInfo[key]).Replace('+', ' ')));
							break;
						}
					case "email":
						{
							identity.AddClaim(new Claim(ClaimTypes.Email, userInfo[key].ToLowerInvariant()));
							break;
						}
					case "external_id":
						{
							identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, userInfo[key]));
							break;
						}
					case "username":
						{
							identity.AddClaim(new Claim(ClaimTypes.UserData, userInfo[key]));
							break;
						}
					case "return_sso_url":
					case "nonce":
						break;
					default:
						identity.AddClaim(new Claim(key, userInfo[key]));
						break;
				}
			}

			if (string.IsNullOrEmpty(query["returnUrl"]) == false) {
				properties.RedirectUri = query["returnUrl"];
			}

			var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), properties, Scheme.Name);

			return HandleRequestResult.Success(ticket);
		}

		protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
		{
			if (string.IsNullOrEmpty(properties.RedirectUri))
			{
				properties.RedirectUri = OriginalPathBase + OriginalPath + Request.QueryString;
			}

			GenerateCorrelationId(properties);

			var authorizationEndpoint = BuildChallengeUrl(properties, BuildRedirectUri(Options.CallbackPath));
			var redirectContext = new RedirectContext<DiscourseOptions>(
				Context, Scheme, Options,
				properties, authorizationEndpoint);
			await Events.RedirectToAuthorizationEndpoint(redirectContext);

			var location = Context.Response.Headers[HeaderNames.Location];
			if (location == StringValues.Empty)
			{
				location = "(not set)";
			}
			var cookie = Context.Response.Headers[HeaderNames.SetCookie];
			if (cookie == StringValues.Empty)
			{
				cookie = "(not set)";
			}
			Logger.HandleChallenge(location, cookie);
		}

		protected virtual string BuildChallengeUrl(AuthenticationProperties properties, string redirectUrl)
		{
			var bytes = new byte[16];
			RandomNumberGenerator.Fill(bytes);
			var nonce = Base64UrlTextEncoder.Encode(bytes);

			properties.Items.Add("nonce", nonce);

			string payload = Convert.ToBase64String(Encoding.UTF8.GetBytes($"nonce={nonce}&return_sso_url={redirectUrl}?returnUrl={properties.RedirectUri}"));

			using var sha256mac = new HMACSHA256(Encoding.UTF8.GetBytes(Options.AuthenticationSecret));
			var challengeBytes = sha256mac.ComputeHash(Encoding.UTF8.GetBytes(payload));
			var codeChallenge = BitConverter.ToString(challengeBytes).Replace("-", "").ToLower();

			var parameters = new Dictionary<string, string>
			{
				{ "sso", Uri.EscapeUriString(payload) },
				{ "sig", codeChallenge },
			};

			Response.Cookies.Append("StateCookie", Options.StateDataFormat.Protect(properties));

			return QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, parameters);
		}

		private static byte[] HexStringToByteArray(string hex)
		{
			byte[] bytes = new byte[hex.Length / 2];
			for (int i = 0; i < hex.Length; i += 2)
				bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
			return bytes;
		}
	}
}
