namespace OAuthService{
	class OAuth{

public void ConfigureServices(IServiceCollection services)
{
	services.AddControllers();
	services
		.AddAuthentication(options => {
			options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
			options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
			options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
		})
		.AddCookie(options =>
		{
			options.Cookie.Name = getConfigString("Cookie:Name");
			options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
			
			/*-----Not Working-----*/
			//options.Cookie.Domain = getConfigString("Shared:Domain");

			options.ExpireTimeSpan = TimeSpan.FromDays(14);
			options.Cookie.IsEssential = true;
			options.Cookie.SameSite = SameSiteMode.Lax;

			// hooking events just for reading runtime info
			options.Events = new CookieAuthenticationEvents
			{
				OnCheckSlidingExpiration = ctx =>
				{
					return Task.CompletedTask;
				},
				OnRedirectToAccessDenied = ctx =>
				{
					return Task.CompletedTask;
				},
				OnRedirectToLogout = ctx =>
				{
					return Task.CompletedTask;
				},
				OnRedirectToReturnUrl = ctx =>
				{
					return Task.CompletedTask;
				},
				OnSignedIn = ctx =>
				{
					return Task.CompletedTask;
				},
				OnSigningIn = ctx =>
				{
					return Task.CompletedTask;
				},
				OnSigningOut = ctx =>
				{
					return Task.CompletedTask;
				},
				OnValidatePrincipal = ctx =>
				{
					return Task.CompletedTask;
				},
				OnRedirectToLogin = ctx =>
				{
					return Task.CompletedTask;
				}
			};
		})
		.AddJwtBearer(options =>
		{
			options.TokenValidationParameters = new TokenValidationParameters
			{
				ValidateIssuer = false,
				ValidateAudience = false,
				ValidateIssuerSigningKey = true,
				ValidIssuer = Configuration.GetValue<string>("Jwt:Issuer"),
				ValidAudience = Configuration.GetValue<string>("Jwt:Audience"),
				IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(getConfigString("Jwt:EncryptionKey"))),
				RequireExpirationTime = true,
			};
		})
		.AddOAuth("Discord", options =>
		{
			options.AuthorizationEndpoint = getConfigString("Discord:AuthorizationEndpoint");
			options.Scope.Add("identify");
			options.CallbackPath = new PathString(getConfigString("Discord:CallbackPath"));
			options.ClientId = getConfigString("Discord:ClientId");
			options.ClientSecret = getConfigString("Discord:ClientSecret");
			options.TokenEndpoint = getConfigString("Discord:TokenEndpoint");
			options.UserInformationEndpoint = getConfigString("Discord:UserInformationEndpoint");

			options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "id");
			options.ClaimActions.MapJsonKey(ClaimTypes.Name, "username");
			options.AccessDeniedPath = "/discordauthfailed";
			options.Events = new OAuthEvents
			{
				OnCreatingTicket = async context =>
				{
					var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
					request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
					request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);

					var response = await context.Backchannel.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, context.HttpContext.RequestAborted);
					response.EnsureSuccessStatusCode();

					var user = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;

					context.RunClaimActions(user);
				}
			};
		});

}
}
}
