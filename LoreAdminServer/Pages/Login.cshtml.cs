// Copyright Lukas Jech 2026. All Rights Reserved.

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using LoreBackend.Auth;
using LoreBackend.Database;

namespace LoreBackend.Pages
{
	[IgnoreAntiforgeryToken]
	public class LoginModel : PageModel
	{
		readonly LoreStore _store;
		readonly SessionStore _sessions;
		readonly ILogger<LoginModel> _logger;

		public LoginModel(LoreStore store, SessionStore sessions, ILogger<LoginModel> logger)
		{
			_store = store;
			_sessions = sessions;
			_logger = logger;
		}

		[BindProperty(SupportsGet = true)]
		public string? Session { get; set; }

		public string? Error { get; private set; }
		public string? SignedInUser { get; private set; }

		public void OnGet()
		{
		}

		public IActionResult OnPost(string username, string password)
		{
			User? user = _store.GetUser(username);
			if (user == null || !LoreStore.VerifyPassword(password, user.PasswordHash))
			{
				Response.StatusCode = 401;
				Error = "Invalid username or password.";
				return Page();
			}
			_sessions.Authorize(Session ?? "", user.Username);
			_logger.LogInformation("interactive login as {User}", user.Username);
			SignedInUser = user.Username;
			return Page();
		}
	}
}
