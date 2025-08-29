using Duende.IdentityModel.Client;
using Duende.IdentityModel.OidcClient;
using Duende.IdentityModel.OidcClient.Browser;
using Microsoft.Web.WebView2.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Windows;
using System.Xml;

namespace OidcClientSample
{
    public enum OAuthProvider
    {
        Okta,
        Auth0,
        EntraId
    }

    public enum AuthFlow
    {
        AuthorizationCode,
        ClientCredentials,
        OidcThenSaml
    }

    public class OAuthConfig
    {
        public string ClientId { get; set; }
        public string Authority { get; set; }
        public string RedirectUri { get; set; }
        public string[] Scopes { get; set; }
        public string PostLogoutRedirectUri { get; set; }
        // SAML specific properties
        public string SamlIdpUrl { get; set; }
        public string SamlSpEntityId { get; set; }
        public string SamlAcsUrl { get; set; }
        // Additional properties
        public string TenantId { get; set; }
    }

    public class ClientCredentialsConfig
    {
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string Authority { get; set; }
        public string TokenEndpoint { get; set; }
        public string[] Scopes { get; set; }
        public string Audience { get; set; }
        public string TenantId { get; set; }
    }

    public class SamlAssertionResult
    {
        public string SamlResponse { get; set; }
        public string RelayState { get; set; }
        public Dictionary<string, string> Attributes { get; set; }
        public DateTime ExpiresAt { get; set; }
        public bool IsValid { get; set; }
        public string Error { get; set; }
        public string RawSamlXml { get; set; }
    }

    public partial class MainWindow : Window
    {
        private OidcClient _oidcClient;
        private HttpClient _httpClient;
        private CustomWebViewBrowser _customBrowser;
        private OAuthProvider _currentProvider;
        private AuthFlow _currentFlow;
        private LoginResult _currentLoginResult;
        private SamlAssertionResult _currentSamlResult;
        private TaskCompletionSource<SamlAssertionResult> _samlCompletionSource;

        // OAuth Configurations
        private readonly OAuthConfig _oktaConfig = new OAuthConfig
        {
            ClientId = "0oatjdh6ftvpqibz8697",
            Authority = "https://integrator-1355928.okta.com/oauth2/default",
            RedirectUri = "https://localhost:5001/",
            PostLogoutRedirectUri = "https://localhost:5001/logout",
            Scopes = new[] { "openid", "profile", "email" },
            // SAML Configuration
            SamlIdpUrl = "https://integrator-1355928.okta.com/app/integrator-1355928_sts_1/exktpzi0kfWlX1Q0v697/sso/saml",
            SamlSpEntityId = "urn:altera:helios:wpf:client1",
            SamlAcsUrl = "http://localhost:5001/sso"
        };

        private readonly OAuthConfig _auth0Config = new OAuthConfig
        {
            ClientId = "EsiZ79MDvhK8fgNo7SPkU0HkW8TNcLIQ",
            Authority = "https://dev-t2bzy5qqqml628wg.us.auth0.com",
            RedirectUri = "https://localhost:5001/",
            PostLogoutRedirectUri = "https://localhost:5001/logout",
            Scopes = new[] { "openid", "profile", "email" },
            // SAML Configuration
            SamlIdpUrl = "https://dev-t2bzy5qqqml628wg.us.auth0.com/samlp/your-client-id",
            SamlSpEntityId = "urn:your-app:saml",
            SamlAcsUrl = "https://localhost:5001/saml/acs"
        };

        private readonly OAuthConfig _entraIdConfig = new OAuthConfig
        {
            ClientId = "your-entra-id-client-id", // Replace with actual client ID
            TenantId = "your-tenant-id", // Replace with actual tenant ID
            Authority = "https://login.microsoftonline.com/your-tenant-id/v2.0", // Will be updated dynamically
            RedirectUri = "https://localhost:5001/",
            PostLogoutRedirectUri = "https://localhost:5001/logout",
            Scopes = new[] { "openid", "profile", "email", "https://graph.microsoft.com/User.Read" },
            // SAML Configuration
            SamlIdpUrl = "https://login.microsoftonline.com/your-tenant-id/saml2",
            SamlSpEntityId = "urn:your-app:entra:saml",
            SamlAcsUrl = "https://localhost:5001/saml/acs"
        };

        // Client Credentials Configurations
        private readonly ClientCredentialsConfig _oktaClientCredentialsConfig = new ClientCredentialsConfig
        {
            ClientId = "0oati8dzjrPdwCfYZ697",
            ClientSecret = "8K8ysI7Na87tz4DEvDcW7PEp7rIphXO_2nHIsXudt4F1Vk9Q1SgYjN-BWyCKzKdx",
            Authority = "https://integrator-1355928.okta.com/oauth2/austos83vyikUni0E697",
            TokenEndpoint = "https://integrator-1355928.okta.com/oauth2/austos83vyikUni0E697/v1/token",
            Scopes = new[] { "read:data" },
            Audience = "api://default"
        };

        private readonly ClientCredentialsConfig _auth0ClientCredentialsConfig = new ClientCredentialsConfig
        {
            ClientId = "0jNPEUVe168UiAitRREkJMTYwwiVPSNs",
            ClientSecret = "1MGfPINLyDYZV4ghq-sbd0PTakxc2DidaE6kes92M4NNrpKtfdw6r7z6lyjSisPe",
            Authority = "https://dev-t2bzy5qqqml628wg.us.auth0.com",
            TokenEndpoint = "https://dev-t2bzy5qqqml628wg.us.auth0.com/oauth/token",
            Scopes = new[] { "read:users" },
            Audience = "https://dev-t2bzy5qqqml628wg.us.auth0.com/api/v2/"
        };

        private readonly ClientCredentialsConfig _entraIdClientCredentialsConfig = new ClientCredentialsConfig
        {
            ClientId = "your-entra-id-service-client-id",
            ClientSecret = "your-entra-id-service-client-secret",
            TenantId = "your-tenant-id",
            Authority = "https://login.microsoftonline.com/your-tenant-id/v2.0",
            TokenEndpoint = "https://login.microsoftonline.com/your-tenant-id/oauth2/v2.0/token",
            Scopes = new[] { "https://graph.microsoft.com/.default" }
        };

        public MainWindow()
        {
            InitializeComponent();
            InitializeHttpClient();
            InitializeWebView();
            UpdateEntraIdAuthority();
        }

        private void InitializeHttpClient()
        {
            _httpClient = new HttpClient();
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "OidcClient WPF Sample/1.0");
        }

        private void UpdateEntraIdAuthority()
        {
            // Update authority URLs based on tenant ID
            var tenantId = _entraIdConfig.TenantId;
            if (!string.IsNullOrEmpty(tenantId) && tenantId != "your-tenant-id")
            {
                _entraIdConfig.Authority = $"https://login.microsoftonline.com/{tenantId}/v2.0";
                _entraIdClientCredentialsConfig.Authority = $"https://login.microsoftonline.com/{tenantId}/v2.0";
                _entraIdClientCredentialsConfig.TokenEndpoint = $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token";
                _entraIdConfig.SamlIdpUrl = $"https://login.microsoftonline.com/{tenantId}/saml2";
            }
        }

        private async void InitializeWebView()
        {
            try
            {
                await WebView.EnsureCoreWebView2Async(null);
                _customBrowser = new CustomWebViewBrowser(WebView);

                StatusTextBlock.Text = "Ready for authentication with IdentityModel.OidcClient";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to initialize WebView2: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void LoginButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                LoginButton.IsEnabled = false;
                _currentProvider = (OAuthProvider)ProviderComboBox.SelectedIndex;
                _currentFlow = (AuthFlow)FlowComboBox.SelectedIndex;

                switch (_currentFlow)
                {
                    case AuthFlow.AuthorizationCode:
                        await PerformInteractiveLogin();
                        break;
                    case AuthFlow.ClientCredentials:
                        await PerformClientCredentialsFlow();
                        break;
                }
            }
            catch (Exception ex)
            {
                StatusTextBlock.Text = $"Login Error: {ex.Message}";
                TokenTextBox.Text = ex.ToString();
                LoginButton.IsEnabled = true;
            }
        }

        private async Task PerformInteractiveLogin()
        {
            try
            {
                StatusTextBlock.Text = $"Authenticating with {_currentProvider} using OidcClient Authorization Code Flow...";
                WebView.Visibility = Visibility.Visible;

                var config = GetCurrentOAuthConfig();

                // Create OidcClient options with explicit endpoint configuration
                var options = new OidcClientOptions
                {
                    Authority = config.Authority,
                    ClientId = config.ClientId,
                    RedirectUri = config.RedirectUri,
                    PostLogoutRedirectUri = config.PostLogoutRedirectUri,
                    Scope = string.Join(" ", config.Scopes),
                    Browser = _customBrowser,
                    FilterClaims = false,
                    LoadProfile = true,
                    Policy = new Policy
                    {
                        Discovery = new DiscoveryPolicy
                        {
                            RequireKeySet = false
                        }
                    }
                };

                // Provider-specific endpoint configuration
                if (_currentProvider == OAuthProvider.Okta)
                {
                    // For Okta, explicitly set the endpoints to avoid discovery issues
                    options.ProviderInformation = new ProviderInformation
                    {
                        IssuerName = config.Authority,
                        AuthorizeEndpoint = $"{config.Authority}/v1/authorize",
                        TokenEndpoint = $"{config.Authority}/v1/token",
                        EndSessionEndpoint = $"{config.Authority}/v1/logout",
                        UserInfoEndpoint = $"{config.Authority}/v1/userinfo",
                    };
                }
                else if (_currentProvider == OAuthProvider.EntraId)
                {
                    // For Entra ID, use standard v2.0 endpoints
                    var baseUrl = config.Authority.Replace("/v2.0", "");
                    options.ProviderInformation = new ProviderInformation
                    {
                        IssuerName = config.Authority,
                        AuthorizeEndpoint = $"{baseUrl}/oauth2/v2.0/authorize",
                        TokenEndpoint = $"{baseUrl}/oauth2/v2.0/token",
                        EndSessionEndpoint = $"{baseUrl}/oauth2/v2.0/logout",
                        UserInfoEndpoint = "https://graph.microsoft.com/oidc/userinfo",
                        TokenEndPointAuthenticationMethods = new[] { "client_secret_basic", "client_secret_post" }
                    };
                }

                _oidcClient = new OidcClient(options);

                var loginResult = await _oidcClient.LoginAsync();

                if (loginResult.IsError)
                {
                    throw new Exception($"Login failed: {loginResult.Error} - {loginResult.ErrorDescription}");
                }

                _currentLoginResult = loginResult;
                DisplayLoginResult(loginResult);

                StatusTextBlock.Text = $"Successfully authenticated with {_currentProvider} (Authorization Code)";
                LoginButton.IsEnabled = true;
                LogoutButton.IsEnabled = true;
                RefreshTokenButton.IsEnabled = !string.IsNullOrEmpty(loginResult.RefreshToken);
                WebView.Visibility = Visibility.Collapsed;
            }
            catch (Exception ex)
            {
                StatusTextBlock.Text = $"Interactive Login Error: {ex.Message}";
                TokenTextBox.Text = ex.ToString();
                LoginButton.IsEnabled = true;
                WebView.Visibility = Visibility.Collapsed;
            }
        }

        private async Task PerformClientCredentialsFlow()
        {
            try
            {
                StatusTextBlock.Text = $"Authenticating with {_currentProvider} using Client Credentials Flow...";

                var config = GetCurrentClientCredentialsConfig();

                var tokenRequest = new ClientCredentialsTokenRequest
                {
                    Address = config.TokenEndpoint,
                    ClientId = config.ClientId,
                    ClientSecret = config.ClientSecret,
                    Scope = string.Join(" ", config.Scopes)
                };

                // Add provider-specific parameters
                if (_currentProvider == OAuthProvider.Auth0)
                {
                    tokenRequest.Parameters.Add("audience", config.Audience);
                }
                else if (_currentProvider == OAuthProvider.Okta && !string.IsNullOrEmpty(config.Audience))
                {
                    tokenRequest.Parameters.Add("audience", config.Audience);
                }

                var tokenResponse = await _httpClient.RequestClientCredentialsTokenAsync(tokenRequest);

                if (tokenResponse.IsError)
                {
                    throw new Exception($"Token request failed: {tokenResponse.Error} - {tokenResponse.ErrorDescription}");
                }

                DisplayClientCredentialsResult(tokenResponse);
                StatusTextBlock.Text = $"Successfully authenticated with {_currentProvider} (Client Credentials)";
                LoginButton.IsEnabled = true;
                LogoutButton.IsEnabled = true;
                RefreshTokenButton.IsEnabled = false;
            }
            catch (Exception ex)
            {
                StatusTextBlock.Text = $"Client Credentials Error: {ex.Message}";
                TokenTextBox.Text = ex.ToString();
                LoginButton.IsEnabled = true;
            }
        }

        private OAuthConfig GetCurrentOAuthConfig()
        {
            switch (_currentProvider)
            {
                case OAuthProvider.Okta:
                    return _oktaConfig;
                case OAuthProvider.Auth0:
                    return _auth0Config;
                case OAuthProvider.EntraId:
                    return _entraIdConfig;
                default:
                    return _oktaConfig;
            }
        }

        private ClientCredentialsConfig GetCurrentClientCredentialsConfig()
        {
            switch (_currentProvider)
            {
                case OAuthProvider.Okta:
                    return _oktaClientCredentialsConfig;
                case OAuthProvider.Auth0:
                    return _auth0ClientCredentialsConfig;
                case OAuthProvider.EntraId:
                    return _entraIdClientCredentialsConfig;
                default:
                    return _oktaClientCredentialsConfig;
            }
        }

        private void DisplayLoginResult(LoginResult loginResult)
        {
            var tokenDisplay = new StringBuilder();
            tokenDisplay.AppendLine($"=== OIDC CLIENT AUTHENTICATION RESULT ===");
            tokenDisplay.AppendLine($"Provider: {_currentProvider}");
            tokenDisplay.AppendLine($"Flow: Authorization Code (OidcClient)");
            tokenDisplay.AppendLine($"Timestamp: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            tokenDisplay.AppendLine();

            tokenDisplay.AppendLine($"Access Token: {loginResult.AccessToken}");
            tokenDisplay.AppendLine($"Token Type: Bearer");
            tokenDisplay.AppendLine($"Expires At: {loginResult.AccessTokenExpiration:yyyy-MM-dd HH:mm:ss} UTC");

            if (!string.IsNullOrEmpty(loginResult.IdentityToken))
                tokenDisplay.AppendLine($"ID Token: {loginResult.IdentityToken}");

            if (!string.IsNullOrEmpty(loginResult.RefreshToken))
                tokenDisplay.AppendLine($"Refresh Token: {loginResult.RefreshToken}");

            //tokenDisplay.AppendLine($"Scope: {loginResult.Scope}");

            // Display user claims
            if (loginResult.User?.Identity?.IsAuthenticated == true)
            {
                tokenDisplay.AppendLine($"User Authenticated: {loginResult.User.Identity.IsAuthenticated}");
                tokenDisplay.AppendLine($"User Name: {loginResult.User.Identity.Name}");

                tokenDisplay.AppendLine();
                tokenDisplay.AppendLine("=== USER CLAIMS ===");

                foreach (var claim in loginResult.User.Claims.Take(15)) // Limit to first 15 claims
                {
                    tokenDisplay.AppendLine($"{claim.Type}: {claim.Value}");
                }
            }

            if (loginResult.TokenResponse?.Raw != null)
            {
                tokenDisplay.AppendLine();
                tokenDisplay.AppendLine("=== TOKEN RESPONSE (Raw) ===");
                try
                {
                    using (var doc = JsonDocument.Parse(loginResult.TokenResponse.Raw))
                    {
                        var formatted = JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true });
                        tokenDisplay.AppendLine(formatted);
                    }
                }
                catch
                {
                    tokenDisplay.AppendLine(loginResult.TokenResponse.Raw);
                }
            }

            TokenTextBox.Text = tokenDisplay.ToString();
        }

        private void DisplayClientCredentialsResult(TokenResponse tokenResponse)
        {
            var tokenDisplay = new StringBuilder();
            tokenDisplay.AppendLine($"=== CLIENT CREDENTIALS RESULT (OidcClient) ===");
            tokenDisplay.AppendLine($"Provider: {_currentProvider}");
            tokenDisplay.AppendLine($"Flow: Client Credentials");
            tokenDisplay.AppendLine($"Timestamp: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            tokenDisplay.AppendLine();

            tokenDisplay.AppendLine($"Access Token: {tokenResponse.AccessToken}");
            tokenDisplay.AppendLine($"Token Type: {tokenResponse.TokenType ?? "Bearer"}");
            tokenDisplay.AppendLine($"Expires In: {tokenResponse.ExpiresIn} seconds");
            tokenDisplay.AppendLine($"Expires At: {DateTime.UtcNow.AddSeconds(tokenResponse.ExpiresIn):yyyy-MM-dd HH:mm:ss} UTC");
            tokenDisplay.AppendLine($"Scope: {tokenResponse.Scope}");

            if (_currentProvider == OAuthProvider.Auth0)
            {
                tokenDisplay.AppendLine($"Audience: {_auth0ClientCredentialsConfig.Audience}");
            }

            tokenDisplay.AppendLine();
            tokenDisplay.AppendLine($"Note: Client Credentials flow is for service-to-service authentication");
            tokenDisplay.AppendLine($"No user context or ID token available");

            if (!string.IsNullOrEmpty(tokenResponse.Raw))
            {
                tokenDisplay.AppendLine();
                tokenDisplay.AppendLine("=== RAW TOKEN RESPONSE ===");
                try
                {
                    using (var doc = JsonDocument.Parse(tokenResponse.Raw))
                    {
                        var formatted = JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true });
                        tokenDisplay.AppendLine(formatted);
                    }
                }
                catch
                {
                    tokenDisplay.AppendLine(tokenResponse.Raw);
                }
            }

            TokenTextBox.Text = tokenDisplay.ToString();
        }

        private async void LogoutButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                LogoutButton.IsEnabled = false;

                if (_oidcClient != null && _currentLoginResult != null &&
                    (_currentFlow == AuthFlow.AuthorizationCode || _currentFlow == AuthFlow.OidcThenSaml))
                {
                    StatusTextBlock.Text = "Logging out...";

                    var logoutRequest = new LogoutRequest
                    {
                        IdTokenHint = _currentLoginResult.IdentityToken
                    };

                    var logoutResult = await _oidcClient.LogoutAsync(logoutRequest);

                    if (logoutResult.IsError)
                    {
                        StatusTextBlock.Text = $"Logout error: {logoutResult.Error}";
                    }
                    else
                    {
                        // Navigate to logout URL if provided
                        //if (!string.IsNullOrEmpty(logoutResult.FrontChannelLogoutUrl))
                        //{
                        //    WebView.Visibility = Visibility.Visible;
                        //    await WebView.Dispatcher.InvokeAsync(() =>
                        //    {
                        //        WebView.CoreWebView2.Navigate(logoutResult.FrontChannelLogoutUrl);
                        //    });

                        //    // Wait a moment for logout to process
                        //    await Task.Delay(2000);
                        //    WebView.Visibility = Visibility.Collapsed;
                        //}
                    }
                }

                // Clear local state
                TokenTextBox.Clear();
                _currentLoginResult = null;
                _currentSamlResult = null;
                _samlCompletionSource?.TrySetCanceled();
                _samlCompletionSource = null;

                // Navigate to blank page
                WebView.CoreWebView2.Navigate("about:blank");

                StatusTextBlock.Text = "Logged out successfully";
                LoginButton.IsEnabled = true;
                LogoutButton.IsEnabled = false;
                RefreshTokenButton.IsEnabled = false;
                WebView.Visibility = Visibility.Collapsed;
            }
            catch (Exception ex)
            {
                StatusTextBlock.Text = $"Logout Error: {ex.Message}";
                LogoutButton.IsEnabled = true;
            }
        }

        private async void RefreshTokenButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                RefreshTokenButton.IsEnabled = false;

                if (_oidcClient == null || _currentLoginResult == null || string.IsNullOrEmpty(_currentLoginResult.RefreshToken))
                {
                    StatusTextBlock.Text = "No refresh token available";
                    RefreshTokenButton.IsEnabled = true;
                    return;
                }

                StatusTextBlock.Text = "Refreshing token...";

                var refreshResult = await _oidcClient.RefreshTokenAsync(_currentLoginResult.RefreshToken);

                if (refreshResult.IsError)
                {
                    StatusTextBlock.Text = $"Token refresh failed: {refreshResult.Error} - {refreshResult.ErrorDescription}";
                    // If refresh fails, user needs to login again
                    LogoutButton.IsEnabled = false;
                    RefreshTokenButton.IsEnabled = false;
                }
                else
                {
                    //_currentLoginResult = refreshResult;
                        //DisplayLoginResult(refreshResult);
                    StatusTextBlock.Text = "Token refreshed successfully";
                    RefreshTokenButton.IsEnabled = !string.IsNullOrEmpty(refreshResult.RefreshToken);
                }

                RefreshTokenButton.IsEnabled = true;
            }
            catch (Exception ex)
            {
                StatusTextBlock.Text = $"Refresh Token Error: {ex.Message}";
                TokenTextBox.Text = ex.ToString();
                RefreshTokenButton.IsEnabled = true;
            }
        }

        protected override void OnClosed(EventArgs e)
        {
            _customBrowser?.Dispose();
            _httpClient?.Dispose();
            _samlCompletionSource?.TrySetCanceled();

            base.OnClosed(e);
        }
    }

    // Custom WebView Browser implementation for IdentityModel.OidcClient
    public class CustomWebViewBrowser : IBrowser, IDisposable
    {
        private readonly Microsoft.Web.WebView2.Wpf.WebView2 _webView;
        private TaskCompletionSource<BrowserResult> _tcs;

        public CustomWebViewBrowser(Microsoft.Web.WebView2.Wpf.WebView2 webView)
        {
            _webView = webView;
            _webView.NavigationCompleted += OnNavigationCompleted;
        }

        public async Task<BrowserResult> InvokeAsync(BrowserOptions options, CancellationToken cancellationToken = default)
        {
            _tcs = new TaskCompletionSource<BrowserResult>();

            // Navigate to the authorization URI
            await _webView.Dispatcher.InvokeAsync(() =>
            {
                _webView.CoreWebView2.Navigate(options.StartUrl);
            });

            // Register cancellation
            cancellationToken.Register(() => {
                _tcs?.TrySetResult(new BrowserResult
                {
                    ResultType = BrowserResultType.UserCancel
                });
            });

            // Wait for the navigation to complete and return the result
            return await _tcs.Task;
        }

        private void OnNavigationCompleted(object sender, CoreWebView2NavigationCompletedEventArgs e)
        {
            var currentUrl = _webView.CoreWebView2.Source;

            // Check if this is the redirect URI (localhost:5001)
            if (currentUrl.Contains("localhost:5001"))
            {
                _tcs?.TrySetResult(new BrowserResult
                {
                    ResultType = BrowserResultType.Success,
                    Response = currentUrl
                });
            }
        }

        public void Dispose()
        {
            if (_webView != null)
            {
                _webView.NavigationCompleted -= OnNavigationCompleted;
            }
            _tcs?.TrySetResult(new BrowserResult
            {
                ResultType = BrowserResultType.UserCancel
            });
        }
    }
}
