using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;

namespace OidcClientSample
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // Initialize any application-wide settings here
            // For example, logging, dependency injection, etc.
        }

        protected override void OnExit(ExitEventArgs e)
        {
            // Cleanup resources
            base.OnExit(e);
        }
    }
}