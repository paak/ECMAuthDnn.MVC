using DotNetNuke.Common.Utilities;
using DotNetNuke.Entities.Portals;
using DotNetNuke.Entities.Users;
using DotNetNuke.Security;
using DotNetNuke.Security.Membership;
using DotNetNuke.Services.Authentication;
using DotNetNuke.Web.Mvc.Framework.Controllers;

using System.Web.Mvc;
using System;
using Dnn.Modules.ECMAuthDnn.Models;
using DotNetNuke.Collections;

namespace Dnn.Modules.ECMAuthDnn.Controllers
{
    public class AccountController : DnnController
    {
        // GET: Account
        [HttpGet]
        public ActionResult Login()
        {
            return View();
        }

        // POST: Account/Create
        [HttpPost]
        public ActionResult Login(LogOn logonModel)
        {
            if (logonModel == null)
            {
                return View();
            }
            // Get Module Settings
            Settings settings = new Settings();
            settings.AuthUrl = ModuleContext.Configuration.ModuleSettings.GetValueOrDefault("ECMAuthDnn_AuthUrl", string.Empty);
            settings.RedirectUrl = ModuleContext.Configuration.ModuleSettings.GetValueOrDefault("ECMAuthDnn_RedirectUrl", string.Empty);
            settings.DnnUser = ModuleContext.Configuration.ModuleSettings.GetValueOrDefault("ECMAuthDnn_DnnUser", string.Empty);
            settings.DnnPass = ModuleContext.Configuration.ModuleSettings.GetValueOrDefault("ECMAuthDnn_DnnPass", string.Empty);

            string userName = new PortalSecurity().InputFilter(logonModel.UserName,
                                    PortalSecurity.FilterFlag.NoScripting |
                                    PortalSecurity.FilterFlag.NoAngleBrackets |
                                    PortalSecurity.FilterFlag.NoMarkup);

            string passWord = new PortalSecurity().InputFilter(logonModel.PassWord,
                                    PortalSecurity.FilterFlag.NoScripting |
                                    PortalSecurity.FilterFlag.NoAngleBrackets |
                                    PortalSecurity.FilterFlag.NoMarkup);

            string AuthType = "DNN";

            UserLoginStatus status = new UserLoginStatus();
            //UserInfo userInfo = UserController.ValidateUser(this.PortalSettings.PortalId, userName, passWord, AuthType, "", PortalSettings.PortalName, AuthenticationLoginBase.GetIPAddress(), ref status);

            UserInfo userInfo = UserController.ValidateUser(this.PortalSettings.PortalId,
                settings.DnnUser,
                settings.DnnPass,
                AuthType,
                "", PortalSettings.PortalName,
                AuthenticationLoginBase.GetIPAddress(),
                ref status);

            switch (status)
            {
                case UserLoginStatus.LOGIN_SUCCESS:
                    userInfo.Membership.Password = passWord;
                    userInfo.Username = userName;

                    UserController.UserLogin(this.PortalSettings.PortalId, userInfo, PortalSettings.PortalName, AuthenticationLoginBase.GetIPAddress(), true);

                    Response.Redirect(DotNetNuke.Common.Globals.NavigateURL(), true);
                    break;
                case UserLoginStatus.LOGIN_SUPERUSER:
                    userInfo.Membership.Password = passWord;
                    userInfo.Username = userName;

                    UserController.UserLogin(this.PortalSettings.PortalId, userInfo, PortalSettings.PortalName, AuthenticationLoginBase.GetIPAddress(), true);

                    Response.Redirect(DotNetNuke.Common.Globals.NavigateURL(), true);
                    break;
                default:
                    break;
            }

            return View();

        }
    }
}
