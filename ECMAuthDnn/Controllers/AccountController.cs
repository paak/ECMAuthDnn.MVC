using Dnn.Modules.ECMAuthDnn.Models;
using DotNetNuke.Collections;
using DotNetNuke.Common.Utilities;
using DotNetNuke.Entities.Portals;
using DotNetNuke.Entities.Users;
using DotNetNuke.Security;
using DotNetNuke.Security.Membership;
using DotNetNuke.Services.Authentication;
using DotNetNuke.Services.Localization;
using DotNetNuke.Web.Mvc.Framework.Controllers;
using System;
using System.IO;
using System.Net;
using System.Text;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using System.Xml;
using System.Xml.Serialization;

namespace Dnn.Modules.ECMAuthDnn.Controllers
{
    public class AccountController : DnnController
    {
        // GET: Account
        [HttpGet]
        public ActionResult Logout()
        {
            FormsAuthentication.SignOut();
            Response.Redirect(DotNetNuke.Common.Globals.NavigateURL(), true);

            return View();
        }

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
            Settings settings = GetModuleSettings();

            // Filtering input string
            string userName = FilterInput(logonModel.UserName);
            string passWord = FilterInput(logonModel.PassWord);

            // Preparing post data
            byte[] byteData = PreparePostData(userName, passWord);

            // Initiate Http request
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(settings.AuthUrl);

            // Set HTTP request method
            request.Method = "POST";
            request.KeepAlive = true;

            //  Set preferred data format in response
            request.Accept = "application/xml";

            // Set request content type as xml
            request.ContentType = "application/xml";
            request.ContentLength = byteData.Length;

            // Attach data to request body
            Stream requestStream = request.GetRequestStream();
            requestStream.Write(byteData, 0, byteData.Length);
            requestStream.Close();

            try
            {
                // Response object
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();

                if (response.StatusCode == HttpStatusCode.OK)
                {
                    // Get response object
                    Stream responseStream = response.GetResponseStream();

                    XmlSerializer serializer = new XmlSerializer(typeof(AuthResponseDTO));
                    AuthResponseDTO authResponse = (AuthResponseDTO)serializer.Deserialize(responseStream);

                    bool isEcom = false;
                    bool isWca = false;
                    if (authResponse != null && authResponse.AgentDetails != null && authResponse.AgentDetails.Networks != null)
                    {
                        isEcom = authResponse.AgentDetails
                            .Networks
                            .Exists(x => x.Code == "WCAeC");
                        isWca = settings.AllowWCA && authResponse.AgentDetails
                            .Networks
                            .Exists(x => x.Name.ToLower().Contains("wca"));
                    }

                    responseStream.Close();

                    // If allows wca members
                    logonModel.IsAuthenthicated = (!isWca && !isEcom) ? false : true;

                    // if not authorize no need to set cookie
                    if (logonModel.IsAuthenthicated)
                    {
                        // Set cookie for browser
                        string setCookie = response.Headers[HttpResponseHeader.SetCookie];

                        HttpCookie httpCookie = new HttpCookie("authToken");
                        httpCookie.Value = setCookie;
                        Response.SetCookie(httpCookie);

                        HttpCookie ecomState = new HttpCookie("ecomState");
                        ecomState["FirstName"] = Base64Encode(authResponse.UserDetails.FirstName);
                        ecomState["LastName"] = Base64Encode(authResponse.UserDetails.LastName);
                        ecomState["Email"] = Base64Encode(authResponse.UserDetails.Email);

                        Response.SetCookie(ecomState);
                    }
                    else
                    {
                        ViewBag.Message = Localization.GetString("LoginEcom", LocalResourceFile);
                    }
                }
                else
                {
                    logonModel.IsAuthenthicated = false;
                    ViewBag.Message = Localization.GetString("LoginFailed", LocalResourceFile);
                }
                response.Close();
            }

            catch (WebException webEx)
            {
                HttpWebResponse response = (HttpWebResponse)webEx.Response;

                // Or if you want to return an HTTP 404 instead:
                logonModel.IsAuthenthicated = false;
                ViewBag.Message = Localization.GetString("LoginFailed", LocalResourceFile);
                response.Close();
            }

            catch
            {
                logonModel.IsAuthenthicated = false;
                ViewBag.Message = Localization.GetString("LoginFailed", LocalResourceFile);
            }

            // Authenthicate failed
            if (!logonModel.IsAuthenthicated)
            {
                return View();
            }

            string AuthType = "DNN";

            UserLoginStatus status = new UserLoginStatus();

            UserInfo userInfo = UserController.ValidateUser(this.PortalSettings.PortalId,
                settings.DnnUser,
                settings.DnnPass,
                AuthType,
                "",
                PortalSettings.PortalName,
                AuthenticationLoginBase.GetIPAddress(),
                ref status);

            switch (status)
            {
                case UserLoginStatus.LOGIN_SUCCESS:
                case UserLoginStatus.LOGIN_SUPERUSER:
                    userInfo.Membership.Password = settings.DnnPass;
                    userInfo.Username = settings.DnnUser;

                    UserController.UserLogin(this.PortalSettings.PortalId, userInfo, PortalSettings.PortalName, AuthenticationLoginBase.GetIPAddress(), true);

                    //Response.Redirect(DotNetNuke.Common.Globals.NavigateURL(), true);
                    Response.Redirect(settings.RedirectUrl, true);
                    break;
                case UserLoginStatus.LOGIN_FAILURE:
                    ViewBag.Message = Localization.GetString("LoginDnnFailed", LocalResourceFile);
                    break;
                default:
                    ViewBag.Message = Localization.GetString("LoginDnnError", LocalResourceFile);
                    break;
            }

            return View();
        }

        #region Private Functions
        private string FilterInput(string input)
        {
            return new PortalSecurity().InputFilter(input,
                           PortalSecurity.FilterFlag.NoScripting |
                           PortalSecurity.FilterFlag.NoAngleBrackets |
                           PortalSecurity.FilterFlag.NoMarkup);
        }

        private Settings GetModuleSettings()
        {
            // Get Module Settings
            Settings settings = new Settings();

            settings.AllowWCA = ModuleContext.Configuration.ModuleSettings.GetValueOrDefault("ECMAuthDnn_AllowWCA", false);
            settings.AuthUrl = ModuleContext.Configuration.ModuleSettings.GetValueOrDefault("ECMAuthDnn_AuthUrl", string.Empty);
            settings.RedirectUrl = ModuleContext.Configuration.ModuleSettings.GetValueOrDefault("ECMAuthDnn_RedirectUrl", "~/");
            settings.DnnUser = ModuleContext.Configuration.ModuleSettings.GetValueOrDefault("ECMAuthDnn_DnnUser", string.Empty);

            string pass = ModuleContext.Configuration.ModuleSettings.GetValueOrDefault("ECMAuthDnn_DnnPass", string.Empty);
            if (!string.IsNullOrWhiteSpace(pass))
            {
                settings.DnnPass = new PortalSecurity().Decrypt(EncryptionKey, pass);
            }

            return settings;
        }

        private byte[] PreparePostData(string userName, string passWord)
        {
            // Create root XML element: LogOnModel
            XmlDocument xml = new XmlDocument();

            XmlElement root;
            root = xml.CreateElement("LogOnModel");
            xml.AppendChild(root);

            // Create UserName element
            XmlElement username;
            username = xml.CreateElement("UserName");
            username.InnerText = userName.Trim();
            root.AppendChild(username);

            // Create Password element
            XmlElement password;
            password = xml.CreateElement("Password");
            password.InnerText = passWord.Trim();
            root.AppendChild(password);

            // Preparing post data
            UTF8Encoding encoding = new UTF8Encoding();
            return encoding.GetBytes(xml.OuterXml);
        }

        private string Base64Encode(string plainText)
        {
            if (string.IsNullOrWhiteSpace(plainText))
            {
                return string.Empty;
            }

            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            return Convert.ToBase64String(plainTextBytes);
        }
        #endregion

        #region Private Members
        private string EncryptionKey
        {
            get
            {
                try
                {
                    XmlDocument xmlConfig = Config.Load();
                    XmlNode xmlMachineKey = xmlConfig.SelectSingleNode("configuration/system.web/machineKey");

                    return xmlMachineKey.Attributes["decryptionKey"].InnerText;
                }
                catch
                {
                    return string.Empty;
                }
            }
        }

        #endregion

    }
}
