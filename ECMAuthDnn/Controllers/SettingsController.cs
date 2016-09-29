/*
' Copyright (c) 2016 Dnn Software
'  All rights reserved.
' 
' THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
' TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
' THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
' CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
' DEALINGS IN THE SOFTWARE.
' 
*/

using DotNetNuke.Collections;
using DotNetNuke.Common.Utilities;
using DotNetNuke.Security;
using DotNetNuke.Web.Mvc.Framework.ActionFilters;
using DotNetNuke.Web.Mvc.Framework.Controllers;
using System.Web.Mvc;
using System.Xml;

namespace Dnn.Modules.ECMAuthDnn.Controllers
{
    [DnnModuleAuthorize(AccessLevel = SecurityAccessLevel.Edit)]
    [DnnHandleError]
    public class SettingsController : DnnController
    {
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        public ActionResult Settings()
        {
            var settings = new Models.Settings();
            settings.AuthUrl = ModuleContext.Configuration.ModuleSettings.GetValueOrDefault("ECMAuthDnn_AuthUrl", string.Empty);
            settings.RedirectUrl = ModuleContext.Configuration.ModuleSettings.GetValueOrDefault("ECMAuthDnn_RedirectUrl", string.Empty);
            settings.DnnUser = ModuleContext.Configuration.ModuleSettings.GetValueOrDefault("ECMAuthDnn_DnnUser", string.Empty);

            string pass = ModuleContext.Configuration.ModuleSettings.GetValueOrDefault("ECMAuthDnn_DnnPass", string.Empty);
            if (!string.IsNullOrWhiteSpace(pass))
            {
                settings.DnnPass = new PortalSecurity().Decrypt(EncryptionKey, pass);
            }

            return View(settings);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="supportsTokens"></param>
        /// <returns></returns>
        [HttpPost]
        [ValidateInput(false)]
        [DotNetNuke.Web.Mvc.Framework.ActionFilters.ValidateAntiForgeryToken]
        public ActionResult Settings(Models.Settings settings)
        {
            ModuleContext.Configuration.ModuleSettings["ECMAuthDnn_AuthUrl"] = settings.AuthUrl;
            ModuleContext.Configuration.ModuleSettings["ECMAuthDnn_RedirectUrl"] = settings.RedirectUrl;
            ModuleContext.Configuration.ModuleSettings["ECMAuthDnn_DnnUser"] = settings.DnnUser;
            ModuleContext.Configuration.ModuleSettings["ECMAuthDnn_DnnPass"] = new PortalSecurity().Encrypt(EncryptionKey, settings.DnnPass);

            return RedirectToDefaultRoute();
        }

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