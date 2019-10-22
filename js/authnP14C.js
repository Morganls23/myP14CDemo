// variable definitions and building authorization url
type="text/javascript";
const environmentId = 'e2431bcc-0d0b-4574-9dbc-ff8c91bb799e'; // available on settings page of p14c admin console
const baseUrl = 'https://morganapps.ping-eng.com/'; // URL of where you will host this application
const scopes = 'openid profile email address phone'; // default scopes to request
const responseType = 'token id_token'; //tokens to recieve

const clientId = '77838143-24eb-4223-9eeb-8559baa52c5a';
const clientSecret = 'w7TxHDpxX2hECtHc4g9bh~M_GwcNMMLF4VmQOUFc0LAS1JQ.PN86mUdmzjpk2KCY';
const adminRedirectUri =baseUrl + 'myP14CDemo/content/finance/admin-login.html'

const cookieDomain = ''; // unnecessary unless using subdomains (e.g., login.example.com, help.example.com, docs.example.com).  Then use a common root (e.g., .example.com)
const landingUrl = baseUrl + 'myP14CDemo/index-finance.html'; // url to send the person once authentication is complete
const logoutUrl = baseUrl + 'logout/'; // whitelisted url to send a person who wants to logout
const redirectUri = baseUrl + 'myP14CDemo/index-finance.html'; // whitelisted url P14C sends the token or code to

const authUrl = 'https://auth.pingone.com';
const apiUrl = 'https://api.pingone.com/v1';

const userAuthScopes = 'p1:read:self:user';

const flowId = getUrlParameter('flowId');

const regexLower = new RegExp('(?=.*[a-z])');
const regexUpper = new RegExp('(?=.*[A-Z])');
const regexNumeric = new RegExp('(?=.*[0-9])');
const regexSpecial = new RegExp('(?=.*[~!@#\$%\^&\*\)\(\|\;\:\,\.\?\_\-])');
const regexLength = new RegExp('(?=.{8,})');


// function to generate random nonce

function generateNonce(length) {
  var result = '';
  var characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789:;_-.()!';
  var charactersLength = characters.length;
  for (var i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
}



if (!clientId || !environmentId) {

  alert('Be sure to edit js/auth.js with your environmentId and clientId');

}


// exJax function makes an AJAX call
function exJax(method, url, callback, contenttype, payload) {
  console.log('ajax (' + url + ')');
  console.log("content type: "+contenttype);
  $.ajax({
      url: url,
      method: method,
      dataType: 'json',
      contentType: contenttype,
      data: payload,
      xhrFields: {
        withCredentials: true
      }
    })
    .done(function(data) {
      callback(data);
    })
    .fail(function(data) {
      console.log('ajax call failed');
      console.log(data);
      $('#warningMessage').text(data.responseJSON.details[0].message);
      $('#warningDiv').show();
    });
}




// change password function
function changePassword() {
  console.log('changePassword called');
  let payload = JSON.stringify({
    currentPassword: $('#password').val(),
    newPassword: $('#changePassword').val()
  });
  let url = $('#changePasswordUrl').val();
  let contenttype = $('#changePasswordContentType').val();
  exJax('POST', url, nextStep, contenttype, payload);
}

// validate password function
function validatePassword() {
  console.log('validatePassword called');
  let payload = JSON.stringify({
    username: $('#user_login').val(),
    password: $('#user_pass').val()
  });
  console.log('payload is ' + payload)
  let url = $('#validatePasswordUrl').val();
  //let url = (authUrl + environmentId + '/flows/' + flowId);
  console.log('url is: ' + url);
  let contenttype = 'application/vnd.pingidentity.usernamePassword.check+json';
  console.log('contenttype is ' + contenttype);
  exJax('POST', url, nextStep, contenttype, payload);
}

// validate one time passcode function
function validateOtp() {
  console.log('validateOtp called');
  let payload = JSON.stringify({
    otp: $('#otp').val()
  });
  let url = $('#validateOtpUrl').val();
  let contenttype = $('#validateOtpContentType').val();
  exJax('POST', url, nextStep, contenttype, payload);
}

function nextStep(data) {
  status = data.status;
  console.log('Parsing json to determine next step: ' + status);

  switch (status) {
    case 'USERNAME_PASSWORD_REQUIRED':
      console.log('Rendering login form');
      $('#loginDiv').show();
      $('#otpDiv').hide();
      $('#validatePasswordUrl').val(data._links['usernamePassword.check'].href);
      $('#validatePasswordContentType').val('application/vnd.pingidentity.usernamePassword.check+json');
      break;
    case 'PASSWORD_REQUIRED':
      console.log('Rendering login form');
      $('#loginDiv').show();
      $('#otpDiv').hide();
      $('#validatePasswordUrl').val(data._embedded.requiredStep._links['usernamePassword.check'].href);
      $('#validatePasswordContentType').val('application/vnd.pingidentity.usernamePassword.check+json');
      break;
    case 'OTP_REQUIRED':
      console.log('Rendering otp form');
      $('#loginDiv').hide();
      $('#otpDiv').show();
      $('#validateOtpUrl').val(data._links['otp.check'].href);
      $('#validateOtpContentType').val('application/vnd.pingidentity.otp.check+json')
      break;
    case 'MUST_CHANGE_PASSWORD':
      console.log('Rendering password form');
      $('#loginDiv').hide();
      $('#passwordDiv').show();
      $('#changePasswordUrl').val(data._links['password.reset'].href);
      $('#changePasswordContentType').val('application/vnd.pingidentity.password.reset+json')
      break;
    case 'COMPLETED':
      console.log('completed authentication successfully');
      $('#warningMessage').text('');
      $('#warningDiv').hide();
      console.log('Redirecting user');
      console.log(data);
      window.location.replace(data.resumeUrl);
      break;
    default:
      console.log('Unexpected outcome');
      break;
  }
}
