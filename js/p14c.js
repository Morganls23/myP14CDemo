// variable definitions and building authorization url
type = 'text/javascript';
const environmentId = '7334523a-4a2d-4dd6-9f37-93c60114e938'; // available on settings page of p14c admin console
const baseUrl = 'https://morganapps.ping-eng.com/'; // URL of where you will host this application

const scopes = 'openid profile email address phone p1:update:user p1:read:user'; // default scopes to request
const responseType = 'token id_token'; // tokens to recieve

const landingUrl = baseUrl + 'myP14CDemo/index-finance.html'; // url to send the person once authentication is complete
const logoutUrl = baseUrl + 'logout/'; // whitelisted url to send a person who wants to logout
const redirectUri = baseUrl + 'myP14CDemo/index-finance.html'; // whitelisted url P14C sends the token or code to

const clientId = '7606b740-bb4b-4253-b449-aabf5b66e7eb';
const authUrl = 'https://auth.pingone.com';
const apiUrl = 'https://api.pingone.com/v1';

const userAuthScopes = 'p1:read:self:user';

const flowId = getUrlParameter('flowId');

const regexLower = new RegExp('(?=.*[a-z])');
const regexUpper = new RegExp('(?=.*[A-Z])');
const regexNumeric = new RegExp('(?=.*[0-9])');
const regexSpecial = new RegExp('(?=.*[~!@#\$%\^&\*\)\(\|\;\:\,\.\?\_\-])');
const regexLength = new RegExp('(?=.{8,})');


const workerClientId='bfd2c852-a478-47ee-9625-7c9bb917deaf';
const workerClientSecret='W5PdV0UP_p-a0FfHOvrgUfs88VzERThYPZs1-.6HC0_VQ4IWS4UX1XY9dk9xi6k2';



// Authentitcaiton
const adminClientId = 'd915beea-7682-4441-b7ed-92fef5b3b9bb';
const adminClientSecret = 'DdkqZjXBqnpQ_0hy19cX8bKRvv_ZSOxIKk.byHqEAf2cSlOE7XoOLEU63euEjnx.';
const adminRedirectUri =baseUrl + 'myP14CDemo/content/finance/admin-login.html';
const adminScopes = 'profile address phone email openid';


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
    currentPassword: $('#current_password').val(),
    newPassword: $('#change_new_password').val()
  });
  let url = $('#changePasswordUrl').val();
  let contenttype = 'application/vnd.pingidentity.password.reset+json';
  console.log('payload '+ payload);
  exJax('POST', url, nextStep, contenttype, payload);
}

// validate password function
function validatePassword() {
  console.log('validatePassword called');
  let payload = JSON.stringify({
    username: $('#user_login').val(),
    password: $('#user_pass').val()
  });
  console.log('payload is ' + payload);
  let url = $('#validatePasswordUrl').val();
  //let url = (authUrl + environmentId + '/flows/' + flowId);
  console.log('url is: ' + url);
  let contenttype = 'application/vnd.pingidentity.usernamePassword.check+json';
  console.log('contenttype is ' + contenttype);
  exJax('POST', url, nextStep, contenttype, payload);
}

//seturl for social
function redirect_toSocial(){
  location.href = $('#socialLoginUrl').val();
}

//seturl for partner
function redirect_toPartner(){
  console.log('redirect to partner was called');
  console.log('usr is ' +$('#partnerLoginUrl').val());

  location.href = $('#partnerLoginUrl').val();
}

// validate one time passcode function
function validateOtp() {
  console.log('validateOtp called');
  let otp = $('#otp_login').val();
  let payload = JSON.stringify({
    otp: otp
  });
  //let url = $('#validateOtpUrl').val();
  let url = (authUrl + '/' + environmentId + '/flows/' + flowId);
  let contenttype ='application/vnd.pingidentity.otp.check+json';
  //$('#validateOtpContentType').val();
  console.log('url :' + url);
  console.log('otp: ' + otp);
  console.log('content' + contenttype);

  exJax('POST', url, nextStep, contenttype, payload);
}

function continue_push() {
  //location.href=authUrl + '/' + environmentId + '/flows/' + flowId;
  console.log('continue push called');
  //let url = $('#pushResumeUrl');
  let url = authUrl + '/' + environmentId + '/flows/' + flowId;
  let contenttype ='application/json';
  //location.href = $('#pushResumeUrl').val();
  console.log('url ' + url);
  exJax('GET', url, nextStep, contenttype);
}

function nextStep(data) {
  status = data.status;
  console.log('Parsing json to determine next step: ' + status);

  switch (status) {
    case 'USERNAME_PASSWORD_REQUIRED':
      console.log('Rendering login form');
      $('#loginDiv').show();
      $('#otpDiv').hide();
      $('#pushDiv').hide();
      $('#changePasswordDiv').hide();
      $('#pwResetCodeDiv').hide();
      $('#validatePasswordUrl').val(data._links['usernamePassword.check'].href);
      $('#validatePasswordContentType').val('application/vnd.pingidentity.usernamePassword.check+json');
      $('#registerUserUrl').val(data._links['user.register'].href);
      $('#forgotPasswordURL').val(data._links["password.forgot"].href);
      $('#socialLoginUrl').val(data._embedded.socialProviders[0]._links.authenticate.href);
      $('#partnerLoginUrl').val(data._embedded.socialProviders[1]._links.authenticate.href);
      $('#ppDiv').hide('');
      break;
    case 'VERIFICATION_CODE_REQUIRED':
      console.log('Rendering Verification code form');
      $('#loginDiv').hide();
      $('#otpDiv').show();
      $('#pushDiv').hide();
      $('#pwResetCodeDiv').hide();
      $('#changePasswordDiv').hide();
      $('#verifyUserUrl').val(data._links['user.verify'].href);
      $('#ppDiv').hide('');
      break;
    case 'PASSWORD_REQUIRED':
      console.log('Rendering login form');
      $('#loginDiv').show();
      $('#otpDiv').hide();
      $('#pushDiv').hide();
      $('#pwResetCodeDiv').hide();
      $('#changePasswordDiv').hide();
      $('#validatePasswordUrl').val(data._embedded.requiredStep._links['usernamePassword.check'].href);
      $('#validatePasswordContentType').val('application/vnd.pingidentity.usernamePassword.check+json');
      $('#ppDiv').hide('');
      break;
    case 'OTP_REQUIRED':
      console.log('Rendering otp form');
      $('#loginDiv').hide();
      $('#otpDiv').show();
      $('#pushDiv').hide();
      $('#pwResetCodeDiv').hide();
      $('#changePasswordDiv').hide();
      $('#validateOtpUrl').val(data._links['otp.check'].href);
      $('#validateOtpContentType').val('application/vnd.pingidentity.otp.check+json')
      $('#ppDiv').hide('');
      break;
    case 'PUSH_CONFIRMATION_REQUIRED':
      console.log('Rendering wait for push form');
      $('#loginDiv').hide();
      $('#otpDiv').hide();
      $('#pushDiv').show();
      $('#pwResetCodeDiv').hide();
      $('#changePasswordDiv').hide();
      $('#pushResumeUrl').val(data._links["device.select"].href);
      $('#ppDiv').hide('');
      break;
    case 'MUST_CHANGE_PASSWORD':
      console.log('Rendering password form');
      $('#loginDiv').hide();
      $('#otpDiv').hide();
      $('#pushDiv').hide();
      $('#pwResetCodeDiv').hide();
      $('#changePasswordDiv').show();
      $('#changePasswordUrl').val(data._links['password.reset'].href);
      $('#changePasswordContentType').val('application/vnd.pingidentity.password.reset+json')
      $('#ppDiv').hide('');
      break;
    case 'RECOVERY_CODE_REQUIRED':
    console.log('Rendering password form');
      $('#loginDiv').hide();
      $('#otpDiv').hide();
      $('#pushDiv').hide();
      $('#changePasswordDiv').hide();
      $('#pwResetCodeDiv').show();
      $('#changePasswordUrl').val(data._links['password.reset'].href);
      $('#pwcodeUrl').val(data._links['password.recover'].href);
      $('#changePasswordContentType').val('application/vnd.pingidentity.password.reset+json')
      $('#ppDiv').hide('');
      break;
    case 'COMPLETED':
      console.log('completed authentication successfully');
      $('#loginDiv').hide();
      $('#otpDiv').hide();
      $('#pushDiv').hide();
      $('#changePasswordDiv').hide();
      $('#pwResetCodeDiv').hide();
      $('#warningMessage').text('');
      $('#warningDiv').hide();
      $('#ppDiv').hide('');
      console.log('Redirecting user');
      console.log(data);
      window.location.replace(data.resumeUrl);
      break;
    case 'PROFILE_DATA_REQUIRED':
    console.log('rendering PP form');
      $('#loginDiv').hide();
      $('#otpDiv').hide();
      $('#pushDiv').hide();
      $('#changePasswordDiv').hide();
      $('#pwResetCodeDiv').hide();
      $('#warningMessage').hide('');
      $('#warningDiv').hide();
      $('#ppDiv').text('');
    break;
    default:
      console.log('Unexpected outcome');
      break;
  }
}






// Other Stuff


// build the authorization url in case we need it

const authorizationUrl =
  authUrl +
  '/' +
  environmentId +
  '/as/authorize?client_id=' +
  clientId +
  '&response_type=' +
  responseType +
  '&redirect_uri=' +
  redirectUri +
  '&scope=' +
  scopes;


  //build the admin auth url
  const adminAuthorizationUrl =
    authUrl +
    '/' +
    environmentId +
    '/as/authorize?client_id=' +
    adminClientId +
    '&response_type=' +
    responseType +
    '&redirect_uri=' +
    adminRedirectUri +
    '&scope=' +
    adminScopes;

    const registerAuthorizationURL =
    authUrl +
    '/' +
    environmentId +
    '/as/authorize?client_id=' +
    clientId +
    '&response_type=' +
    responseType +
    '&redirect_uri=' +
    "https://morganapps.ping-eng.com/myP14CDemo/content/finance/register.html" +
    '&scope=' +
    scopes;


// simple function to parse json web token
function parseJwt(token) {
  console.log("parseJWT was called");
  var base64Url = token.split('.')[1];
  var base64 = base64Url.replace('-', '+').replace('_', '/');
  return JSON.parse(window.atob(base64));
}

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


function renderDivState() {
  console.log("renderDiv called");
  console.log(Cookies.get('accessToken'));

  if (Cookies.get('accessToken')) {
    let login = document.getElementById("loginDiv");
    login.style.display = "none";

    let otp = document.getElementById("otpDiv");
    otp.style.display = "none";

    let push = document.getElementById("pushDiv");
    push.style.display = "none";

    let resetpass = document.getElementById("pwResetCodeDiv");
    resetpass.style.display = "none";

    let changePassword = document.getElementById("changePasswordDiv");
    changePassword.style.display = "none";

    let account = document.getElementById("myAccount");
    account.style.display = "block";


  } else {
    let login = document.getElementById("loginDiv");
    login.style.display = "block";

    let otp = document.getElementById("otpDiv");
    otp.style.display = "none";

    let push = document.getElementById("pushDiv");
    login.style.display = "none";

    let changePassword = document.getElementById("changePasswordDiv");
    login.style.display = "none";

    let account = document.getElementById("myAccount");
    account.style.display = "none";
  }


}



// populate any login buttons with the authorization URL

$('#signOnButton').attr('href', authorizationUrl);

// if environmentId or clientId are null warn the user

if (!clientId || !environmentId) {

  alert('Be sure to edit js/auth.js with your environmentId and clientId');

}

$('#changePassword').on('input', function(e) {
  let thisPassword = $('#changePassword').val();

  if (regexLower.test(thisPassword)) {
    $('#lowercase').removeClass('text-primary');
  } else {
    $('#lowercase').addClass('text-primary');
  }

  if (regexUpper.test(thisPassword)) {
    $('#uppercase').removeClass('text-primary');
  } else {
    $('#uppercase').addClass('text-primary');
  }

  if (regexNumeric.test(thisPassword)) {
    $('#numeric').removeClass('text-primary');
  } else {
    $('#numeric').addClass('text-primary');
  }

  if (regexSpecial.test(thisPassword)) {
    $('#special').removeClass('text-primary');
  } else {
    $('#special').addClass('text-primary');
  }

  if (regexLength.test(thisPassword)) {
    $('#length').removeClass('text-primary');
  } else {
    $('#length').addClass('text-primary');
  }
});

// getUrlParameter function parses out the querystring to fetch specific value (e.g., flowId)
function getUrlParameter (parameterName) {
  console.log('getUrlParameter was called');
  let pageUrl = window.location.href;
  const pound = '#';
  const q = '?';
  const simpleUrl = pageUrl.substring(0, pageUrl.indexOf(pound));
  console.log('simple url: ' + simpleUrl);
  console.log('pageUrl: ' + pageUrl);
  if (pageUrl.includes(pound)) {
    console.log('pageUrl is not null and has #');
    pageUrl = pageUrl.substring(pageUrl.indexOf(pound) + 1);
    console.log('removed base at #:' + pageUrl);
    const urlVariables = pageUrl.split('&');

    console.log('urlVariables: ' + urlVariables);
    for (let i = 0; i < urlVariables.length; i++) {
      const thisParameterName = urlVariables[i].split('=');
      if (thisParameterName[0] === parameterName) {
        console.log('parameterName:' + thisParameterName[1]);
        return thisParameterName[1];
      }
      if (thisParameterName[0].includes('access_token')) {
        console.log('setting at cookie : ' + thisParameterName[1]);
        Cookies.set('accessToken', thisParameterName[1]);
      }
      if (thisParameterName[0].includes('id_token')) {
        console.log('setting id cookie : ' + thisParameterName[1]);
        const idToken = thisParameterName[1];
        Cookies.set('idToken', idToken);
        setUserinfoCookie();
      }

      console.log(thisParameterName);
      console.log('remove AT and IDT from URL');
      window.location.replace(simpleUrl);
    }
  } else if (pageUrl.includes(q)) {
    console.log("pageUrl is not null");
    pageUrl = pageUrl.substring(pageUrl.indexOf(q));
    console.log("removed base at ?:" + pageUrl);
    let urlVariables = pageUrl.split('&');

    console.log("urlVariables: " + urlVariables);
    for (let i = 0; i < urlVariables.length; i++) {
      let thisParameterName = urlVariables[i].split('=');
      if (thisParameterName[0] == parameterName) return thisParameterName[1];
    }
  } else {
    console.log("URLparams are not present");
    return "";
  }
  console.log("getURLParms done");
}


function setUserinfoCookie() {
  let idToken = Cookies.get('idToken');
  let idPayload = parseJwt(idToken);
  Cookies.set('uuid', idPayload.sub);
  //Cookies.set('name', idPayload.given_name);
}

function setUserValues(userJson) {
  console.log("setuserValues was called");
  console.log(userJson);
  let uuid = Cookies.get('uuid');
  //let streetAddress = userJson.address.streetAddress + " " + userJson.address.locality + ", " + userJson.address.region + " " + userJson.address.postalCode;
  if (Cookies.get("accessToken")) {
    if(userJson.name){
      if(userJson.name.given){
        console.log("givenname if was passes")
        document.getElementById("user").value = 'Hello ' + userJson.name.given + "!";
        document.getElementById("fname").value = userJson.name.given;
      }
      if(userJson.name.family){
      document.getElementById("lname").value = userJson.name.family;
      }
    }
    document.getElementById("email").value = userJson.email;
    document.getElementById("username").value = userJson.username;
    //document.getElementById("address").innerHTML=streetAddress;
  } else {
    document.getElementById("username").innerHTML = 'Welcome Guest';
  }

  //let idPayload = parseJwt(idToken);
}



function resetPassword(){

  //https://api.pingone.com/v1/environments/7334523a-4a2d-4dd6-9f37-93c60114e938/users/bfd0e265-abe6-41c9-aca6-2352478b30da/password
  console.log("resetPassword was called");
  let method = "POST";
  let user = $('#user_login').val();
  let url = $('#forgotPasswordURL').val();
  let contentType='application/vnd.pingidentity.password.forgot+json';
  console.log('url (' + url + ')');
  console.log('user =' + user);
  console.log("make exJax call");
  let payload = JSON.stringify({
    username: user
  });
  exJax(method, url, nextStep, contentType, payload);
  console.log("resetPassword finished");
}


function validatePWResetCode(){
  console.log("validate password code called ")
  let method = "POST";
  let url = $('#forgotPasswordURL').val();
  let contentType='application/vnd.pingidentity.password.recover+json';
  console.log('url (' + url + ')');
  console.log("make exJax call");
  let payload = JSON.stringify({
    recoveryCode: $('#pwReset_Code').val(),
    newPassword: $('#new_password').val()
  });
    console.log('payload =' + payload);
  exJax(method, url, nextStep, contentType, payload);
  console.log("validate Password code finished");

}


function adminChangePassword(){
  console.log("adminChangePassword was called");
  let method = "PUT";
  let user = Cookies.get("currentUser");
  let at = "Bearer " + Cookies.get("accessToken");
  let url = apiUrl + "/environments/" + environmentId + "/users/" + user + '/password';
  let pass = document.getElementById('password').value;
  let payload = JSON.stringify({
    newPassword: pass
  });
  console.log(payload);
  console.log('ajax (' + url + ')');
  console.log('at =' + at);
  console.log("make ajax call");
  $.ajax({
      async: "true",
      url: url,
      method: method,
      data:payload,
      contentType: 'application/vnd.pingidentity.password.reset+json',
      beforeSend: function(xhr) {
        xhr.setRequestHeader('Authorization', at);
      }
    }).done(function(data) {
      console.log(data);
    })
    .fail(function(data) {
      console.log('ajax call failed');
      console.log(data);
      $('#warningMessage').text(data.responseJSON.details[0].message);
      $('#warningDiv').show();
    });
    console.log("AdminchangePassword finished");

}

function adminGetUser(){
  //{{apiPath}}/environments/{{envID}}/users/?filter=username%20eq%20%22lsmith%22
  console.log('adminGetUser called');
  let method = "GET";
  let user = document.getElementById('username').value;
  console.log(user);
  let at = "Bearer " + Cookies.get("accessToken");
  let url = apiUrl + "/environments/" + environmentId + "/users/?filter=username%20eq%20%22" + user + "%22";
  console.log('ajax (' + url + ')');
  console.log('at =' + at);
  console.log("make ajax call");
  $.ajax({
    async: "true",
    url: url,
    method: method,
    beforeSend: function(xhr) {
      xhr.setRequestHeader('Authorization', at);
    }
  }).done(function(response) {
    console.log('response '+response);
    adminSetUserValues(response);
  });
  console.log("adminGetUser completed")
}

function adminSetUserValues(userJson) {
  console.log("adminsetuserValues was called");
  console.log(userJson);
  console.log(userJson._embedded.users[0].id);
  Cookies.set('currentUser', userJson._embedded.users[0].id);
  if (Cookies.get("accessToken")) {
    document.getElementById("user").value = 'Hello ' + userJson._embedded.users[0].username + "!";
    document.getElementById("fname").value = userJson._embedded.users[0].name.given;
    document.getElementById("lname").value = userJson._embedded.users[0].name.family;
    document.getElementById("email").value = userJson._embedded.users[0].email;
    document.getElementById("username").value = userJson._embedded.users[0].username;
    //document.getElementById("address").innerHTML=streetAddress;
  } else {
    document.getElementById("username").innerHTML = 'Welcome Guest';
  }

  //let idPayload = parseJwt(idToken);
}

function getUserValues() {
  console.log('getUserValues called');
  let method = "GET";
  let user = Cookies.get("uuid");
  let at = "Bearer " + Cookies.get("accessToken");
  let url = apiUrl + "/environments/" + environmentId + "/users/" + user;
  console.log('ajax (' + url + ')');
  console.log('at =' + at);
  console.log("make ajax call");
  $.ajax({
    async: "true",
    url: url,
    method: method,
    beforeSend: function(xhr) {
      xhr.setRequestHeader('Authorization', at);
    }
  }).done(function(response) {
    console.log(response);
    setUserValues(response);
  });
  console.log("getUserValues completed")

}

function getValueFromJson(obj, label) {
  if (obj.label === label) {
    return obj;
  }
  for (let i in obj) {
    if (obj.hasOwnProperty(i)) {
      let foundLabel = findObjectByLabel(obj[i], label);
      if (foundLabel) {
        return foundLabel;
      }
    }
  }
  return null;
}


function updateUser() {
  console.log("updateUser was called");
  let method = "PATCH";
  let user = Cookies.get("uuid");
  let at = "Bearer " + Cookies.get("accessToken");
  let url = apiUrl + "/environments/" + environmentId + "/users/" + user;
  let payload = JSON.stringify({
    username: $('#username').val(),
    name: {
      given: $('#fname').val(),
      family: $('#lname').val()
    }
  });
  console.log(payload);
  console.log('ajax (' + url + ')');
  console.log('at =' + at);
  console.log("make ajax call");
  $.ajax({
      async: "true",
      url: url,
      method: method,
      dataType: 'json',
      contentType: 'application/json',
      data: payload,
      beforeSend: function(xhr) {
        xhr.setRequestHeader('Authorization', at);
      }
    }).done(function(data) {
      console.log(data);
    })
    .fail(function(data) {
      console.log('ajax call failed');
      console.log(data);
      $('#warningMessage').text(data.responseJSON.details[0].message);
      $('#warningDiv').show();
    });

  //add brief delay so info is populated
  setTimeout(function() {
    getUserValues();
  }, 1000);

}


//MFA stuff
function getMFADevices(){
  console.log("getMFADevices was called");
  let user =Cookies.get('uuid');
  let method = "GET";
  let url = apiUrl + "/environments/" + environmentId + "/users/" + user +"/devices";
  console.log('url:' + url);
//  let devices = exJax("GET", url)

}

function updateMFA(){
  console.log("updateMFA was called");
  let method = "POST";
  let user = Cookies.get("uuid");
  let at = "Bearer " + Cookies.get("accessToken");
  let url = apiUrl + "/environments/" + environmentId + "/users/" + user + 'devices';
  let payload = JSON.stringify({
    type: 'SMS',
    phone: $('#device').val()
  });
  console.log(payload);
  console.log('ajax (' + url + ')');
  console.log('at =' + at);
  console.log("make ajax call");
  $.ajax({
      async: "true",
      url: url,
      method: method,
      dataType: 'json',
      contentType: 'application/json',
      data: payload,
      beforeSend: function(xhr) {
        xhr.setRequestHeader('Authorization', at);
      }
    }).done(function(data) {
      console.log(data);
    })
    .fail(function(data) {
      console.log('ajax call failed');
      console.log(data);
      $('#warningMessage').text(data.responseJSON.details[0].message);
      $('#warningDiv').show();
    });

    console.log('enableMFA');
    let payloadEnable = JSON.stringify({
      mfaEnabled: 'true',
    });
    $.ajax({
        async: "true",
        url: url,
        method: 'PUT',
        dataType: 'json',
        contentType: 'application/json',
        data: payload,
        beforeSend: function(xhr) {
          xhr.setRequestHeader('Authorization', at);
        }
      }).done(function(data) {
        console.log(data);
      })
      .fail(function(data) {
        console.log('ajax call failed');
        console.log(data);
        $('#warningMessage').text(data.responseJSON.details[0].message);
        $('#warningDiv').show();
      });

  //add brief delay so info is populated
  setTimeout(function() {
    getUserValues();
  }, 1000);
}





function getAccessToken() {
  console.log("getAccessToken was called");
  let url = authUrl + "/environments/" + environmentId + "/as/token";
  console.log(url);
  let tok = workerClientId + ':' + workerClientSecret;
  let hash = btoa(tok);
  let auth = "Basic " + hash;
  let contentType = "application/x-www-form-urlencoded";
  console.log(auth);
  exJax("POST", url, nextStep, contentType, payload);

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

function getAllUsers() {
  console.log("getAllUsers called");
  let method = "GET";
  let at = "Bearer " + Cookies.get("accessToken");
  let url = apiUrl + "/environments/" + environmentId + "/users";
  console.log('ajax (' + url + ')');
  console.log('at =' + at);
  console.log("make ajax call");
  $.ajax({
      async: "true",
      url: url,
      method: method,
      beforeSend: function(xhr) {
        xhr.setRequestHeader('Authorization', at);
      }
    }).done(function(data) {
      console.log("data from get" + data);
      populateTable(data);
    })
    .fail(function(data) {
      console.log('ajax call failed');
      console.log(data);
      $('#warningMessage').text(data.responseJSON.details[0].message);
      $('#warningDiv').show();
    });
  console.log("getAllUsers completed")
}

function populateTable (json) {
  console.log('populateTable called');
  console.log(json);
  const len = Object.keys(json).length;
  const users = Object(json._embedded.users);
  // var users = JSON.parse(userslist);
  console.log(users);
  if (len > 0) {
    for (var i = 0; i < len; i++) {
      let value = users[i];
      console.log(value);
      console.log('object above, company below');
      value = JSON.stringify(value);
      value = JSON.parse(value);
      // console.log(value.company);
      console.log(Object.entries(value));
      // let values = Object.entries(value);
      // let companyarray = Object.entries(value[4]);
      // txt += "<tr><td>"+value.company+"</td><td>"+value.name.family+"</td><td>"+value.name.given+"</td><td>"+users[i].email+"</td><td>"+value.email+"</td><td>"+value.primaryPhone+"</td></tr>";
    }
  }
}

function getSubscriptions (userData) {  //will need ot use getUserValues() to get info to function
  console.log(userData);
  let mySubs = userData.subscriptions;
  console.log(mySubs);
  var table = document.createElement('table');
  let tr = table.instertRow(-1);
  for (var i = 0; i < mySubs.length; i++){

  }
}

/* sendOTPForgetPassword() {
  console.log('sendOTPForgetPassword called');
  let payload = JSON.stringify({
    username: $('#user_login').val()
  });
  let url = $('#forgotPasswordURL').val();
  let contenttype = 'application/vnd.pingidentity.password.forgot+json';
  console.log(url);
  exJax('POST', url, nextStep, contenttype, payload);
}

setForgotPassword(otp, password) {
  console.log('setForgotPassword called');
  let payload = JSON.stringify({
    recoveryCode: $('#otp_reset').val(),
    newPassword: $('#user_new_pass').val()

  });
  let url = $('#forgotPasswordURL').val();
  let contenttype = $('#changePasswordContentType').val();
  exJax('POST', url, nextStep, contenttype, payload);
}

*/

//--------Registration -------//
function registerUser() {
  console.log("registerUser was called");
  let method = "POST";
  let contentType = 'application/vnd.pingidentity.user.register+json';
  //let url = apiUrl + "/environments/" + environmentId + "/flows/" + flowId;
  let url = $('#registerUserUrl').val();

  let payload = JSON.stringify({
    Attr2: $('#user_company').val(),
    population: {
      id: "57ee5904-32f3-4bfe-9504-d40704edeab0"
    },
    username: $('#user_login').val(),
    phone: $('#user_phoneNumber').val(),
    email: $('#user_email').val(),
    password: $('#user_pass').val()
  });
  console.log('url:' + url);
  console.log('payload:' + payload);
  exJax("POST", url, nextStep, contentType, payload);

  //add brief delay so info is populated
  //setTimeout(function() {
  //  getUserValues();
  //}, 1000);
}

function verifyUser(){
  console.log('verifyUser called');
  let otp = $('#otp_login').val();
  let payload = JSON.stringify({
    verificationCode: $('#otp_login').val()
  });
  //let url = $('#validateOtpUrl').val();
  //let url = $('verifyUserUrl').val();
  let url = authUrl + '/'+ environmentId + '/flows/' + flowId;
  let contenttype ='application/vnd.pingidentity.user.verify+json';
  console.log('url :' + url);
  console.log('verificationCode: ' + otp);
  console.log('content' + contenttype);

  exJax('POST', url, nextStep, contenttype, payload);
}

function redirect_toReg(){
  location.href = 'https://morganapps.ping-eng.com/myP14CDemo/content/finance/register.html?' + 'environmentId=' + environmentId + '&flowId=' + flowId;
}



//Progessivce Profile
