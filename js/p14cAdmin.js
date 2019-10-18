// variable definitions and building authorization url
type="text/javascript";
const environmentId = 'e2431bcc-0d0b-4574-9dbc-ff8c91bb799e'; // available on settings page of p14c admin console
const clientId = 'dc43b43e-1a3e-4d1f-bacb-280dfb53e835'; // available on connections tab of admin console
const baseUrl = 'https://morganapps.ping-eng.com/'; // URL of where you will host this application
const clientsecret = '0KMjPI3YGV4CbBH~VFIc.9jNROGwFCf9OQsomzi_bGtxZzkhpJxGZyFZ9~hD_s5H';
const scopes = 'openid profile email address phone'; // default scopes to request
const responseType = 'token id_token'; //tokens to recieve

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



function doLogin() {
  let nonce = generateNonce(60);
  let authorizationUrl =
    authUrl +
    '/' +
    environmentId +
    '/as/authorize?response_type=' +
    responseType +
    '&client_id=' +
    clientId +
    '&redirect_uri=' +
    redirectUri +
    '&scope=' +
    scopes +
    '&nonce=' +
    nonce;

  window.localStorage.setItem('nonce', nonce);

  // window.localStorage.setItem('nonce', 'bogus nonce that does not match');

  window.location.href = authorizationUrl;
}

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


function renderDivState(){
  console.log("renderDiv called");
  console.log(Cookies.get('accessToken'));

  if(Cookies.get('accessToken')){
    let login = document.getElementById("loginDiv");
    login.style.display = "none";
    let account = document.getElementById("myAccount");
    account.style.display = "block";

  }
  else {
    let login = document.getElementById("loginDiv");
    login.style.display = "block";

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
function getUrlParameter(parameterName) {
  console.log('getUrlParameter was called');
  let pageUrl = window.location.href;
  console.log('pageUrl: ' + pageUrl);
  let pound = "#";
  let q = "?";
  if (pageUrl.includes(pound)) {
    console.log("pageUrl is not null and has #");
    pageUrl = pageUrl.substring(pageUrl.indexOf(pound)+1);
    console.log("removed base at #:" + pageUrl);
    let urlVariables = pageUrl.split('&');

    console.log("urlVariables: " + urlVariables);
    for (let i = 0; i < urlVariables.length; i++) {
      let thisParameterName = urlVariables[i].split('=');
      if (thisParameterName[0] == parameterName) {
        console.log("parameterName:"+thisParameterName[1]);
        return thisParameterName[1];
      }
      if(thisParameterName[0].includes("access_token")){
        console.log("setting at cookie : " + thisParameterName[1]);
        Cookies.set('accessToken', thisParameterName[1]);
      }
      if(thisParameterName[0].includes("id_token")){
        console.log("setting id cookie : " + thisParameterName[1]);
        let idToken=thisParameterName[1];
        Cookies.set('idToken', idToken);
        setUserinfoCookie();
      }

      console.log(thisParameterName);
      console.log("remove AT and IDT from URL");
      window.location.replace(landingUrl);
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


function setUserinfoCookie(){
  let idToken = Cookies.get('idToken');
  let idPayload = parseJwt(idToken);
  Cookies.set('uuid', idPayload.sub);
  //Cookies.set('name', idPayload.given_name);
}

function setUserValues(userJson){
  console.log("setuserValues was called");
  console.log(userJson);
  let uuid = Cookies.get('uuid');
  //let streetAddress = userJson.address.streetAddress + " " + userJson.address.locality + ", " + userJson.address.region + " " + userJson.address.postalCode;
  if (Cookies.get("accessToken")){
    document.getElementById("user").value='Hello ' + userJson.name.given +"!";
    document.getElementById("fname").value=userJson.name.given;
    document.getElementById("lname").value=userJson.name.family;
    document.getElementById("email").value=userJson.email;
    document.getElementById("username").value=userJson.username;
    //document.getElementById("address").innerHTML=streetAddress;
  } else {
    document.getElementById("username").innerHTML='Welcome Guest';
  }

  //let idPayload = parseJwt(idToken);
}

function getUserValues(){
  console.log("getUserValues called");
  let method = "GET";
  let user = Cookies.get("uuid");
  let at = "Bearer " + Cookies.get("accessToken");
  let url = apiUrl + "/environments/" + environmentId + "/users/" + user;
  console.log('ajax (' + url + ')');
  console.log('at =' +at);
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

function getValueFromJson(obj, label){
   if(obj.label === label) { return obj; }
   for(let i in obj) {
       if(obj.hasOwnProperty(i)){
           let foundLabel = findObjectByLabel(obj[i], label);
           if(foundLabel) { return foundLabel; }
       }
   }
   return null;
}


function updateUser(){
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
        contentType:'application/json',
        data: payload,
        beforeSend: function(xhr) {
            xhr.setRequestHeader('Authorization', at);
        }
      })    .done(function(data) {
            console.log(data);
          })
          .fail(function(data) {
            console.log('ajax call failed');
            console.log(data);
            $('#warningMessage').text(data.responseJSON.details[0].message);
            $('#warningDiv').show();
          });

          //add brief delay so info is populated
          setTimeout(function() { getUserValues(); }, 1000);

}

function getAccessToken(){
  console.log("getAccessToken was called");
  let url = authUrl + "/environments/" + environmentId + "/as/token";
  console.log(url);
  let tok = clientId + ':' + clientsecret;
  let hash = btoa(tok);
  let auth = "Basic " + hash;
  console.log(auth);
  //let settings =

  $.ajax({
    async: "true",
    method: "POST",
    url: "https://auth.pingone.com/e2431bcc-0d0b-4574-9dbc-ff8c91bb799e/as/token",
    beforeSend: function(xhr) {
        xhr.setRequestHeader(
            "Authorization", "Basic ZGM0M2I0M2UtMWEzZS00ZDFmLWJhY2ItMjgwZGZiNTNlODM1OjBLTWpQSTNZR1Y0Q2JCSH5WRkljLjlqTlJPR3dGQ2Y5T1Fzb216aV9iR3R4WnpraHBKeEdaeUZaOX5oRF9zNUg="
    )},
    headers: {
      "Content-Type": "application/json",
      //"Authorization": "Basic ZGM0M2I0M2UtMWEzZS00ZDFmLWJhY2ItMjgwZGZiNTNlODM1OjBLTWpQSTNZR1Y0Q2JCSH5WRkljLjlqTlJPR3dGQ2Y5T1Fzb216aV9iR3R4WnpraHBKeEdaeUZaOX5oRF9zNUg=",
      "cache-control": "no-cache",
      "access-control-allow-headers": "cache-control, Origin, Authorization",
      "Access-Control-Allow-Methods": "POST, GET, OPTIONS"
    },
    data: {
      "scope": "openid profile",
      "grant_type": "client_credentials"
    },
    xhrFields: {
      withCredentials: true
    }
  })
  .done(function(data) {
        console.log(data);
      })
      .fail(function(data) {
        console.log('ajax call failed');
        console.log(data);
        $('#warningMessage').text(data.responseJSON.details[0].message);
        $('#warningDiv').show();
      });
}

function registerUser(){
  console.log("registerUser was called");
    let method = "POST";
    let at = "Bearer " + Cookies.get("accessToken");
    let url = apiUrl + "/environments/" + environmentId + "/users/" + user;
    let payload = JSON.stringify({
      company: $('#user_company').val(),
      username: $('#user_login').val(),
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
        contentType:'application/json',
        data: payload,
        beforeSend: function(xhr) {
            xhr.setRequestHeader('Authorization', at);
        },
        xhrFields: {
          withCredentials: true
        }
      })    .done(function(data) {
            console.log(data);
          })
          .fail(function(data) {
            console.log('ajax call failed');
            console.log(data);
            $('#warningMessage').text(data.responseJSON.details[0].message);
            $('#warningDiv').show();
          });

          //add brief delay so info is populated
          setTimeout(function() { getUserValues(); }, 1000);
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

function populateTable(){
    let json=getUserValues();
    //while running this code the template will be appended in your div with json data
    $("#tbody").jPut({
        jsonData:json,
        //ajax_url:"youfile.json",  if you want to call from a json file
        name:"tbody_template",
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
