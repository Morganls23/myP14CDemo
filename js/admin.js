type = 'text/javascript';

const adminClientId = 'd915beea-7682-4441-b7ed-92fef5b3b9bb';
const adminClientSecret = 'DdkqZjXBqnpQ_0hy19cX8bKRvv_ZSOxIKk.byHqEAf2cSlOE7XoOLEU63euEjnx.';
const adminRedirectUri =baseUrl + 'myP14CDemo/content/finance/admin-login.html';
const adminScopes = 'profile address phone email openid';


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
          console.log(response);
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
