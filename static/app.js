async function queryServer(endpoint, options = {}) {
    const answer = await fetch(endpoint, options);
    const body = await answer.json();
    if (body.fail)
        throw body.fail;
    return body;
}

async function getCredentialOptions(data) {
    return queryServer("getCredentialOptions",
        {method: "POST", body: data})
        .then(data => parseCredentialOptions(data));
}

async function getAuthenticationOptions(data) {
    return queryServer("getAuthenticationOptions",
        {method: "POST", body: data})
        .then(data => parseAuthenticationOptions(data));
}

async function getCredentialsValidation(credentials, data) {
    credentials = parseCredentials(credentials);
    for (let key in credentials) {
        data.append(key, credentials[key]);
    }
    let x = {};
    data.forEach((value, key) => {
        x[key] = value
    });
    return queryServer("verifyCredentials",
        {
            method: "POST",
            headers: {"Content-Type": "application/json", 'Accept': 'application/json',},
            body: JSON.stringify(x)
        });
}

async function getLoginValidation(credentials, email) {
    data = new FormData;
    credentials = parseAuthenticationCredentials(credentials);
    for (let key in credentials) {
        data.append(key, credentials[key]);
    }
    data.append('email', email);
    return queryServer("verifyAuthentication",
        {
            method: "POST",
            body: data
        });
}

function parseCredentialOptions(options) {
    options.challenge = b64ToBytes(options.challenge);
    options.user.id = b64ToBytes(options.user.id);
    return options
}

function parseAuthenticationOptions(options) {
    if ("verified" in options) {
        return changeLoginStatus("Error getting Authentication options:" + options.reason, true);
    }
    options.challenge = b64ToBytes(options.challenge);

    for (let option of options.allowCredentials) {
        option.id = b64ToBytes(option.id)
    }
    return options

}

function parseCredentials(credentials) {
    return {
        id: credentials.id,
        rawId: bytesToB64(credentials.rawId),
        type: credentials.type,
        attestationObject: bytesToB64(credentials.response.attestationObject),
        clientData: bytesToB64(credentials.response.clientDataJSON),
        registrationClientExtensions: JSON.stringify(credentials.getClientExtensionResults())
    }
}

function parseAuthenticationCredentials(credentials) {
    return {
        id: credentials.id,
        rawId: bytesToB64(credentials.rawId),
        type: credentials.type,
        authenticatorData: bytesToB64(credentials.response.authenticatorData),
        clientData: bytesToB64(credentials.response.clientDataJSON),
        signature: bytesToB64(credentials.response.signature),
        userHandle: bytesToB64(credentials.response.userHandle),
        registrationClientExtensions: JSON.stringify(credentials.getClientExtensionResults())
    }
}

async function createCredentials(options) {
    let credential;
    try {
        credential = await navigator.credentials.create({
            publicKey: options
        });
    } catch (err) {
        return changeRegistrationStatus("Error creating credential: " + err, true);
    }

    return credential;
}

async function getCredentials(options) {
    let credential;
    try {
        credential = await navigator.credentials.get({
            publicKey: options
        });
    } catch (err) {
        return changeLoginStatus("Error getting credential: " + err, true);
    }

    return credential;
}

function b64ToBytes(input) {
    let str = atob(input);
    return Uint8Array.from(str, c => c.charCodeAt(0));
}

function bytesToB64(bytes) {
    return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

async function initRegistration() {
    const form = document.querySelector('#form-registration');
    let formData = new FormData(form);
    if (formData.get('email') === "" || formData.get('name') === "") {
        return;
    }
    changeRegistrationStatus("Initiating registration process...");
    const options = await getCredentialOptions(formData);
    if (options) {

        changeRegistrationStatus("Requesting data from authenticator");
        var credentials = await createCredentials(options);
    }
    if (credentials) {
        try {
            changeRegistrationStatus("Waiting for server validation")
            credentialsValidation = await getCredentialsValidation(credentials, formData);
            if (credentialsValidation.registered === true) {
                changeRegistrationStatus("Registered!")
            } else {
                changeRegistrationStatus("Error validating recieved credentials: " + credentialsValidation.reason, true);
            }
        } catch (err) {
            changeRegistrationStatus("Error validating recieved credentials: " + err, true);
        }
    }

}

async function login() {
    const form = document.querySelector('#form-login');
    let formData = new FormData(form);
    if (formData.get('email') === "") {
        return;
    }
    changeLoginStatus("Logging in...");

    const options = await getAuthenticationOptions(formData);

    if (options) {
        changeLoginStatus("Requesting data from authenticator");
        var credentials = await getCredentials(options);
    }
    if (credentials) {
        try {
            changeLoginStatus("Waiting for server validation");
            credentialsValidation = await getLoginValidation(credentials, formData.get('email'));
            if (credentialsValidation.verified === true) {
                changeLoginStatus("Logged in! Welcome back, " + credentialsValidation.name + "!");
            } else {
                changeLoginStatus("Error validating login credentials: " + credentialsValidation.reason, true);
            }
        } catch (err) {
            changeLoginStatus("Error validating login credentials: " + err, true);
        }
    }
}

function changeRegistrationStatus(status, isError = false) {
    document.getElementById("registration-status").innerHTML = status;
    if (isError) {
        document.getElementById("registration-status").className = "text-danger"
    } else {
        document.getElementById("registration-status").className = "text-success"
    }
}

function changeLoginStatus(status, isError = false) {
    document.getElementById("login-status").innerHTML = status;
    if (isError) {
        document.getElementById("login-status").className = "text-danger"
    } else {
        document.getElementById("login-status").className = "text-success"
    }
}