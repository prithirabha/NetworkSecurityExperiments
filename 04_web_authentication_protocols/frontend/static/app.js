let token = "";

function login(){

    fetch("/login",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({
            username:document.getElementById("username").value,
            password:document.getElementById("password").value
        })
    })
    .then(r=>r.json())
    .then(d=>{
        token=d.token
        localStorage.setItem("token",token)
        displayToken()
    })
}

function loginSecure() {
    fetch("/login/secure", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            username: document.getElementById("username").value,
            password: document.getElementById("password").value
        })
    })
    .then(r => r.json())
    .then(d => {
        token = d.token;
        localStorage.setItem("token", token);
        displayToken();
    });
}

function loginInsecure() {
    fetch("/login/insecure", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            username: document.getElementById("username").value,
            password: document.getElementById("password").value
        })
    })
    .then(r => r.json())
    .then(d => {
        token = d.token;
        localStorage.setItem("token", token);
        displayToken();
    });
}

function displayToken() {
    let parts = token.split(".");

    document.getElementById("header").innerText =
        JSON.stringify(JSON.parse(atob(parts[0])), null, 2);

    document.getElementById("payload").innerText =
        JSON.stringify(JSON.parse(atob(parts[1])), null, 2);

    document.getElementById("signature").innerText = parts[2];
}

function runAttack(name) {
    fetch("/attack/" + name, { method: "POST" });
}

function simulateXSS(){

    let stolen = localStorage.getItem("token")

    fetch("/attack/xss",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({token:stolen})
    })

}

function base64ToArrayBuffer(base64url) {

    // Convert Base64URL → Base64
    let base64 = base64url
        .replace(/-/g, "+")
        .replace(/_/g, "/")

    // Pad if necessary
    while (base64.length % 4 !== 0) {
        base64 += "="
    }

    const binary = atob(base64)

    const bytes = new Uint8Array(binary.length)

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i)
    }

    return bytes.buffer
}

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

async function registerPasskey(){

    let res = await fetch("/webauthn/register",{method:"POST"})
    let options = await res.json()

    options.publicKey.challenge = base64ToArrayBuffer(options.publicKey.challenge)
    options.publicKey.user.id = base64ToArrayBuffer(options.publicKey.user.id)

    let credential = await navigator.credentials.create(options)

    await fetch("/webauthn/register/finish",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body: JSON.stringify(credential)
    })
}

async function loginPasskey() {

    const res = await fetch("/webauthn/login", { method: "POST" });
    let options = await res.json();

    options.publicKey.challenge = base64ToArrayBuffer(options.publicKey.challenge);

    if (options.publicKey.allowCredentials) {
        options.publicKey.allowCredentials = options.publicKey.allowCredentials.map(c => ({
            ...c,
            id: base64ToArrayBuffer(c.id)
        }));
    }

    const credential = await navigator.credentials.get({
        publicKey: options.publicKey
    });

    const data = {
        id: credential.id,
        rawId: arrayBufferToBase64(credential.rawId),
        type: credential.type,
        response: {
            authenticatorData: arrayBufferToBase64(credential.response.authenticatorData),
            clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON),
            signature: arrayBufferToBase64(credential.response.signature),
            userHandle: credential.response.userHandle
                ? arrayBufferToBase64(credential.response.userHandle)
                : null
        }
    };

    await fetch("/webauthn/login/finish", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
    });
}


let chartInstance = null;

function runBenchmark() {
    fetch("/benchmark")
        .then(r => r.json())
        .then(d => {

            if (chartInstance) {
                chartInstance.destroy();
            }

            const ctx = document.getElementById("chart").getContext("2d");

            chartInstance = new Chart(ctx, {
                type: "bar", 
                data: {
                    labels: ["Symmetric", "Asymmetric"],
                    datasets: [{
                        label: "ms",
                        data: [
                            Number(d.symmetric_ms),
                            Number(d.asymmetric_ms)
                        ]
                    }]
                },
                options: {
                    scales: {
                        y: {
                            type: "logarithmic", 
                            beginAtZero: false
                        }
                    },
                    plugins: {
                        title: {
                            display: true,
                            text: `Asymmetric is ${d.ratio.toFixed(1)}x slower`
                        }
                    }
                }
            });
        });
}

function pollLogs() {
    fetch("/logs")
        .then(r => r.json())
        .then(d => {
            document.getElementById("logs").innerText = d.join("\n");
        });
}

setInterval(pollLogs, 1000);