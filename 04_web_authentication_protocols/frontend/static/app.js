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

function runBenchmark() {
    fetch("/benchmark")
        .then(r => r.json())
        .then(d => {
            new Chart(document.getElementById("chart"), {
                type: "bar",
                data: {
                    labels: ["JWT", "WebAuthn"],
                    datasets: [
                        {
                            label: "ms",
                            data: [d.jwt, d.webauth]
                        }
                    ]
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