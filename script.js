async function encryptText() {
    const text = document.getElementById("textInput").value;
    const password = document.getElementById("passwordInput").value;
    if (!text || !password) {
        alert("Please enter both text and password!");
        return;
    }

    const iv = crypto.getRandomValues(new Uint8Array(12)); // Initialization Vector (IV)
    const encoder = new TextEncoder();
    const passwordKey = await deriveKey(password);

    const encryptedData = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        passwordKey,
        encoder.encode(text)
    );

    const encryptedBase64 = encodeBase64(new Uint8Array(encryptedData), iv);
    document.getElementById("output").value = encryptedBase64;
}

async function decryptText() {
    const encryptedText = document.getElementById("textInput").value;
    const password = document.getElementById("passwordInput").value;
    if (!encryptedText || !password) {
        alert("Please enter both encrypted text and password!");
        return;
    }

    try {
        const { encryptedData, iv } = decodeBase64(encryptedText);
        const passwordKey = await deriveKey(password);
        const decryptedData = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            passwordKey,
            encryptedData
        );

        const decoder = new TextDecoder();
        document.getElementById("output").value = decoder.decode(decryptedData);
    } catch (error) {
        alert("Decryption failed! Make sure you have the correct password.");
    }
}

async function deriveKey(password) {
    const encoder = new TextEncoder();
    const salt = new Uint8Array(16); // Ensure same salt (use a fixed value for consistency across encryption and decryption)

    const keyMaterial = await crypto.subtle.importKey(
        "raw", 
        encoder.encode(password), 
        { name: "PBKDF2" }, 
        false, 
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

function encodeBase64(data, iv) {
    const ivBase64 = btoa(String.fromCharCode(...iv));
    const encryptedBase64 = btoa(String.fromCharCode(...data));
    return ivBase64 + ':' + encryptedBase64; // Combine IV and encrypted text
}

function decodeBase64(base64String) {
    const [ivBase64, encryptedBase64] = base64String.split(':');
    const iv = new Uint8Array(atob(ivBase64).split('').map(c => c.charCodeAt(0)));
    const encryptedData = new Uint8Array(atob(encryptedBase64).split('').map(c => c.charCodeAt(0)));
    return { iv, encryptedData };
}
