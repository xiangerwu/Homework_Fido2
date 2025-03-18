/* 
    函式名稱: base64UrlToUint8Array
    作用:將 base64url 字串轉換為 Uint8Array
    參數: base64Url (string) - base64url 字串
    回傳: uint8Array (Uint8Array) - Uint8Array 格式
*/
function base64UrlToUint8Array(base64) {
    const binary = atob(base64.replace(/_/g, '/').replace(/-/g, '+'));  //Base64 修正
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}
/*
    函式名稱: uint8ArrayToBase64Url
    作用: 將 Uint8Array 轉換為 base64url 字串
    參數: uint8Array (Uint8Array) - Uint8Array 格式
    回傳: base64Url (string) - base64url 字串
*/
function uint8ArrayToBase64Url(uint8Array) {
    const binaryString = String.fromCharCode(...uint8Array);
    return btoa(binaryString)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}
/*
    函式名稱: arrayBufferToBase64
    作用: 將 ArrayBuffer 轉換為 base64 字串
    參數: buffer (ArrayBuffer) - ArrayBuffer 格式
    回傳: base64 (string) - base64 字串
*/
function arrayBufferToBase64(buffer) {
    let binary = "";
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

/*
    函式名稱: showMessage
    作用: 顯示訊息在網頁上
    參數: elementId (string) - HTML 元素的 ID
    message (string) - 訊息
*/
function showMessage(elementId, message) {
    document.getElementById(elementId).textContent = message;
}

/*
    函式名稱: appendMessage
    作用: 附加訊息在網頁上
    參數: elementId (string) - HTML 元素的 ID
    message (string) - 訊息
*/
function appendMessage(elementId, message) {
    document.getElementById(elementId).textContent += message;
}

/*
    函式名稱: NetworkError
    作用: 網路錯誤處理
    參數: message (string) - 錯誤訊息
    回傳: location.reload() - 重新整理頁面
*/
function NetworkError(message) {
    const error = message.toString();
    if (error.includes("NetworkError")) {
        alert("網路錯誤，請檢查網路連線！");
        return true;
    }
    return false;
}

// 切換折疊區塊
async function toggleCollapse(id, btn) {
    const section = document.getElementById(id);
    section.classList.toggle("show");

    // 切換按鈕方向
    if (section.classList.contains("show")) {
        btn.innerHTML = "▼";
    } else {
        btn.innerHTML = "▶";
    }
}

// 使用 SHA-256 加密密碼
async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, "0")).join("");
    return hashHex;
}

// 判斷是否是 iOS Safari
async function isiOSSafari() {

    let result = /iP(ad|hone|od).+Version\/[\d.]+.*Safari/i.test(navigator.userAgent);
    return result;
}

// 將憑證轉換為 JSON 格式
function credentialToJSON(credential) {
    if (!credential) return null;

    // **用 Object.assign() 創建新物件，避免直接讀取 `credential` 屬性**
    let temp_json = Object.assign({}, credential);
    temp_json.rawId = credential.rawId ? arrayBufferToBase64(credential.rawId) : null;
    temp_json.authenticatorAttachment = credential.authenticatorAttachment || null,
    temp_json.clientExtensionResults = credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
    temp_json.id = credential.id,
    temp_json.response = {
        attestationObject: credential.response.attestationObject
            ? arrayBufferToBase64(credential.response.attestationObject)
            : null,
        authenticatorData: credential.response.getAuthenticatorData
            ? arrayBufferToBase64(credential.response.getAuthenticatorData())
            : null,
        clientDataJSON: credential.response.clientDataJSON
            ? arrayBufferToBase64(credential.response.clientDataJSON)
            : null,
        publicKey: credential.response.getPublicKey
            ? arrayBufferToBase64(credential.response.getPublicKey())
            : null,
        publicKeyAlgorithm: credential.response.getPublicKeyAlgorithm
            ? credential.response.getPublicKeyAlgorithm()
            : null,
        transports: credential.response.getTransports ? credential.response.getTransports() : [],
};
    temp_json.type = credential.type;
    return temp_json;
}

// 匯出函式，讓其他程式使用
export {
    base64UrlToUint8Array,
    uint8ArrayToBase64Url,
    arrayBufferToBase64,
    showMessage,
    appendMessage,
    NetworkError,
    toggleCollapse,
    hashPassword,
    isiOSSafari,
    credentialToJSON,
}