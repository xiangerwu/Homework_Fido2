// window.direct_url = "https://fido2-web.akitawan.moe"; // 上線環境
// 根據部署環境動態取得 base path
window.base_path = window.location.pathname.split("\main")[0].replace(/\/+$/, ''); // 移除尾端斜線

// 函式名稱: sendRequest
// 作用: 向後端發送請求
// 參數: url (string) - 請求的路徑
//      method (string) - 請求的方法
//      data (object) - 請求的資料
// 回傳: response.json() - 後端回應的資料
async function sendRequest(url, method, data) {
    try {
        const response = await fetch(
            window.base_path + url, {
            method: method,
            headers: { "Content-Type": "application/json" },
            body: data?JSON.stringify(data): null,
            credentials: "include", // 這行是讓 cookie 可以傳送到後端
        });
        const text = await response.text();
        let result;

        try {
            result = JSON.parse(text);
        } catch {
            result = { error: "❌ 後端回傳非 JSON 格式", raw: text };
        }

        if (!response.ok) {
            result.error = result.error || `❌ 錯誤狀態碼 ${response.status}`;
        }

        return result;
    } catch (error) {
        return { error: "❌ 請求失敗：" + error.message };
    }
}


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
    if (!buffer || !(buffer instanceof ArrayBuffer) || buffer.byteLength === 0) return "";
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

// 使用 SHA-256 加密密碼
async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, "0")).join("");
    return hashHex;
}


// 將憑證轉換為 JSON 格式
function credentialToJSON(credential) {
    if (!credential) return null;
    // **用 Object.assign() 創建新物件，避免直接讀取 `credential` 屬性**
    let temp_json = Object.assign({}, credential);
    temp_json.authenticatorAttachment = credential.authenticatorAttachment || null,
    temp_json.clientExtensionResults = credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
    temp_json.id = credential.id || "",
    temp_json.rawId = credential.rawId ? arrayBufferToBase64(credential.rawId) : "";
    const response_key = [
        "attestationObject",
        "authenticatorData",
        "clientDataJSON",
        "signature",
        "publicKey",
    ];
    temp_json.response = {};
    for (let key of response_key) {
        temp_json.response[key] = credential.response[key] ? arrayBufferToBase64(credential.response[key]) : "";
    }
    temp_json.response.transports = credential.response.transports || [];
    temp_json.type = credential.type || "public-key";
    return temp_json;
}


// 如果是 ios-safari 將憑證轉換為 JSON 格式 否則直接使用
function convertCredential(credential, useragent) {
    let check_ios = /iP(ad|hone|od).+Version\/[\d.]+.*Safari/i.test(navigator.userAgent);
    let credential_JSON = null;
    if (check_ios === true) { credential_JSON = credentialToJSON(credential); }
    else { credential_JSON = credential; }
    return credential_JSON;
}


// 隨機生成顏色
function getRandomColor() {
    const letters = '0123456789ABCDEF';
    let color = '#';
    for (let i = 0; i < 6; i++) {
        color += letters[Math.floor(Math.random() * 16)];
    }
    return color;
}


// 隨機設定跑馬燈顏色
function setRandomColor() {
    const marqueeTexts = document.querySelectorAll('.marquee-text');
    marqueeTexts.forEach((text) => {
        text.style.color = getRandomColor(); // 每次顯示時隨機顏色
    });
}


// 隨機打亂顯示順序並設置延遲時間
function setRandomOrder() {
    const marqueeTexts = document.querySelectorAll('.marquee-text');
    marqueeTexts.forEach((text) => {
        const randomDelay = Math.random() * 5; // 隨機延遲，範圍 0-5 秒
        text.style.animationDelay = `${randomDelay}s`; // 設置隨機延遲
    });
}


// 動態生成跑馬燈文字
function generateMarqueeText(count) {
    const container = document.querySelector('.marquee-container');

    for (let i = 0; i < count; i++) {
        const marqueeText = document.createElement('div');
        marqueeText.classList.add('marquee-text');
        marqueeText.textContent = 'Ciallo～(∠・ω< )⌒☆'; // 文字內容

        // 隨機設置顏色
        marqueeText.style.color = getRandomColor();

        // 隨機設置動畫延遲
        const randomDelay = Math.random() * 20; // 隨機延遲範圍 0-5 秒
        marqueeText.style.animationDelay = `${randomDelay}s`;

        // 增加複製的文字，使得滾動不會有空白區域
        // container.appendChild(marqueeText.cloneNode(true)); // 複製一個文字內容，讓文字無縫接續滾動
        container.appendChild(marqueeText); // 添加一個原始文字
    }
}


// XSS 防護
function escapeHTML(str) {
    const element = document.createElement('div');
    if (str) {
        element.innerText = str;
        element.textContent = str;
    }
    return element.innerHTML;
}

// 取得 URL 參數
function getURLParam(key) {
    return new URLSearchParams(window.location.search).get(key);
}
// 取得 Cookie
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

// 轉換特殊文字名稱
function htmlUnescape(str) {
    const div = document.createElement("div");
    div.innerHTML = str;
    return div.textContent;
}


// 顯示登入紀錄
async function showLoginHistory(username) {
    const loginHistorySection = document.getElementById("loginHistorySection");
    const loginHistoryTitle = document.getElementById("loginHistoryTitle");
    const loginHistory = document.getElementById("loginHistory");

    const userdata = await sendRequest("/authentication/user-log", "POST", { username });
    console.log("user_log:", userdata);

    // 更新標題
    loginHistoryTitle.innerText = `${username} 的登入紀錄`;

    // 清空舊資料
    loginHistory.innerHTML = "";

    try {
        // 檢查是否有紀錄
        if (userdata.length === 0) {
            loginHistory.innerHTML = `<tr><td colspan="6" class="text-center text-warning">無登入紀錄</td></tr>`;
        } else {
            // 迭代紀錄，填充表格
            userdata.forEach(log => {
                let row = `
                    <tr>
                    <td>${log.loginStatus ? "✅" : "❌"}</td>
                    <td>${log.ip}</td>
                    <td>${log.device}</td>
                    <td>${log.os}</td>
                    <td>${log.browser}</td>
                    <td>${log.loginTime}</td>
                    <td>${log.authenticator}</td>
                    </tr>
                `;
                loginHistory.innerHTML += row;
            });
        }

        // 顯示登入紀錄區塊
        loginHistorySection.classList.remove("d-none");

    } catch (error) {
        console.error("獲取登入紀錄時發生錯誤:", error);
        loginHistory.innerHTML = `<tr><td colspan="6" class="text-center text-danger">無法載入登入紀錄</td></tr>`;
    }
}


// 匯出函式，讓其他程式使用
export {
    sendRequest,
    base64UrlToUint8Array,
    uint8ArrayToBase64Url,
    arrayBufferToBase64,
    showMessage,
    appendMessage,
    NetworkError,
    hashPassword,
    credentialToJSON,
    getRandomColor,
    setRandomColor,
    setRandomOrder,
    generateMarqueeText,
    escapeHTML,
    convertCredential,
    getURLParam,
    getCookie,
    htmlUnescape,
    showLoginHistory,
}


