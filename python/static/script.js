// 函式名稱: base64UrlToUint8Array
// 作用:將 base64url 字串轉換為 Uint8Array
// 參數: base64Url (string) - base64url 字串
// 回傳: uint8Array (Uint8Array) - Uint8Array 格式
function base64UrlToUint8Array(base64Url) {
    if (!base64Url) {
        throw new Error("base64Url is undefined");
    }
    const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
    const padding = "=".repeat((4 - (base64.length % 4)) % 4);
    const base64WithPadding = base64 + padding;
    const rawData = atob(base64WithPadding);
    const uint8Array = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; i++) {
        uint8Array[i] = rawData.charCodeAt(i);
    }
    return uint8Array;
}
// 函式名稱: uint8ArrayToBase64Url
// 作用: 將 Uint8Array 轉換為 base64url 字串
// 參數: uint8Array (Uint8Array) - Uint8Array 格式
// 回傳: base64Url (string) - base64url 字串
function uint8ArrayToBase64Url(uint8Array) {
    const binaryString = String.fromCharCode(...uint8Array);
    return btoa(binaryString)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}

// 函式名稱: arrayBufferToBase64
// 作用: 將 ArrayBuffer 轉換為 base64 字串
// 參數: buffer (ArrayBuffer) - ArrayBuffer 格式
// 回傳: base64 (string) - base64 字串
function arrayBufferToBase64(buffer) {
    let binary = "";
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

// 函式名稱: showMessage
// 作用: 顯示訊息在網頁上
// 參數: elementId (string) - HTML 元素的 ID
//      message (string) - 訊息
function showMessage(elementId, message) {
    document.getElementById(elementId).textContent = message;
}

// 函式名稱: sendRequest
// 作用: 向後端發送請求
// 參數: url (string) - 請求的路徑
//      method (string) - 請求的方法
//      data (object) - 請求的資料
// 回傳: response.json() - 後端回應的資料
async function sendRequest(url, method, data) {
    const response = await fetch(
        "https://localhost:5000" + url, {
        method: method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
    });
    return response.json();
}

// async 函式名稱: (WebAuthn 註冊 register)
// 作用: 向後端發送註冊請求，取得註冊選項，並將憑證資訊傳送到後端
async function register() {
    // 取得使用者名稱
    const username = document.getElementById("username").value;
    if (!username) {
        alert("請輸入使用者名稱");
        return;
    }
    // 執行 WebAuthn 註冊
    try {
        // 向後端請求 WebAuthn 註冊選項
        const options = await sendRequest("/register", "POST", { username });
        console.log("後端回傳 challenge:", options.challenge);
        showMessage("Register_Challenge", options.challenge)
        // 判斷 options 是否 error
        if (options.error) {
            console.error("註冊錯誤:", options.error);
            alert("註冊失敗:" + options.error + "！");
            return;
        }

        // 後端正確回應後，將 options 轉換為 WebAuthn API 可用的格式
        // 原本的 challenge 和 user.id 都是 base64url 字串
        // 需要轉換為 Uint8Array 格式
        options.challenge = base64UrlToUint8Array(options.challenge);
        options.user.id = base64UrlToUint8Array(options.user.id);

        // 之後將憑證資訊儲存到瀏覽器的 API 中
        const credential = await navigator.credentials.create({ publicKey: options });
        console.log("瀏覽器已註冊憑證:", credential);

        showMessage("Register_credentialInfo", `User: ${username}\n${JSON.stringify(credential, null, 2)}`);

        // 將憑證資料傳送到後端
        console.log("將憑證資料傳送到後端");
        const result = await sendRequest("/store-credential", "POST", {
            username: username,
            credential: {
                id: credential.id,
                rawId: uint8ArrayToBase64Url(new Uint8Array(credential.rawId)),
                response: {
                    attestationObject: uint8ArrayToBase64Url(new Uint8Array(credential.response.attestationObject)),
                    clientDataJSON: uint8ArrayToBase64Url(new Uint8Array(credential.response.clientDataJSON)),
                },
                type: credential.type,
            },
        });

        // 解析回傳資料是否有錯誤，有錯誤則顯示錯誤訊息
        if (result.error) {
            console.error("後端回覆資料錯誤:", result.error);
            alert("後端回覆資料錯誤，請看主控台");
            return;
        }

        console.log("註冊成功！請查看憑證資訊，接下來嘗試登入看看。");
        alert("註冊成功！請查看憑證資訊，接下來嘗試登入看看。");

    } catch (error) {
        console.error("註冊過程失敗:", error);
        alert("註冊過程失敗，請看主控台");
    }

} // end of register()

// async 函式 (WebAuthn 向後端確認使用者存在並取得憑證)
async function verify_register() {

    console.log("細分驗證流程");
    console.log("1.向後端確認使用者存在");
    // 取得使用者名稱
    const username = document.getElementById("username").value;
    if (!username) {
        alert("請輸入使用者名稱");
        return;
    }

    try {
        // 傳送使用者名稱到後端
        const options = await sendRequest("/verify-register", "POST", { username });

        // 取得後端回應
        console.log("認證選項:", options.challenge);
        showMessage("Verify_Challenge", options.challenge)
        if (options.error) {
            console.error("認證錯誤(後端回應 error):", options.error);
            alert("認證失敗(後端回應 error):" + options.error + "！");
            return;
        }
        console.log("2.後端回傳使用者資料再從瀏覽器取得憑證");
        // 將 options 轉換為 WebAuthn API 可用的格式
        //options.challenge = base64UrlToUint8Array( options.challenge );

        // 認證憑證
        const credential = await navigator.credentials.get(
            {
                publicKey: {
                    challenge: base64UrlToUint8Array(options.challenge),
                    rpId: "localhost",
                    userVerification: "required"
                }
            }
        );
        console.log("瀏覽器已認證憑證:", credential);
        // 顯示憑證資訊在網頁上
        showMessage("verify-register_credentialInfo", `User: ${username}\n${JSON.stringify(credential, null, 2)}`);

        console.log("3.將憑證傳給後端完成登入");

        // 將認證結果傳送給後端進行驗證
        const verifyResult = await sendRequest("/verify-credential", "POST", {
            username: username,
            credential: {
                id: credential.id,
                rawId: arrayBufferToBase64(credential.rawId),
                response: {
                    clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON),
                    authenticatorData: arrayBufferToBase64(credential.response.authenticatorData),
                    signature: arrayBufferToBase64(credential.response.signature),
                    userHandle: credential.response.userHandle ? arrayBufferToBase64(credential.response.userHandle) : null,
                },
                type: credential.type,
            },
        });


        console.log("登入驗證結果:", verifyResult);

        if (verifyResult.error) {
            console.error("登入驗證錯誤:", verifyResult.error);
            alert("登入驗證失敗:" + verifyResult.error + "！");
            return;
        }

        alert("認證成功！");
    } catch (error) {
        console.error("認證錯誤:", error);
        alert("認證失敗！");
    }
} // end of verify_register()

// 清除憑證資訊
async function clearData() {
    showMessage("Register_credentialInfo", "");
    showMessage("verify-register_credentialInfo", "");

    try {
        const result = await sendRequest("/clear", "POST", "No Data");
        console.log("清除結果:", result);

        await navigator.credentials.preventSilentAccess();
        console.log("前端瀏覽器中的憑證已清除");
        alert("憑證資訊已清除！");
    } catch (error) {
        console.error("清除錯誤:", error);
        alert("清除失敗！");
    }
} // end of clear()