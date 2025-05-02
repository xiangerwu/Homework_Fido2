// OAuth 登入函式
// 這個函式會在 OAuth 登入頁面中被呼叫
// 它會向後端發送登入請求，並獲取 JWT token
// 然後將 token 傳回主頁面
import { 
    sendRequest,
    base64UrlToUint8Array, 
    convertCredential,
    getCookie,
    getURLParam,
    
} from "./web_functions.js";

window.oauth_login = oauth_login;

// 彈出式視窗的 登入按鈕觸發函式
async function oauth_login() {
    const username = document.getElementById("username").value;
    if (!username) {
        alert("請輸入使用者名稱");
        return;
    }

    try {
        // 取得 state 參數
        const dist          = getURLParam("dist");
        const state         = getURLParam("state");
        const scope         = getURLParam("scope");
        const source        = getURLParam("source");
        // const redirect_uri  = getURLParam("redirect_uri");
        const response_type = getURLParam("response_type");


        // ✅ 第一步：發送使用者名稱，獲取 PublicKeyCredential options
        const options = await sendRequest("/authentication", "POST", { username });
        console.log("後端回應:", options);
        // 偵錯用
        if (options.error) {
            console.error("認證錯誤(後端回應 error):", options.error);
            alert("認證失敗(後端回應 error):" + options.error + "！");
            return;
        }

        // ✅ 第二步：轉換 publicKey 結構（挑戰碼、憑證 ID）
        // 轉換 base64url 字串為 Uint8Array 格式
        options.publicKey.challenge = base64UrlToUint8Array(options.publicKey.challenge);
        options.publicKey.allowCredentials = options.publicKey.allowCredentials.map((cred) => ({
            id: base64UrlToUint8Array(cred.id), // 轉換 base64url 字串為 Uint8Array 格式
            type: cred.type,
        }));

        // ✅ 第三步：透過瀏覽器取得 WebAuthn 憑證
        const credential = await navigator.credentials.get(options);

        // ✅ 第四步：組裝驗證資料並送回後端驗證
        const verify_credential = { 
            username: username, 
            source: source,
            dist: dist,
            credential: convertCredential(credential, navigator.userAgent), 
        };

        // 將驗證器認證結果傳送給後端進行驗證
        const verifyResult = await sendRequest("/authentication/verify-credential?from_oauth=1", "POST", verify_credential);
        console.log("登入驗證結果:", verifyResult);

        if (verifyResult.error) {
            console.error("登入驗證錯誤:", verifyResult.error);
            return;
        }

        // 嘗試從 cookie 取出 token，這裡只是為了確認有沒有驗證成功
        // 確認完這個 token 之後就不需要了
        const normalizedSource = source ? normalizeSource(source) : null;
        const cookieName = normalizedSource ? `${normalizedSource}_token` : "token";
        const token = getCookie(cookieName);
        if (token) {
            
            if (verifyResult.status == "ok"){            
                window.opener.postMessage({
                    status: "login_success",
                    token: token,
                    state: state
                }, "*");
                window.close();  // ✅ 直接關閉視窗

            }
            // 先保留用不到後刪除
            const params = new URLSearchParams({
                source: source,
                dist: dist,
                // redirect_uri: redirect_uri,
                response_type: response_type,
                scope: scope,
                state: state,
                username: username,
            });
    
            alert("登入成功 重導回 /authorize");
            window.location.href = `/oauth2/authorize?${params.toString()}`;
            
        } else {
            alert("找不到登入憑證 Cookie！");
        }


    } catch (error) {
        console.error("認證錯誤:", error);
        alert("認證失敗！");
    }
}

export { 
    oauth_login 
};

function normalizeSource(source) {
    return source.replace(/\W+/g, "_");  // 等效於 Python 的 re.sub(r'\W+', '_', ...)
}