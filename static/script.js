//
// srcipt.js 是前端的 JavaScript 檔案，用來處理前端的 WebAuthn 註冊和登入功能
// 這個檔案會引入 web_functions.js 檔案，裡面有一些轉換資料的函式
//

// 引入 web_functions.js 檔案，將常用的放進去減少程式碼重複
import {
    base64UrlToUint8Array,
    uint8ArrayToBase64Url,
    arrayBufferToBase64,
    showMessage,
    appendMessage,
    NetworkError,

} from "./web_functions.js";

// 將函式註冊到 window 物件上
window.register = register;
window.verify_register = verify_register;
window.clearData = clearData;
window.toggleCollapse = toggleCollapse;

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
        // credentials: 'include',
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
    });
    return response.json();
}

// WebAuthn 註冊 register 函式
// 作用: 向後端發送註冊請求，取得註冊選項，再將憑證資訊傳送到後端
async function register() {
    // 取得使用者名稱
    const username = document.getElementById("username").value;
    if (!username) {
        alert("請輸入使用者名稱");
        return;
    }

    // 執行 WebAuthn 註冊流程
    console.log("開始註冊流程");
    try {
        // 向後端請求 WebAuthn 註冊選項
        const options = await sendRequest("/register", "POST", { username });
        //
        // 判斷 options 是否 error
        if (options.error) {
            console.error("註冊錯誤:", options.error);
            alert("註冊失敗:" + options.error + "！");
            return;
        }
        // 後端正確回應後，將 options 轉換為 WebAuthn API 可用的格式
        // 顯示挑戰碼在網頁上
        showMessage("Register_Challenge", options.publicKey.challenge);
        // 原本的 challenge 和 user.id 都是 base64url 字串需要轉換為 Uint8Array 格式
        options.publicKey.challenge = base64UrlToUint8Array(options.publicKey.challenge);
        options.publicKey.user.id = base64UrlToUint8Array(options.publicKey.user.id);
        /* 
        debug 用，沒有問題就 mark 掉減少 console.log 訊息
        console.log("Challenge Type:", options.publicKey.challenge.constructor.name);
        console.log("User ID Type:", options.publicKey.user.id.constructor.name);
        */

        // 之後將憑證資訊儲存到瀏覽器的 API 中，同時捕捉成功與失敗的訊息
        // credential 是 瀏覽器 API 運算後的憑證資訊
        const credential = await navigator.credentials.create({ publicKey: options.publicKey })
        // 顯示憑證資訊在網頁上
        showMessage(
            "Register_credentialInfo",
            `User: ${username}\n註冊驗證器金要得到的credential\n${JSON.stringify(credential, null, 4)}`
        );

        // 將憑證資料組合起來傳送到後端 /register/store-credential
        // 組合憑證資料 (username, credential)
        console.log("將憑證資料傳送到後端");
        var store_credential = { username: username, credential: credential, };
        console.log("store_credential:", store_credential);
        const result = await sendRequest("/register/store-credential", "POST", store_credential);

        // 解析回傳資料是否有錯誤，有錯誤則顯示錯誤訊息
        if (result.error) {
            console.error("後端回覆資料錯誤:", result.error);
            alert("後端回覆資料錯誤，請看主控台");
            return;
        }

        console.log("註冊成功！請查看憑證資訊，接下來嘗試登入看看。");
        alert("註冊成功！請查看憑證資訊，接下來嘗試登入看看。");
        appendMessage(
            "Register_credentialInfo",
            "\n登入計數：" + result.signCount + " 次"
        );
        updateUserList();


    } catch (error) {
        // 網路錯誤處理
        if (NetworkError(error)) {
            location.reload();
            return;
        }
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

        // 第一步: 向後端確認使用者存在
        // 傳送使用者名稱到後端
        const options = await sendRequest("/auth", "POST", { username });

        // 取得回應後顯示在主控台
        console.log("後端回應:", options);

        showMessage("Verify_Challenge", options)
        if (options.error) {
            console.error("認證錯誤(後端回應 error):", options.error);
            alert("認證失敗(後端回應 error):" + options.error + "！");
            return;
        }
        // 如果後端回應沒有錯誤，則繼續執行下一步


        // 第二步: 從瀏覽器取得憑證
        console.log("2.後端回傳使用者資料再從瀏覽器取得憑證");
        // 顯示挑戰碼在網頁上
        showMessage("Verify_Challenge", options.publicKey.challenge);
        // 轉換 base64url 字串為 Uint8Array 格式
        options.publicKey.challenge = base64UrlToUint8Array(options.publicKey.challenge);
        options.publicKey.allowCredentials = options.publicKey.allowCredentials.map((cred) => ({
            id: base64UrlToUint8Array(cred.id), // 轉換 base64url 字串為 Uint8Array 格式
            type: cred.type,
        }));
        // 呼叫瀏覽器 API 認證憑證
        // console.log("options:", options);
        const credential = await navigator.credentials.get(options);
        console.log("瀏覽器已認證憑證:", credential);
        // 顯示憑證資訊在網頁上
        showMessage("verify-register_credentialInfo", `User: ${username}\n後端確認有此使用者並且經過瀏覽器 API 認證的資料\n${JSON.stringify(credential, null, 2)}`);

        // 第三步: 將憑證傳給後端完成登入
        console.log("3.將憑證傳給後端完成登入");
        var verify_credential = { username: username, credential: credential };
        // 將認證結果傳送給後端進行驗證
        const verifyResult = await sendRequest("/auth/verify-credential", "POST", verify_credential);

        // 顯示驗證結果
        console.log("登入驗證結果:", verifyResult);

        if (verifyResult.error) {
            console.error("登入驗證錯誤:", verifyResult.error);
            alert("登入驗證失敗:" + verifyResult.error + "！");
            return;
        }

        alert("認證成功！");
        // 顯示驗證器登入計數
        appendMessage(
            "verify-register_credentialInfo",
            "\n登入計數：" + verifyResult.signCount + " 次"
        );
        // 顯示登入紀錄  
        const user_log = await sendRequest("/auth/user-log", "POST", { username });
        console.log("user_log:", user_log);
        showLoginHistory(username,user_log);

    } catch (error) {
        // 網路錯誤處理
        if (NetworkError(error)) {
            location.reload();
            return;
        }
        console.error("認證錯誤:", error);
        alert("認證失敗！");
    }
} // end of verify_register()

// 清除憑證資訊
async function clearData() {
    // 確認是否要清除憑證資訊
    if (confirm("確定要清除全部憑證資訊嗎？此操作無法還原！")) {

        // 清除網頁上的訊息
        showMessage("Register_credentialInfo", "");
        showMessage("verify-register_credentialInfo", "");
        // 清除後端的憑證資訊
        try {
            const result = await sendRequest("/clear", "POST", "No Data");
            console.log("清除結果:", result);

            await navigator.credentials.preventSilentAccess();
            console.log("前端瀏覽器中的憑證已清除");
            alert("憑證資訊已清除！");
            updateUserList();
        } catch (error) {
            // 網路錯誤處理
            if (NetworkError(error)) { location.reload(); return; }
            console.error("清除錯誤:", error);
            alert("清除失敗！");
        }

    }
} // end of clear()

// export 函式
export {
    register,
    verify_register,
    clearData,
}





// 頁面載入時獲取使用者名單
document.addEventListener("DOMContentLoaded", updateUserList);


// 從後端獲取使用者列表並更新表格
async function updateUserList() {
    const userList = document.getElementById("userList");
    userList.innerHTML = ""; // 清空列表

    try {
        // 發送 GET 請求到後端 API
        const response = await fetch("https://fido2.akitawan.moe");


        // 確保回應成功
        if (!response.ok) {
            throw new Error(`HTTP 錯誤！狀態碼: ${response.status}`);
        }

        // 解析 JSON 資料
        const users = await response.json();

        // 迭代用戶數據，填充表格
        users.forEach(user => {
            let row = `
                <tr>
                    <td>${user.id}</td>
                    <td>${user.username}</td>
                    <td>${user.registeredAt}</td>
                </tr>
            `;
            userList.innerHTML += row;
        });
    } catch (error) {
        console.error("獲取使用者列表時發生錯誤:", error);
        userList.innerHTML = `<tr><td colspan="3" class="text-center text-danger">無法載入使用者資料</td></tr>`;
    }
}


// 顯示登入紀錄
async function showLoginHistory(username, userdata) {
    const loginHistorySection = document.getElementById("loginHistorySection");
    const loginHistoryTitle = document.getElementById("loginHistoryTitle");
    const loginHistory = document.getElementById("loginHistory");

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
                        <td>${log.authenticator}</td>
                        <td>${log.ip}</td>
                        <td>${log.os}</td>
                        <td>${log.device}</td>
                        <td>${log.browser}</td>
                        <td>${log.loginTime}</td>
                        <td>${log.success ? "❌" : "✅"}</td>
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
