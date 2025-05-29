// --- 模組初始化區塊 ---
let domReady = false;
let bgReady = false;
let bgLoaded = false;
let jsonReady = false;
let cardData = [];

function tryRender() {
    if (domReady && bgReady && jsonReady && bgLoaded) {
        renderCards(cardData);
    }
}

function renderCards(cards) {
    const hand = document.getElementById("hand");
    const tooltip = document.getElementById("tooltip");
    const radius = 300;
    const angleStep = 20;

    cards.forEach((card, i) => {
        const angle = -angleStep * (cards.length - 1) / 2 + i * angleStep;

        const wrapper = document.createElement("div");
        wrapper.className = "card-wrapper";

        const cardDiv = document.createElement("div");
        cardDiv.className = "card";
        cardDiv.dataset.flip = card.flip ? "true" : "false";
        cardDiv.style.transform = `rotate(${angle}deg) translateY(-${radius}px) scale(${card.scale || 1})`;

        const cardInner = document.createElement("div");
        cardInner.className = "card-inner";

        const frontDiv = document.createElement("div");
        frontDiv.className = "card-front";

        const a = document.createElement("a");
        a.href = card.link;
        a.dataset.tooltip = card.tooltip;

        const img = document.createElement("img");
        img.src = card.src;
        img.alt = `card${i + 1}`;

        a.appendChild(img);
        frontDiv.appendChild(a);

        const backDiv = createCardBack(i);
        backDiv.classList.add("card-back");

        cardInner.appendChild(frontDiv);
        if (card.flip) cardInner.appendChild(backDiv);

        cardDiv.appendChild(cardInner);
        wrapper.appendChild(cardDiv);
        hand.appendChild(wrapper);

        setTooltipEvents(a, tooltip);

        cardDiv.addEventListener("click", (e) => {
            const target = e.target;
            if (target.tagName === "INPUT" || target.tagName === "BUTTON") return;
            e.preventDefault();
            e.stopPropagation();

            const allCards = document.querySelectorAll(".card");
            const allBackContents = document.querySelectorAll(".card-back-content");

            if (cardDiv.classList.contains("selected")) {
                if (cardDiv.dataset.flip === "true") {
                    const inner = cardDiv.querySelector(".card-inner");
                    if (inner) inner.classList.toggle("flip");
                    const content = cardDiv.querySelector(".card-back-content");
                    if (content) content.style.display = "flex";
                } else {
                    const link = cardDiv.querySelector("a");
                    if (link && link.href) {
                        window.open(link.href, "_blank");
                    }
                }
            } else {
                allCards.forEach(c => {
                    c.classList.remove("selected");
                    const innerC = c.querySelector(".card-inner");
                    if (innerC) innerC.classList.remove("flip");
                });
                allBackContents.forEach(c => c.style.display = "none");

                cardDiv.classList.add("selected");
            }
        });
    });
}

function createCardBack(i) {
    const backDiv = document.createElement("div");
    backDiv.className = "card-back";

    const backContent = document.createElement("div");
    backContent.className = "card-back-content";

    const input = document.createElement("input");
    input.type = "text";
    input.placeholder = "輸入用戶名稱";
    input.id = `username_${i}`;

    const buttonsDiv = document.createElement("div");
    buttonsDiv.className = "buttons";
    buttonsDiv.appendChild(createButton(null, "註冊", "register-btn", "handleRegister"));
    buttonsDiv.appendChild(createButton(null, "登入", "login-btn", "handleLogin"));

    backContent.appendChild(input);
    backContent.appendChild(buttonsDiv);
    backDiv.appendChild(backContent);

    return backDiv;
}

function createButton(href, text, className, onClickFnName = null) {
    const btn = document.createElement("button");
    btn.textContent = text;
    btn.className = `button ${className}`;

    btn.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();

        if (onClickFnName && typeof window[onClickFnName] === 'function') {
            window[onClickFnName](e);
        } else if (href) {
            window.location.href = href;
        }
    });

    return btn;
}

function setTooltipEvents(element, tooltip) {
    element.addEventListener("mouseenter", () => {
        tooltip.textContent = element.dataset.tooltip;
        tooltip.style.display = "block";
    });
    element.addEventListener("mousemove", e => {
        tooltip.style.left = `${e.pageX + 15}px`;
        tooltip.style.top = `${e.pageY - 30}px`;
    });
    element.addEventListener("mouseleave", () => {
        tooltip.style.display = "none";
    });
}

document.addEventListener("DOMContentLoaded", () => {
    domReady = true;
    tryRender();
});

document.addEventListener("click", (e) => {
    const isCard = e.target.closest(".card");
    const isBackContent = e.target.closest(".card-back-content");
    const allCards = document.querySelectorAll(".card");
    const allBackContents = document.querySelectorAll(".card-back-content");

    if (!isCard && !isBackContent) {
        allCards.forEach(c => {
            c.classList.remove("selected");
            const innerC = c.querySelector(".card-inner");
            if (innerC) innerC.classList.remove("flip");
        });
        allBackContents.forEach(c => c.style.display = "none");
    }
});

const bg = document.querySelector(".background");
if (bg.complete) {
    bgReady = true;
} else {
    bg.onload = () => {
        bgReady = true;
        tryRender();
    };
}

const mainBg = document.querySelector('.main-bg');
if (mainBg.complete) {
    mainBg.style.opacity = 1;
    bgLoaded = true;
    tryRender();
} else {
    mainBg.onload = () => {
        mainBg.style.opacity = 1;
        bgLoaded = true;
        tryRender();
    };
}

if (!sessionStorage.getItem("reloaded")) {
    sessionStorage.setItem("reloaded", "yes");
    window.location.reload();
}

fetch("static/data/cards.json")
    .then(res => res.json())
    .then(cardGroups => {
        if (LOGIN_LEVEL === 0) {
            if (cardGroups[0]) {
                cardData.push(...cardGroups[0]);
            }
        } else {
            for (let level = 1; level <= LOGIN_LEVEL; level++) {
                if (cardGroups[level]) {
                    cardData.push(...cardGroups[level]);
                }
            }
        }
        jsonReady = true;
        tryRender();
    });

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
            body: data ? JSON.stringify(data) : null,
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

async function handleRegister(event) {
    event.preventDefault();
    event.stopPropagation();
    const username = getUsernameFromEvent(event);
    // 取得使用者名稱
    if (!username) return alert("請先輸入用戶名稱");
    // 執行 WebAuthn 註冊流程
    console.log("開始註冊流程");
    try {
        // 向後端請求 WebAuthn 註冊選項
        const options = await sendRequest("/register-begin", "POST", { username });
        //
        // 判斷 options 是否 error
        if (options.error) {
            console.error("註冊錯誤:", options.error);
            alert("註冊失敗:" + options.error + "！");
            return;
        }
        // 後端正確回應後，將 options 轉換為 WebAuthn API 可用的格式
        options.publicKey.challenge = base64UrlToUint8Array(options.publicKey.challenge);
        options.publicKey.user.id = base64UrlToUint8Array(options.publicKey.user.id);
        // credential 是 瀏覽器 API 運算後的憑證資訊
        const credential = await navigator.credentials.create({ publicKey: options.publicKey })
        // 顯示憑證資訊在網頁上
        console.log("將憑證資料傳送到後端");
        let store_credential = { 
            username: username, 
            credential: convertCredential(credential, navigator.userAgent) 
        };
        // 將憑證資料組合起來傳送到後端 
        console.log("store_credential:", store_credential);
        const result = await sendRequest("/register-end", "POST", store_credential);

        // 解析回傳資料是否有錯誤，有錯誤則顯示錯誤訊息
        if (result.error) {
            console.error("後端回覆資料錯誤:", result.error);
            alert("後端回覆資料錯誤，請看主控台");
            return;
        }

        console.log("註冊成功！請查看憑證資訊，接下來嘗試登入看看。");
        alert("註冊成功！請查看憑證資訊，接下來嘗試登入看看。");
    } catch (error) {
        // 網路錯誤處理
        if (NetworkError(error)) {
            location.reload();
            return;
        }
        console.error("註冊過程失敗:", error);
        alert("註冊過程失敗，請看主控台");
        }
}

async function handleLogin(event) {
    event.preventDefault();
    event.stopPropagation();
    const username = getUsernameFromEvent(event);
    if (!username) return alert("請先輸入用戶名稱");
    try {
        // 第一步: 向後端確認使用者存在
        // 傳送使用者名稱到後端
        const options = await sendRequest("/login-begin", "POST", { username });
        // 取得回應後顯示在主控台
        console.log("後端回應:", options);

        if (options.error) {
            console.error("認證錯誤(後端回應 error):", options.error);
            alert("認證失敗(後端回應 error):" + options.error + "！");
            return;
        }
        // 如果後端回應沒有錯誤，則繼續執行下一步
        // 第二步: 從瀏覽器取得憑證
        console.log("2.後端回傳使用者資料再從瀏覽器取得憑證");
        // 轉換 base64url 字串為 Uint8Array 格式
        options.publicKey.challenge = base64UrlToUint8Array(options.publicKey.challenge);
        options.publicKey.allowCredentials = options.publicKey.allowCredentials.map((cred) => ({
            id: base64UrlToUint8Array(cred.id), // 轉換 base64url 字串為 Uint8Array 格式
            type: cred.type,
        }));
        // 呼叫瀏覽器 API 認證憑證
        const credential = await navigator.credentials.get(options);
        console.log("瀏覽器已認證憑證:", credential);
        // 第三步: 將憑證傳給後端完成登入
        console.log("3.將憑證傳給後端完成登入");
        let verify_credential = { 
            username: username, 
            credential: convertCredential(credential, navigator.userAgent),
         };
        // 將認證結果傳送給後端進行驗證
        const verifyResult = await sendRequest("/login-end", "POST", verify_credential);

        // 顯示驗證結果
        console.log("登入驗證結果:", verifyResult);

        if (verifyResult.error) {
            console.error("登入驗證錯誤:", verifyResult.error);
            alert("登入驗證失敗:" + verifyResult.error + "！");
            return;
        }

        alert("成功登入！");        
        location.reload();

    } catch (error) {
        // 網路錯誤處理
        if (NetworkError(error)) {
            location.reload();
            return;
        }
        console.error("認證錯誤:", error);
        alert("認證失敗！");
        }
}

function getUsernameFromEvent(event) {
    const card = event.target.closest(".card");
    if (!card) return null;
    const input = card.querySelector("input[type='text']");
    return input ? input.value.trim() : null;
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

// 如果是 ios-safari 將憑證轉換為 JSON 格式 否則直接使用
function convertCredential(credential, useragent) {
    let check_ios = /iP(ad|hone|od).+Version\/[\d.]+.*Safari/i.test(navigator.userAgent);
    let credential_JSON = null;
    if (check_ios === true) { credential_JSON = credentialToJSON(credential); }
    else { credential_JSON = credential; }
    return credential_JSON;
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


window.sendRequest = sendRequest;
window.handleRegister = handleRegister;
window.handleLogin = handleLogin;
window.getUsernameFromEvent = getUsernameFromEvent;
window.base64UrlToUint8Array = base64UrlToUint8Array;
window.convertCredential = convertCredential;
window.NetworkError = NetworkError;