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

function handleRegister(event) {
    event.preventDefault();
    event.stopPropagation();
    const username = getUsernameFromEvent(event);
    if (!username) return alert("請先輸入用戶名稱");

    fetch("/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username }),
    })
        .then(async res => {
            const data = await res.json();
            if (res.ok && data.success) {
                alert("✅ 註冊成功：" + data.message);
            } else {
                alert("❌ 註冊失敗：" + (data.message || "未知錯誤"));
            }
        })
        .catch(err => {
            alert("❌ 註冊請求錯誤：" + err.message);
        });
}

function handleLogin(event) {
    event.preventDefault();
    event.stopPropagation();
    const username = getUsernameFromEvent(event);
    if (!username) return alert("請先輸入用戶名稱");

    fetch("/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username }),
    })
        .then(async res => {
            const data = await res.json();
            if (res.ok && data.status === "OK" && data.token) {
                document.cookie = `pdp_token=${data.token}; path=/; max-age=3600;`;
                alert("✅ 登入成功，頁面將重新載入");
                window.location.reload();
            } else {
                alert("❌ 登入失敗：" + (data.message || "未知錯誤"));
            }
        })
        .catch(err => {
            alert("❌ 登入請求錯誤：" + err.message);
        });
}

function getUsernameFromEvent(event) {
    const card = event.target.closest(".card");
    if (!card) return null;
    const input = card.querySelector("input[type='text']");
    return input ? input.value.trim() : null;
}

window.handleRegister = handleRegister;
window.handleLogin = handleLogin;
window.getUsernameFromEvent = getUsernameFromEvent;
