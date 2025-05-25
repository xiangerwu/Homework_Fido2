// --- 模組初始化區塊 ---
let domReady = false;        // HTML 是否載入完成
let bgReady = false;         // 背景圖片是否載入完成
let bgLoaded = false;       // 背景圖片是否載入完成
let jsonReady = false;       // 卡片資料是否載入完成
//let cardData = [];           // 儲存卡片資料陣列


// 嘗試執行卡片繪製（須三者皆完成）
function tryRender() {
    if (domReady && bgReady && jsonReady&& bgLoaded) {
        renderCards(cardData);
    }
}

// --- 核心函式：渲染卡片區 ---
function renderCards(cards) {
    const hand = document.getElementById("hand");
    const tooltip = document.getElementById("tooltip");
    const radius = 300;          // 控制卡片與中心點距離
    const angleStep = 20;        // 每張卡片的角度間隔

    cards.forEach((card, i) => {
        // 計算卡片角度（中間為 0）
        const angle = -angleStep * (cards.length - 1) / 2 + i * angleStep;

        // 包裹層：定位與管理
        const wrapper = document.createElement("div");
        wrapper.className = "card-wrapper";

        // 超連結容器（包含提示與開新頁）
        const a = document.createElement("a");
        a.href = card.link;
        a.dataset.tooltip = card.tooltip;

        // 卡片主體：加入旋轉與 Y 位移
        const cardDiv = document.createElement("div");
        cardDiv.className = "card";
        cardDiv.style.transform = `rotate(${angle}deg) translateY(-${radius}px)`;
        

        // 卡片圖片
        const img = document.createElement("img");
        img.src = card.src;
        img.alt = `card${i + 1}`;

        // 組合結構
        cardDiv.appendChild(img);
        a.appendChild(cardDiv);
        wrapper.appendChild(a);
        hand.appendChild(wrapper);

        // tooltip 行為設定
        a.addEventListener("mouseenter", () => {
            tooltip.textContent = a.dataset.tooltip;
            tooltip.style.display = "block";
        });
        a.addEventListener("mousemove", e => {
            tooltip.style.left = e.pageX + 15 + "px";
            tooltip.style.top = e.pageY - 30 + "px";
        });
        a.addEventListener("mouseleave", () => {
            tooltip.style.display = "none";
        });
    });
}

// --- DOM 載入監聽 ---
document.addEventListener("DOMContentLoaded", () => {
    domReady = true;
    tryRender();
});

// // --- 背景圖片監聽 ---
const bg = document.querySelector(".background");
if (bg.complete) {
    bgReady = true;
} else {
    bg.onload = () => {
        bgReady = true;
        tryRender();
    };
}

// --- 點擊邏輯：卡片點擊與取消邏輯 ---
document.addEventListener("click", (e) => {
    const isCard = e.target.closest(".card");
    const allCards = document.querySelectorAll(".card");

    if (isCard) {
        e.preventDefault(); // 阻止 a 元素預設跳轉

        const card = isCard;
        const link = card.closest("a").href;

        if (card.classList.contains("selected")) {
            window.open(link, "_blank"); // 第二次點 → 開新分頁
        } else {
            allCards.forEach(c => c.classList.remove("selected"));
            card.classList.add("selected"); // 第一次點 → 選中
        }

        e.stopPropagation(); // 防止冒泡影響整頁點擊事件
    } else {
        allCards.forEach(c => c.classList.remove("selected")); // 點空白區取消所有選中
    }
});

// --- 載入卡片資料 ---
fetch("data/cards.json")
    .then(res => res.json())
    .then(cardGroups => {
        cardData = [];
        if (LOGIN_LEVEL === 0) {
            // 僅顯示等級 0（訪客卡）
            if (cardGroups[0]) {
                cardData.push(...cardGroups[0]);
            }
        } else {
            // 顯示 1 ~ LOGIN_LEVEL 的所有等級卡
            for (let level = 1; level <= LOGIN_LEVEL; level++) {
                if (cardGroups[level]) {
                    cardData.push(...cardGroups[level]);
                }
            }
        }
        jsonReady = true;
        tryRender();
    });

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