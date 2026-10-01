// =========================
// ADD TO CHROME
// =========================
function installExtension() {
    alert(
        "PHISHSHIELD Chrome Extension\n\n" +
        "The extension installation page will open here."
    );
}

// =========================
// HOW IT WORKS POPUP
// =========================
function showInfo() {
    const info = document.getElementById("info");
    if (info) {
        info.style.display = "block";
    }
}

// =========================
// CLOSE INFO POPUP
// =========================
function closeInfo() {
    const info = document.getElementById("info");
    if (info) {
        info.style.display = "none";
    }
}

// =========================
// BLOCK WEBSITE BUTTON
// =========================
function blockWebsite() {
    alert(
        "PHISHSHIELD has blocked this suspicious website."
    );
}