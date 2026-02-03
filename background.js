// background.js - manage badge state updates

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    // Update the badge when the content script signals an alert.
    if (request.action === "update_badge" && sender.tab) {
        chrome.action.setBadgeBackgroundColor({
            tabId: sender.tab.id,
            color: "#FF0000"
        });
        chrome.action.setBadgeText({
            tabId: sender.tab.id,
            text: "!"
        });
    }
});
