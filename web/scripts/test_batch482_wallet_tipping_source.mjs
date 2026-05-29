import { readFileSync } from "node:fs";

const wallet = readFileSync(new URL("../src/components/WalletPanel.tsx", import.meta.url), "utf8");
const tip = readFileSync(new URL("../src/components/ContentTipButton.tsx", import.meta.url), "utf8");
const account = readFileSync(new URL("../src/pages/Account.tsx", import.meta.url), "utf8");
const feed = readFileSync(new URL("../src/components/FeedView.tsx", import.meta.url), "utf8");

function assertIncludes(src, needle, label) {
  if (!src.includes(needle)) {
    throw new Error(`${label}: missing ${needle}`);
  }
}

assertIncludes(wallet, "WeCoin balance", "wallet surface");
assertIncludes(wallet, "BALANCE_TRANSFER", "wallet transfer tx");
assertIncludes(wallet, "Genesis economics are locked", "wallet lock copy");
assertIncludes(wallet, "balance_transfer_enabled", "wallet capability gate");
assertIncludes(wallet, "from_account_id", "wallet transfer sender");
assertIncludes(wallet, "to_account_id", "wallet transfer recipient");

assertIncludes(tip, "Tip WCN", "content tip button");
assertIncludes(tip, "BALANCE_TRANSFER", "content tip tx");
assertIncludes(tip, "content_tip", "content tip purpose");
assertIncludes(tip, "Tips are locked until Genesis economics activation", "content tip lock copy");
assertIncludes(tip, "content_id", "content tip content binding");

assertIncludes(account, "WalletPanel", "profile wallet mount");
assertIncludes(feed, "ContentTipButton", "feed tip mount");

console.log("batch482 wallet and tipping source checks passed");
