import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import { getKeypair, getSession, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { useMutationRefresh } from "../hooks/useMutationRefresh";
import { useSignerSubmissionBusy } from "../hooks/useSignerSubmissionBusy";
import { checkGates, summarizeAccountState } from "../lib/gates";
import { nav } from "../lib/router";
import { refreshMutationSlices } from "../lib/revalidation";
import { actionableTxError, txPendingKey } from "../lib/txAction";
import { useTxQueue } from "../hooks/useTxQueue";
import { useAccount } from "../context/AccountContext";

function prettyErr(e: any): { msg: string; details: any } {
  return actionableTxError(e, "Messages failed to load.");
}

type MessagingMode = "hub" | "compose" | "thread";

type MessageRecord = {
  message_id: string;
  thread_id: string;
  sender: string;
  to: string;
  body: string;
  cid?: string;
  created_at_nonce: number;
  redacted?: boolean;
};

type ThreadRecord = {
  thread_id: string;
  members: string[];
  message_ids: string[];
  last_message_id?: string;
  last_message_at_nonce?: number;
};

type MessagingSurface = {
  threads: ThreadRecord[];
  messagesById: Record<string, MessageRecord>;
};

function asRecord(value: unknown): Record<string, any> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, any>) : {};
}

function asArray<T = any>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : [];
}

function normalizeMessage(raw: any): MessageRecord {
  const rec = asRecord(raw);
  return {
    message_id: String(rec.message_id || rec.id || "").trim(),
    thread_id: String(rec.thread_id || "").trim(),
    sender: String(rec.sender || "").trim(),
    to: String(rec.to || rec.recipient || "").trim(),
    body: String(rec.body || ""),
    cid: String(rec.cid || "").trim() || undefined,
    created_at_nonce: Number(rec.created_at_nonce || 0),
    redacted: !!rec.redacted,
  };
}

function normalizeThread(raw: any): ThreadRecord {
  const rec = asRecord(raw);
  return {
    thread_id: String(rec.thread_id || rec.id || "").trim(),
    members: asArray(rec.members).map((x) => String(x || "").trim()).filter(Boolean).sort(),
    message_ids: asArray(rec.message_ids).map((x) => String(x || "").trim()).filter(Boolean),
    last_message_id: String(rec.last_message_id || "").trim() || undefined,
    last_message_at_nonce: Number(rec.last_message_at_nonce || 0),
  };
}

function messageText(message: MessageRecord): string {
  if (message.redacted) return "This message was removed by the sender.";
  if (message.body.trim()) return message.body.trim();
  if (message.cid) return `Attached message content: ${message.cid}`;
  return "No message text.";
}

function otherMemberAccount(thread: ThreadRecord, account: string): string {
  const others = thread.members.filter((member) => member !== account);
  return others[0] || account || "";
}

function otherMembers(thread: ThreadRecord, account: string): string {
  const others = thread.members.filter((member) => member !== account);
  return others.length ? others.join(", ") : account ? `${account} only` : "Conversation";
}

function threadLastMessage(thread: ThreadRecord, messagesById: Record<string, MessageRecord>): string {
  const lastId = thread.last_message_id || thread.message_ids[thread.message_ids.length - 1] || "";
  const last = lastId ? messagesById[lastId] : null;
  return last ? messageText(last) : "No messages yet.";
}

function defaultThreadId(account: string, recipient: string): string {
  const pair = [normalizeAccount(account), normalizeAccount(recipient)].filter(Boolean).sort();
  return pair.length === 2 ? `dm:${pair[0]}:${pair[1]}` : "";
}

export default function Messaging({ mode = "hub", threadId = "" }: { mode?: MessagingMode; threadId?: string }): JSX.Element {
  const apiBase = useMemo(() => getApiBaseUrl(), []);
  const session = getSession();
  const account = session ? normalizeAccount(session.account) : "";
  const canSign = account ? !!getKeypair(account)?.secretKeyB64 : false;
  const { refresh: refreshAccountContext } = useAccount();
  const signerSubmission = useSignerSubmissionBusy(account);
  const tx = useTxQueue();

  const [acctState, setAcctState] = useState<any | null>(null);
  const [surface, setSurface] = useState<MessagingSurface>({ threads: [], messagesById: {} });
  const [recipient, setRecipient] = useState("");
  const [body, setBody] = useState("");
  const [replyBody, setReplyBody] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<{ msg: string; details: any } | null>(null);
  const [result, setResult] = useState<any | null>(null);

  const gate = checkGates({ loggedIn: !!account, canSign, accountState: acctState, requireTier: 1 });

  async function refreshAccount(): Promise<void> {
    if (!account) {
      setAcctState(null);
      return;
    }
    try {
      const acct: any = await weall.account(account, apiBase);
      setAcctState(acct?.state ?? null);
    } catch {
      setAcctState(null);
    }
  }

  async function loadMessages(): Promise<void> {
    setBusy(true);
    setErr(null);
    try {
      const [snapshot] = await Promise.all([weall.stateSnapshot(apiBase), refreshAccount()]);
      const state = asRecord((snapshot as any)?.state);
      const messaging = asRecord(state.messaging);
      const inboxByAccount = asRecord(messaging.inbox_by_account);
      const inbox = asRecord(inboxByAccount[account]);
      const threadIds = asArray(inbox.threads).map((x) => String(x || "").trim()).filter(Boolean);
      const threadsById = asRecord(messaging.threads_by_id);
      const messagesRaw = asRecord(messaging.messages_by_id);
      const messagesById: Record<string, MessageRecord> = {};

      for (const [id, raw] of Object.entries(messagesRaw).sort((a, b) => a[0].localeCompare(b[0]))) {
        const msg = normalizeMessage(raw);
        if (msg.message_id || id) messagesById[msg.message_id || id] = { ...msg, message_id: msg.message_id || id };
      }

      const threads = threadIds
        .map((id) => normalizeThread(threadsById[id]))
        .filter((thread) => !!thread.thread_id)
        .sort((a, b) => Number(b.last_message_at_nonce || 0) - Number(a.last_message_at_nonce || 0) || a.thread_id.localeCompare(b.thread_id));

      setSurface({ threads, messagesById });
    } catch (e: any) {
      setErr(prettyErr(e));
      setSurface({ threads: [], messagesById: {} });
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    void loadMessages();
  }, [account, apiBase]);

  useMutationRefresh({
    entityTypes: ["account"],
    account,
    onRefresh: async () => {
      await loadMessages();
      await refreshAccountContext();
    },
  });

  const selectedThread = surface.threads.find((thread) => thread.thread_id === threadId) || null;
  const selectedMessages = selectedThread
    ? selectedThread.message_ids.map((id) => surface.messagesById[id]).filter((message): message is MessageRecord => !!message).sort((a, b) => a.created_at_nonce - b.created_at_nonce || a.message_id.localeCompare(b.message_id))
    : [];
  const selectedRecipient = selectedThread ? otherMembers(selectedThread, account) : "";
  const selectedReplyRecipient = selectedThread ? otherMemberAccount(selectedThread, account) : "";
  const accountSummary = acctState ? summarizeAccountState(acctState) : "(state unknown)";

  async function sendMessage(args?: { to?: string; messageBody?: string; thread_id?: string; afterThread?: string }): Promise<void> {
    setErr(null);
    setResult(null);
    const to = normalizeAccount(args?.to || recipient);
    const messageBody = String(args?.messageBody || body || "").trim();
    try {
      if (!gate.ok) throw new Error(gate.reason || "Messages require account verification and a local session.");
      if (!to) throw new Error("Choose who should receive the message.");
      if (!messageBody) throw new Error("Write a message first.");
      if (signerSubmission.busy) throw new Error("Another signed action is still settling for this account.");

      const payload: Record<string, string> = { to, body: messageBody };
      if (args?.thread_id) payload.thread_id = args.thread_id;

      const res = await tx.runTx({
        title: args?.thread_id ? "Send reply" : "Send message",
        pendingKey: txPendingKey(["message", account, to, String(args?.thread_id || "new"), messageBody.slice(0, 24)]),
        pendingMessage: args?.thread_id ? "Sending reply…" : "Sending message…",
        successMessage: args?.thread_id ? "Reply sent." : "Message sent.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (raw: any) => raw?.result?.tx_id || raw?.tx_id,
        task: () => submitSignedTx({
          account,
          tx_type: "DIRECT_MESSAGE_SEND",
          payload,
          base: apiBase,
        }),
      });
      setResult(res);
      setBody("");
      setReplyBody("");
      await refreshMutationSlices(loadMessages, refreshAccountContext);
      const nextThread = args?.afterThread || args?.thread_id || defaultThreadId(account, to);
      if (nextThread) nav(`/messages/${encodeURIComponent(nextThread)}`);
    } catch (e: any) {
      setErr(prettyErr(e));
    }
  }

  function renderHero(): JSX.Element {
    return (
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Messages</div>
              <h1 className="heroTitle heroTitleSm">Direct messages</h1>
              <p className="heroText">
                Pick a chat, read the thread, and respond in one focused conversation. Compose stays on its own page so the inbox feels familiar and uncluttered.
              </p>
            </div>
            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Messaging readiness</div>
              <div className="heroInfoList">
                <span className={`statusPill ${account ? "ok" : ""}`}>{account ? "Session present" : "No session"}</span>
                <span className={`statusPill ${gate.ok ? "ok" : ""}`}>{gate.ok ? "Can send messages" : "Verification needed"}</span>
                <span className="statusPill">{accountSummary}</span>
              </div>
            </div>
          </div>
          <div className="heroActions">
            <button className="btn btnPrimary" onClick={() => nav("/messages/compose")} disabled={!account}>New message</button>
            <button className="btn" onClick={() => void refreshMutationSlices(loadMessages, refreshAccountContext)} disabled={busy || signerSubmission.busy || !account}>
              {busy ? "Refreshing…" : signerSubmission.busy ? "Waiting…" : "Refresh messages"}
            </button>
            <button className="btn" onClick={() => nav("/profile")}>Open profile</button>
          </div>
        </div>
      </section>
    );
  }

  function renderNoSession(): JSX.Element | null {
    if (account) return null;
    return (
      <section className="card">
        <div className="cardBody formStack">
          <div className="emptyPanel">
            <strong>No active session.</strong>
            <span>Restore this device session before sending or reading messages.</span>
            <button className="btn btnPrimary" onClick={() => nav("/login")}>Go to sign in</button>
          </div>
        </div>
      </section>
    );
  }

  function renderConversationList(): JSX.Element {
    return (
      <section className="card messengerInboxCard">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Chats</div>
              <h2 className="cardTitle">Conversations</h2>
              <div className="cardDesc">{surface.threads.length} chat{surface.threads.length === 1 ? "" : "s"} visible to this account.</div>
            </div>
            <button className="btn btnPrimary" onClick={() => nav("/messages/compose")} disabled={!account}>New message</button>
          </div>
          {surface.threads.length === 0 ? (
            <div className="emptyPanel">
              <strong>No conversations yet.</strong>
              <span>Start a message from the compose page. For the local demo, you can message your own test account.</span>
            </div>
          ) : (
            <div className="messengerChatList">
              {surface.threads.map((thread) => (
                <button
                  key={thread.thread_id}
                  className="messengerChatButton"
                  onClick={() => nav(`/messages/${encodeURIComponent(thread.thread_id)}`)}
                  type="button"
                >
                  <span className="messengerAvatar" aria-hidden="true">{otherMembers(thread, account).slice(0, 1).replace("@", "").toUpperCase() || "M"}</span>
                  <span className="messengerChatText">
                    <span className="messengerChatTitle">{otherMembers(thread, account)}</span>
                    <span className="messengerChatPreview">{threadLastMessage(thread, surface.messagesById)}</span>
                  </span>
                  <span className="messengerChatChevron">›</span>
                </button>
              ))}
            </div>
          )}
        </div>
      </section>
    );
  }

  function renderCompose(): JSX.Element {
    return (
      <section className="card messengerComposeCard">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">New message</div>
              <h2 className="cardTitle">Compose message</h2>
              <div className="cardDesc">Choose one person and send a direct message. The backend remains authoritative for every send.</div>
            </div>
            <button className="btn" onClick={() => nav("/messages")}>Back to chats</button>
          </div>
          <div className="grid2">
            <label className="fieldLabel">
              Recipient
              <input value={recipient} onChange={(e) => setRecipient(e.target.value)} placeholder="@example" />
            </label>
            <label className="fieldLabel">
              Your account
              <input value={account || "No active session"} readOnly />
            </label>
          </div>
          <label className="fieldLabel">
            Message
            <textarea value={body} onChange={(e) => setBody(e.target.value)} placeholder="Write a message…" rows={5} />
          </label>
          {!gate.ok ? <div className="calloutInfo">{gate.reason || "Complete account verification before sending messages."}</div> : null}
          <div className="buttonRow">
            <button className="btn btnPrimary" onClick={() => void sendMessage()} disabled={!gate.ok || !recipient.trim() || !body.trim() || signerSubmission.busy}>
              {signerSubmission.busy ? "Waiting…" : "Send message"}
            </button>
            {account ? <button className="btn" onClick={() => setRecipient(account)}>Message myself for demo</button> : null}
          </div>
          {result ? <pre className="codePanel mono">{JSON.stringify(result, null, 2)}</pre> : null}
        </div>
      </section>
    );
  }

  function renderThread(): JSX.Element {
    if (!selectedThread) {
      return (
        <section className="card">
          <div className="cardBody formStack">
            <div className="emptyPanel">
              <strong>Conversation not found.</strong>
              <span>Refresh messages or return to your chat list.</span>
              <div className="buttonRow"><button className="btn" onClick={() => nav("/messages")}>Back to chats</button></div>
            </div>
          </div>
        </section>
      );
    }

    return (
      <section className="card messengerThreadCard">
        <div className="cardBody formStack">
          <div className="messengerThreadHeader">
            <button className="btn" onClick={() => nav("/messages")}>Back to chats</button>
            <div>
              <div className="eyebrow">Conversation</div>
              <h2 className="cardTitle">{selectedRecipient}</h2>
            </div>
            <span className="statusPill">{selectedMessages.length} message{selectedMessages.length === 1 ? "" : "s"}</span>
          </div>

          <div className="messengerMessages" aria-label="Message thread">
            {selectedMessages.map((message) => (
              <div key={message.message_id} className={`messageBubbleRow ${message.sender === account ? "mine" : "theirs"}`}>
                <div className="messageBubble">
                  <div className="messageBubbleSender">{message.sender === account ? "You" : message.sender}</div>
                  <div>{messageText(message)}</div>
                  <div className="messageBubbleMeta mono">{message.message_id}</div>
                </div>
              </div>
            ))}
          </div>

          <div className="messengerReplyBox">
            <label className="fieldLabel">
              Reply
              <textarea value={replyBody} onChange={(e) => setReplyBody(e.target.value)} placeholder={`Message ${selectedRecipient}…`} rows={3} />
            </label>
            {!gate.ok ? <div className="calloutInfo">{gate.reason || "Complete account verification before replying."}</div> : null}
            <div className="buttonRow">
              <button
                className="btn btnPrimary"
                onClick={() => void sendMessage({ to: selectedReplyRecipient, messageBody: replyBody, thread_id: selectedThread.thread_id, afterThread: selectedThread.thread_id })}
                disabled={!gate.ok || !replyBody.trim() || signerSubmission.busy}
              >
                {signerSubmission.busy ? "Waiting…" : "Send reply"}
              </button>
            </div>
          </div>
        </div>
      </section>
    );
  }

  return (
    <div className="pageStack messengerPage">
      {renderHero()}

      <ErrorBanner message={err?.msg} details={err?.details} onDismiss={() => setErr(null)} onRetry={() => void refreshMutationSlices(loadMessages, refreshAccountContext)} />
      {renderNoSession()}

      {mode === "compose" ? renderCompose() : null}
      {mode === "thread" ? renderThread() : null}
      {mode === "hub" ? renderConversationList() : null}
    </div>
  );
}
