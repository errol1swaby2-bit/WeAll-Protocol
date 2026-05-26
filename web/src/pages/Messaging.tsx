import React, { useEffect, useMemo, useRef, useState } from "react";

import { getApiBaseUrl, weall } from "../api/weall";
import ErrorBanner from "../components/ErrorBanner";
import { getAuthHeaders, getKeypair, getSession, submitSignedTx } from "../auth/session";
import { normalizeAccount } from "../auth/keys";
import { useMutationRefresh } from "../hooks/useMutationRefresh";
import { useSignerSubmissionBusy } from "../hooks/useSignerSubmissionBusy";
import { checkGates, summarizeAccountState } from "../lib/gates";
import { nav } from "../lib/router";
import { WEALL_API_BASE_CHANGED_EVENT } from "../lib/nodeConnectionManager";
import {
  accountMessagingKeyId,
  accountMessagingPublicJwk,
  decryptDirectMessage,
  encryptDirectMessage,
  ensureMessagingEncryptionIdentity,
} from "../lib/messageCrypto";
import { refreshMutationSlices } from "../lib/revalidation";
import { actionableTxError, txPendingKey } from "../lib/txAction";
import { useTxQueue } from "../hooks/useTxQueue";
import { useAccount } from "../context/AccountContext";

function prettyErr(e: any): { msg: string; details: any } {
  return actionableTxError(e, "Messages failed to load.");
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => window.setTimeout(resolve, ms));
}

type MessagingMode = "hub" | "compose" | "thread";

type MessageRecord = {
  message_id: string;
  thread_id: string;
  sender: string;
  to: string;
  body: string;
  cid?: string;
  encrypted?: boolean;
  encryption?: Record<string, any>;
  created_at_nonce: number;
  redacted?: boolean;
};

type ThreadRecord = {
  thread_id: string;
  members: string[];
  message_ids: string[];
  last_message_id?: string;
  last_message_at_nonce?: number;
  last_message?: MessageRecord;
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
    encrypted: !!rec.encrypted,
    encryption: rec.encryption && typeof rec.encryption === "object" ? rec.encryption : undefined,
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
    last_message: rec.last_message && typeof rec.last_message === "object" ? normalizeMessage(rec.last_message) : undefined,
  };
}

function messageText(message: MessageRecord, decryptedBodies?: Record<string, string>): string {
  if (message.redacted) return "This message was removed by the sender.";
  const decrypted = decryptedBodies?.[message.message_id];
  if (decrypted) return decrypted;
  if (message.encrypted) return "Encrypted message — decrypting on this device…";
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
  return last ? messageText(last) : thread.last_message ? messageText(thread.last_message) : "No messages yet.";
}

function defaultThreadId(account: string, recipient: string): string {
  const pair = [normalizeAccount(account), normalizeAccount(recipient)].filter(Boolean).sort();
  return pair.length === 2 ? `dm:${pair[0]}:${pair[1]}` : "";
}

export default function Messaging({ mode = "hub", threadId = "" }: { mode?: MessagingMode; threadId?: string }): JSX.Element {
  const [apiBase, setApiBaseState] = useState<string>(() => getApiBaseUrl());
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
  const [lastMessageRefreshMs, setLastMessageRefreshMs] = useState<number>(0);
  const [decryptedBodies, setDecryptedBodies] = useState<Record<string, string>>({});
  const [encryptionBusy, setEncryptionBusy] = useState<boolean>(false);
  const loadingMessagesRef = useRef<boolean>(false);

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

  async function loadMessages(opts?: { silent?: boolean }): Promise<void> {
    if (loadingMessagesRef.current) return;
    loadingMessagesRef.current = true;
    const silent = opts?.silent === true;
    if (!silent) {
      setBusy(true);
      setErr(null);
    }
    try {
      await refreshAccount();
      if (!account) {
        setSurface({ threads: [], messagesById: {} });
        return;
      }
      const headers = getAuthHeaders(account);
      if (!headers["x-weall-account"] || !headers["x-weall-session-key"]) {
        throw new Error("Restore this device session before reading messages.");
      }

      const threadsRes: any = await weall.messageThreads({ limit: 50 }, apiBase, headers);
      const messagesById: Record<string, MessageRecord> = {};
      const threads = asArray(threadsRes?.threads)
        .map((raw) => normalizeThread(raw))
        .filter((thread) => !!thread.thread_id)
        .sort((a, b) => Number(b.last_message_at_nonce || 0) - Number(a.last_message_at_nonce || 0) || a.thread_id.localeCompare(b.thread_id));

      for (const thread of threads) {
        if (thread.last_message?.message_id) {
          messagesById[thread.last_message.message_id] = thread.last_message;
        }
      }

      if (threadId) {
        const detail: any = await weall.messageThread(threadId, { limit: 100 }, apiBase, headers);
        const detailedThread = normalizeThread(detail?.thread);
        const detailedMessages = asArray(detail?.messages).map((raw) => normalizeMessage(raw)).filter((msg) => !!msg.message_id);
        for (const msg of detailedMessages) messagesById[msg.message_id] = msg;
        if (detailedThread.thread_id) {
          detailedThread.message_ids = detailedMessages.map((msg) => msg.message_id);
          const idx = threads.findIndex((t) => t.thread_id === detailedThread.thread_id);
          if (idx >= 0) threads[idx] = { ...threads[idx], ...detailedThread };
          else threads.push(detailedThread);
        }
      }

      setSurface({ threads, messagesById });
      setLastMessageRefreshMs(Date.now());
    } catch (e: any) {
      if (!silent) {
        setErr(prettyErr(e));
        setSurface({ threads: [], messagesById: {} });
      }
    } finally {
      loadingMessagesRef.current = false;
      if (!silent) setBusy(false);
    }
  }

  useEffect(() => {
    const onBaseChanged = () => setApiBaseState(getApiBaseUrl());
    window.addEventListener(WEALL_API_BASE_CHANGED_EVENT, onBaseChanged as EventListener);
    window.addEventListener("storage", onBaseChanged);
    return () => {
      window.removeEventListener(WEALL_API_BASE_CHANGED_EVENT, onBaseChanged as EventListener);
      window.removeEventListener("storage", onBaseChanged);
    };
  }, []);

  useEffect(() => {
    void loadMessages();
  }, [account, apiBase, threadId]);

  useEffect(() => {
    if (!account) return undefined;
    const intervalMs = mode === "thread" ? 2500 : 5000;
    const id = window.setInterval(() => {
      void loadMessages({ silent: true });
    }, intervalMs);
    return () => window.clearInterval(id);
  }, [account, apiBase, threadId, mode]);

  useMutationRefresh({
    entityTypes: ["account", "message"],
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

  useEffect(() => {
    let cancelled = false;
    async function decryptSelected(): Promise<void> {
      if (!account || selectedMessages.length === 0) {
        setDecryptedBodies({});
        return;
      }
      const next: Record<string, string> = {};
      for (const message of selectedMessages) {
        if (!message.encrypted || !message.encryption || message.redacted) continue;
        try {
          next[message.message_id] = await decryptDirectMessage({
            viewer: account,
            sender: message.sender,
            recipient: message.to,
            encryption: message.encryption,
          });
        } catch {
          next[message.message_id] = "Encrypted message — this device does not have the matching messaging key.";
        }
      }
      if (!cancelled) setDecryptedBodies(next);
    }
    void decryptSelected();
    return () => {
      cancelled = true;
    };
  }, [account, selectedMessages.map((m) => m.message_id).join("|"), selectedMessages.length]);
  const accountSummary = acctState ? summarizeAccountState(acctState) : "(state unknown)";
  const localMessagingPublicJwk = acctState ? accountMessagingPublicJwk(acctState) : null;
  const localMessagingKeyId = acctState ? accountMessagingKeyId(acctState) : "";
  const messagingEncryptionReady = !!localMessagingPublicJwk && !!localMessagingKeyId;

  async function publishMessagingEncryptionKey(): Promise<void> {
    if (!account) {
      setErr({ msg: "Sign in before enabling encrypted messages.", details: null });
      return;
    }
    if (!gate.ok) {
      setErr({ msg: gate.reason || "Messages require account verification before enabling encryption.", details: null });
      return;
    }
    setEncryptionBusy(true);
    setErr(null);
    try {
      const identity = await ensureMessagingEncryptionIdentity(account);
      const currentPolicy = asRecord(acctState?.security_policy);
      const policy = {
        ...currentPolicy,
        messaging_encryption_public_jwk: identity.publicJwk,
        messaging_encryption_key_id: identity.keyId,
        messaging_encryption_scheme: "WEALL_E2EE_V1",
      };
      await tx.runTx({
        title: "Enable encrypted messages",
        pendingKey: txPendingKey(["message-encryption", account, identity.keyId]),
        pendingMessage: "Publishing your messaging encryption public key…",
        successMessage: "Encrypted messaging key published.",
        errorMessage: (e) => prettyErr(e).msg,
        getTxId: (raw: any) => raw?.result?.tx_id || raw?.tx_id,
        task: () => submitSignedTx({
          account,
          tx_type: "ACCOUNT_SECURITY_POLICY_SET",
          payload: {
            policy,
            messaging_encryption_public_jwk: identity.publicJwk,
            messaging_encryption_key_id: identity.keyId,
          },
          base: apiBase,
        }),
      });
      await refreshMutationSlices(loadMessages, refreshAccountContext);
    } catch (e: any) {
      setErr(prettyErr(e));
    } finally {
      setEncryptionBusy(false);
    }
  }

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

      if (!messagingEncryptionReady) {
        throw new Error("Enable encrypted messages for your account before sending.");
      }
      const recipientAccount: any = await weall.account(to, apiBase);
      const recipientPublicJwk = accountMessagingPublicJwk(recipientAccount?.state);
      const recipientKeyId = accountMessagingKeyId(recipientAccount?.state);
      if (!recipientPublicJwk) {
        throw new Error("This recipient has not published a messaging encryption key yet.");
      }
      const payload = await encryptDirectMessage({
        sender: account,
        recipient: to,
        plaintext: messageBody,
        recipientPublicJwk,
        recipientKeyId,
        threadId: args?.thread_id,
      });

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
      const nextThread = args?.afterThread || args?.thread_id || defaultThreadId(account, to);
      await refreshMutationSlices(loadMessages, refreshAccountContext);
      // Batch 426: chain commit/read-model refresh can lag after several back-and-forth
      // messages across observer/genesis frontends. Poll the exact thread briefly so
      // the open conversation continues converging without a manual refresh.
      for (let attempt = 0; attempt < 3; attempt += 1) {
        await sleep(650);
        await loadMessages({ silent: true });
      }
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
            <button className="btn btnPrimary" onClick={() => nav("/messages/compose")} disabled={!account}>Compose message</button>
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

  function renderCompose(): JSX.Element {
    return (
      <section className="card messengerComposeCard">
        <div className="cardBody formStack">
          <div className="sectionHead">
            <div>
              <div className="eyebrow">Compose</div>
              <h2 className="cardTitle">Send a direct message</h2>
              <div className="cardDesc">Choose one person and send an end-to-end encrypted direct message. The backend commits only encrypted ciphertext and never receives plaintext.</div>
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
            <button className="btn btnPrimary" onClick={() => void sendMessage()} disabled={!gate.ok || !messagingEncryptionReady || !recipient.trim() || !body.trim() || signerSubmission.busy}>
              {signerSubmission.busy ? "Waiting…" : "Send message"}
            </button>
            {account ? <button className="btn" onClick={() => setRecipient(account)}>Message myself for demo</button> : null}
          </div>
          {result ? <pre className="codePanel mono">{JSON.stringify(result, null, 2)}</pre> : null}
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
              <div className="eyebrow">Inbox</div>
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
            <span className="statusPill">Auto-refresh {lastMessageRefreshMs ? "active" : "pending"}</span>
          </div>

          <div className="messengerMessages" aria-label="Message thread">
            {selectedMessages.map((message) => (
              <div key={message.message_id} className={`messageBubbleRow ${message.sender === account ? "mine" : "theirs"}`}>
                <div className="messageBubble">
                  <div className="messageBubbleSender">{message.sender === account ? "You" : message.sender}</div>
                  <div>{messageText(message, decryptedBodies)}</div>
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
                disabled={!gate.ok || !messagingEncryptionReady || !replyBody.trim() || signerSubmission.busy}
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

      {account && !messagingEncryptionReady ? (
        <section className="card">
          <div className="cardBody formStack">
            <div className="calloutWarn">
              <strong>Encrypted messaging key required.</strong> Direct messages are end-to-end encrypted. Publish this device's messaging public key before sending or reading encrypted conversations on this account.
            </div>
            <div className="buttonRow">
              <button className="btn btnPrimary" onClick={() => void publishMessagingEncryptionKey()} disabled={!gate.ok || encryptionBusy || signerSubmission.busy}>
                {encryptionBusy ? "Publishing…" : "Enable encrypted messages"}
              </button>
            </div>
          </div>
        </section>
      ) : null}

      {mode === "compose" ? renderCompose() : null}
      {mode === "thread" ? renderThread() : null}
      {mode === "hub" ? renderConversationList() : null}
    </div>
  );
}
