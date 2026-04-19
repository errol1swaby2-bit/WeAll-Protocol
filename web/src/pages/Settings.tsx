import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, getEmailOracleBaseUrl, setApiBaseUrl } from "../api/weall";
import { getKeypair, getSession } from "../auth/session";
import { useAppConfig } from "../lib/config";
import {
  AccentTone,
  applySettingsToDocument,
  ClientSettings,
  DEFAULT_SETTINGS,
  Density,
  FontScale,
  loadSettings,
  MotionMode,
  saveSettings,
  ThemeMode,
} from "../lib/settings";



function SettingToggle({
  label,
  description,
  checked,
  onChange,
}: {
  label: string;
  description: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}): JSX.Element {
  return (
    <label className="progressRow" style={{ alignItems: "flex-start", gap: 14, cursor: "pointer" }}>
      <span style={{ flex: 1 }}>
        <strong style={{ display: "block", marginBottom: 4 }}>{label}</strong>
        <span className="cardDesc">{description}</span>
      </span>
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} />
    </label>
  );
}

function SettingSelect<T extends string>({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: T;
  options: Array<{ value: T; label: string }>;
  onChange: (value: T) => void;
}): JSX.Element {
  return (
    <label className="pageStack" style={{ gap: 8 }}>
      <span>{label}</span>
      <select value={value} onChange={(e) => onChange(e.target.value as T)}>
        {options.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </select>
    </label>
  );
}

export default function Settings(): JSX.Element {
  const config = useAppConfig();
  const session = getSession();
  const account = session?.account || "";
  const keypair = useMemo(() => (account ? getKeypair(account) : null), [account]);

  const [settings, setSettings] = useState<ClientSettings>(() => loadSettings());
  const [apiBase, setApiBase] = useState<string>(() => getApiBaseUrl());
  const [saved, setSaved] = useState<string>("");
  const relayBase = getEmailOracleBaseUrl();

  useEffect(() => {
    applySettingsToDocument(settings);
  }, [settings]);

  function flash(message: string) {
    setSaved(message);
    window.setTimeout(() => setSaved(""), 1800);
  }

  function update<K extends keyof ClientSettings>(key: K, value: ClientSettings[K]) {
    const next = { ...settings, [key]: value };
    setSettings(next);
    saveSettings(next);
    applySettingsToDocument(next);
    flash("Appearance settings saved.");
  }

  function saveNetwork() {
    const trimmed = String(apiBase || "").trim();
    if (!trimmed) return;
    setApiBaseUrl(trimmed);
    flash("Connection target saved.");
  }

  function resetAppearance() {
    const next = { ...DEFAULT_SETTINGS, showGenesisBootstrap: settings.showGenesisBootstrap, showAdvancedMode: settings.showAdvancedMode };
    setSettings(next);
    saveSettings(next);
    applySettingsToDocument(next);
    flash("Appearance reset.");
  }

  const apiChanged = String(apiBase || "").trim() !== String(config.defaultApiBase || "").trim();

  return (
    <div className="pageStack">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Settings</div>
              <h1 className="heroTitle heroTitleSm">Connection, environment, and client preferences</h1>
              <p className="heroText">
                This page is for local client behavior and backend targeting. It should make clear what changes only this browser, what changes the connection target, and what leaves on-chain state untouched.
              </p>
            </div>

            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Current client state</div>
              <div className="heroInfoList">
                <span className={`statusPill ${session ? "ok" : ""}`}>
                  {session ? "Session present" : "No session"}
                </span>
                <span className={`statusPill ${keypair ? "ok" : ""}`}>
                  {keypair ? "Signer stored" : "No local signer"}
                </span>
                <span className="statusPill ok">{config.envLabel}</span>
              </div>
            </div>
          </div>

          {saved ? (
            <div className="calloutInfo"><strong>{saved}</strong></div>
          ) : null}
        </div>
      </section>

      <section className="summaryCardGrid">
        <article className="summaryCard">
          <div className="summaryCardLabel">Connection target</div>
          <div className="summaryCardValue mono">{apiBase || "Unset"}</div>
          <div className="summaryCardText">Changing this affects which backend and protocol environment this browser talks to. It does not alter on-chain data by itself.</div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Default environment</div>
          <div className="summaryCardValue mono">{config.defaultApiBase}</div>
          <div className="summaryCardText">Build-time default for this client: {config.appName} {config.clientVersion} ({config.envLabel}).</div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Email relay</div>
          <div className="summaryCardValue mono">{relayBase || "Unavailable"}</div>
          <div className="summaryCardText">Used for backend-assisted verification steps. This is informational here, not an authority switch.</div>
        </article>
      </section>

      <section className="card">
        <div className="cardBody pageStack">
          <div className="eyebrow">Connection & Environment</div>
          <h2 style={{ marginTop: 8 }}>Treat backend changes as protocol-context changes</h2>
          <p className="cardDesc">
            Switching the API base changes what node or environment this browser trusts for reads, session workflows, and transaction submission. Use this deliberately.
          </p>

          <label className="pageStack" style={{ gap: 8 }}>
            <span>API base URL</span>
            <input
              value={apiBase}
              onChange={(e) => setApiBase(e.target.value)}
              placeholder="http://127.0.0.1:8000"
            />
          </label>

          <div className="progressList">
            <div className="progressRow">
              <span>Configured target differs from build default</span>
              <span className={`statusPill ${apiChanged ? "" : "ok"}`}>{apiChanged ? "Custom target" : "Using default"}</span>
            </div>
            <div className="progressRow">
              <span>Build environment label</span>
              <span className="statusPill ok">{config.envLabel}</span>
            </div>
            <div className="progressRow">
              <span>Client version</span>
              <span className="statusPill ok">{config.clientVersion}</span>
            </div>
          </div>

          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            <button className="btn btnPrimary" onClick={saveNetwork}>
              Save connection target
            </button>
            <button className="btn" onClick={() => setApiBase(config.defaultApiBase)}>
              Use build default
            </button>
            <button className="btn" onClick={() => setApiBase("http://127.0.0.1:8000")}>
              Use local backend
            </button>
          </div>
        </div>
      </section>

      <section className="card">
        <div className="cardBody pageStack">
          <div className="eyebrow">Appearance</div>
          <h2 style={{ marginTop: 8 }}>Personalize this browser client</h2>
          <p className="cardDesc">Appearance changes are local only. They do not change session state, account standing, or protocol behavior.</p>

          <SettingSelect<ThemeMode>
            label="Theme mode"
            value={settings.themeMode}
            options={[
              { value: "dark", label: "Dark" },
              { value: "light", label: "Light" },
            ]}
            onChange={(value) => update("themeMode", value)}
          />

          <SettingSelect<AccentTone>
            label="Accent tone"
            value={settings.accentTone}
            options={[
              { value: "mint", label: "Mint" },
              { value: "cyan", label: "Cyan" },
              { value: "gold", label: "Gold" },
              { value: "rose", label: "Rose" },
            ]}
            onChange={(value) => update("accentTone", value)}
          />

          <SettingSelect<FontScale>
            label="Font size"
            value={settings.fontScale}
            options={[
              { value: "sm", label: "Small" },
              { value: "md", label: "Medium" },
              { value: "lg", label: "Large" },
            ]}
            onChange={(value) => update("fontScale", value)}
          />

          <SettingSelect<Density>
            label="Layout density"
            value={settings.density}
            options={[
              { value: "comfortable", label: "Comfortable" },
              { value: "compact", label: "Compact" },
            ]}
            onChange={(value) => update("density", value)}
          />

          <SettingSelect<MotionMode>
            label="Motion"
            value={settings.motionMode}
            options={[
              { value: "full", label: "Full motion" },
              { value: "reduced", label: "Reduced motion" },
            ]}
            onChange={(value) => update("motionMode", value)}
          />

          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            <button className="btn" onClick={resetAppearance}>
              Reset appearance
            </button>
          </div>
        </div>
      </section>


      <section className="card">
        <div className="cardBody pageStack">
          <div className="eyebrow">Experience mode</div>
          <h2 style={{ marginTop: 8 }}>Keep protocol workbench tools behind an explicit toggle</h2>
          <p className="cardDesc">
            Advanced mode reveals tester-oriented surfaces such as the protocol console, transaction catalog views, and raw payload authoring controls. Leave it off for a cleaner end-user experience.
          </p>

          <SettingToggle
            label="Show advanced and tester surfaces"
            description="Use this only when you are intentionally auditing the protocol, debugging a flow, or exercising expert-only authoring controls."
            checked={settings.showAdvancedMode}
            onChange={(value) => update("showAdvancedMode", value)}
          />
        </div>
      </section>

      <section className="card">
        <div className="cardBody pageStack">
          <div className="eyebrow">Local state</div>
          <h2 style={{ marginTop: 8 }}>What this page does not change</h2>
          <p className="cardDesc">
            This page does not register accounts, upgrade PoH, assign roles, or modify consensus state. It only changes this browser’s client behavior and connection target.
          </p>
        </div>
      </section>
    </div>
  );
}
