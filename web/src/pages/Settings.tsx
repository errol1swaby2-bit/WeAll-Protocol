import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, getEmailOracleBaseUrl, setApiBaseUrl } from "../api/weall";
import { getKeypair, getSession } from "../auth/session";
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
    flash("Network settings saved.");
  }

  function resetAppearance() {
    setSettings({ ...DEFAULT_SETTINGS, showGenesisBootstrap: settings.showGenesisBootstrap });
    saveSettings({ ...DEFAULT_SETTINGS, showGenesisBootstrap: settings.showGenesisBootstrap });
    applySettingsToDocument({ ...DEFAULT_SETTINGS, showGenesisBootstrap: settings.showGenesisBootstrap });
    flash("Appearance reset.");
  }

  function toggleGenesisBootstrap() {
    const next = { ...settings, showGenesisBootstrap: !settings.showGenesisBootstrap };
    setSettings(next);
    saveSettings(next);
    flash("Advanced setting saved.");
  }

  return (
    <div className="pageStack">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Settings</div>
              <h1 className="heroTitle heroTitleSm">Customize the client, not the login flow</h1>
              <p className="heroText">
                Device bootstrap now lives on the Login page. Settings is reserved for appearance,
                accessibility, and real client / node targeting controls.
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
                <span className="statusPill ok">{apiBase || "API base unset"}</span>
              </div>
            </div>
          </div>

          {saved ? <div className="calloutInfo"><strong>{saved}</strong></div> : null}
        </div>
      </section>

      <section className="card">
        <div className="cardBody pageStack">
          <div className="eyebrow">Appearance</div>
          <h2 style={{ marginTop: 8 }}>Personalize the frontend</h2>

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
          <div className="eyebrow">Network</div>
          <h2 style={{ marginTop: 8 }}>API and relay settings</h2>

          <label className="pageStack" style={{ gap: 8 }}>
            <span>API base URL</span>
            <input
              value={apiBase}
              onChange={(e) => setApiBase(e.target.value)}
              placeholder="http://127.0.0.1:8000"
            />
          </label>

          <label className="pageStack" style={{ gap: 8 }}>
            <span>Email relay base</span>
            <input value={relayBase} readOnly />
          </label>

          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            <button className="btn btnPrimary" onClick={saveNetwork}>
              Save network settings
            </button>
            <button className="btn" onClick={() => setApiBase("http://127.0.0.1:8000")}>
              Use local backend
            </button>
          </div>
        </div>
      </section>

      <section className="card">
        <div className="cardBody pageStack">
          <div className="eyebrow">Advanced</div>
          <h2 style={{ marginTop: 8 }}>Local client behavior</h2>

          <p className="cardDesc">
            Founder-only bootstrap controls are hidden from the product surface for external testers.
            This page keeps only user-facing network and appearance settings.
          </p>
        </div>
      </section>
    </div>
  );
}
