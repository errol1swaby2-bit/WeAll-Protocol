import React, { useEffect, useMemo, useState } from "react";

import { getApiBaseUrl, setApiBaseUrl, validateApiBaseInput } from "../api/weall";
import { applyCompatibilityBaseline, discoverNodeProbes, isPublicApiOrigin, loadExpectedCompatibilityBaseline, probeNode } from "../lib/nodeConnectionManager";
import { selectBrowserNode } from "../lib/browserNodeTransition";
import NodeConnectionPanel from "../components/NodeConnectionPanel";
import { getKeypair, getSession } from "../auth/session";
import { useAppConfig } from "../lib/config";
import { nav } from "../lib/router";
import { SETTINGS_SECTIONS, settingsSectionFromHash, type SettingsSection } from "../lib/settingsSections";
import { THEME_PRESETS, presetMatchesSettings, type ThemePreset } from "../lib/themePresets";
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
  const [networkError, setNetworkError] = useState<string>("");
  const [networkBusy, setNetworkBusy] = useState(false);
  const [section, setSection] = useState<SettingsSection>(() =>
    settingsSectionFromHash(typeof window === "undefined" ? "" : window.location.hash),
  );

  useEffect(() => {
    const syncSection = () => setSection(settingsSectionFromHash(window.location.hash));
    window.addEventListener("hashchange", syncSection);
    syncSection();
    return () => window.removeEventListener("hashchange", syncSection);
  }, []);

  function openSection(next: SettingsSection) {
    const choice = SETTINGS_SECTIONS.find((candidate) => candidate.id === next);
    if (!choice) return;
    setSection(next);
    nav(choice.href);
  }

  function applyPreset(preset: ThemePreset) {
    const next = { ...settings, themeMode: preset.themeMode, accentTone: preset.accentTone };
    setSettings(next);
    saveSettings(next);
    applySettingsToDocument(next);
    flash(`${preset.name} theme applied locally.`);
  }

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

  async function saveNetwork() {
    const trimmed = String(apiBase || "").trim();
    const validation = validateApiBaseInput(trimmed);
    if (!validation.ok) {
      setNetworkError(validation.reason);
      return;
    }
    setNetworkError("");
    setNetworkBusy(true);
    try {
      if (config.publicTestnet) {
        // No bypass from this raw URL field to an unlisted or unsynced node.
        if (!isPublicApiOrigin(validation.normalized)) {
          throw new Error("Public testnet access requires a published HTTPS node URL.");
        }
        const probes = await discoverNodeProbes({ timeoutMs: 3000 });
        let probe = probes.find((item) => item.baseUrl === validation.normalized);
        if (!probe) {
          // Explicit custom URL: inspect its public chain identity without
          // transmitting any bearer before the user consents.
          const baseline = await loadExpectedCompatibilityBaseline();
          const raw = await probeNode({ url: validation.normalized, label: "Manual HTTPS API" }, { timeoutMs: 3000 });
          probe = applyCompatibilityBaseline([raw], baseline)[0];
        }
        if (!probe || probe.phase !== "healthy" || !probe.ok) {
          throw new Error("The requested HTTPS API is not ready or does not match the pinned testnet chain.");
        }
        const connection = await selectBrowserNode(probe, {
          intent: "manual",
          allowCurrent: true,
          confirmUnlisted: () => window.confirm(
            "This compatible HTTPS node is not in WeAll's published seed manifest. Its operator may observe your API requests and session bearer. Approve connecting to this specific address in this browser tab?",
          ),
        });
        if (!connection) return; // Declined; preserve the existing connection.
        setApiBase(connection.baseUrl);
        flash(connection.runtimeBase ? "Verified connection target saved." : "Connection target saved.");
      } else {
        const runtimeBase = setApiBaseUrl(validation.normalized);
        setApiBase(validation.normalized);
        flash(runtimeBase ? "Connection target saved." : "Connection target saved for same-origin API.");
      }
    } catch (error: unknown) {
      setNetworkError(error instanceof Error ? error.message : "Could not verify the connection target.");
    } finally {
      setNetworkBusy(false);
    }
  }

  function resetAppearance() {
    const next = { ...DEFAULT_SETTINGS, showGenesisBootstrap: settings.showGenesisBootstrap, showAdvancedMode: settings.showAdvancedMode };
    setSettings(next);
    saveSettings(next);
    applySettingsToDocument(next);
    flash("Appearance reset.");
  }

  const validation = validateApiBaseInput(apiBase);
  const apiChanged = String(apiBase || "").trim() !== String(config.defaultApiBase || "").trim();
  const usingLoopback = validation.ok && validation.isLoopback;
  const usingRemote = validation.ok && validation.isRemote;

  return (
    <div className="pageStack utilityPage settingsPage">
      <section className="card heroCard">
        <div className="cardBody heroBody compactHero">
          <div className="heroSplit">
            <div>
              <div className="eyebrow">Settings</div>
              <h1 className="heroTitle heroTitleSm">Connection, environment, and client preferences</h1>
              <p className="heroText">
                This page is for local app behavior and backend targeting. It should make clear what changes only this browser, what changes the connection target, and what leaves authoritative account state untouched.
              </p>
            </div>

            <div className="heroInfoPanel">
              <div className="heroInfoTitle">Current client state</div>
              <div className="heroInfoList">
                <span className={`statusPill ${session ? "ok" : ""}`}>
                  {session ? "Session present" : "No session"}
                </span>
                <span className={`statusPill ${keypair ? "ok" : ""}`}>
                  {keypair ? "Signer stored" : "No saved account key"}
                </span>
                <span className="statusPill ok">{config.envLabel}</span>
              </div>
            </div>
          </div>

          <div className="heroActions">
            <button className="btn" onClick={() => nav("/session")}>Open devices & sessions</button>
            <button className="btn" onClick={() => openSection("connection")}>Manage connection</button>
          </div>

          {saved ? (
            <div className="calloutInfo"><strong>{saved}</strong></div>
          ) : null}

          {networkError ? (
            <div className="calloutWarn"><strong>Connection target not saved.</strong> {networkError}</div>
          ) : null}

          <div className="detailFocusStrip utilityFocusStrip">
            <article className="detailFocusCard utilityFocusCard">
              <div className="detailFocusLabel">Utility contract</div>
              <div className="detailFocusValue">Local client preferences only</div>
              <div className="detailFocusText">Treat this page as a browser-side control surface. It changes how this client behaves and which backend it talks to, not the chain itself.</div>
            </article>
            <article className="detailFocusCard utilityFocusCard">
              <div className="detailFocusLabel">Connection context</div>
              <div className="detailFocusValue">{apiChanged ? "Custom backend target" : "Using build default"}</div>
              <div className="detailFocusText">Changing the API base changes the environment used for reads, session workflows, and submissions. It should always feel deliberate.</div>
            </article>
            <article className="detailFocusCard utilityFocusCard">
              <div className="detailFocusLabel">Chain safety</div>
              <div className="detailFocusValue">On-chain state untouched</div>
              <div className="detailFocusText">Nothing on this page grants roles, changes balances, or edits protocol state by itself. It only changes local client posture.</div>
            </article>
          </div>
        </div>
      </section>

      <nav className="settingsSectionTabs" aria-label="Settings categories">
        {SETTINGS_SECTIONS.map((item) => (
          <button
            key={item.id}
            type="button"
            className={`settingsSectionTab ${section === item.id ? "isActive" : ""}`}
            aria-current={section === item.id ? "page" : undefined}
            onClick={() => openSection(item.id)}
          >
            {item.label}
          </button>
        ))}
      </nav>

      {section === "overview" ? (
      <section className="card" aria-label="Settings overview">
        <div className="cardBody pageStack">
          <h2 className="cardTitle">Choose what to customize</h2>
          <p className="cardDesc">
            Appearance affects only this browser. Node connection and advanced diagnostics are separate
            settings; nothing here changes a signed protocol record or public profile appearance.
          </p>
          <div className="settingsCategoryGrid">
            {SETTINGS_SECTIONS.filter((item) => item.id !== "overview").map((item) => (
              <button key={item.id} type="button" className="settingsCategoryTile" onClick={() => openSection(item.id)}>
                <strong>{item.label}</strong>
                <span className="cardDesc">Open {item.label.toLowerCase()} settings</span>
              </button>
            ))}
          </div>
        </div>
      </section>
      ) : null}

      {section === "connection" ? (
      <>
      <section className="summaryCardGrid">
        <article className="summaryCard">
          <div className="summaryCardLabel">Connection target</div>
          <div className="summaryCardValue mono">{apiBase || "Unset"}</div>
          <div className="summaryCardText">Changing this affects which backend and environment this browser talks to. Remote genesis APIs are supported when entered as full http(s) URLs.</div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Default environment</div>
          <div className="summaryCardValue mono">{config.defaultApiBase}</div>
          <div className="summaryCardText">Build-time default for this client: {config.appName} {config.clientVersion} ({config.envLabel}). Production builds default to same-origin unless a remote API is explicitly configured.</div>
        </article>
        <article className="summaryCard">
          <div className="summaryCardLabel">Account verification path</div>
          <div className="summaryCardValue mono">Async / Live</div>
          <div className="summaryCardText">Human verification is handled through WeAll account-verification surfaces and authoritative backend state, not by a browser-configured external identity endpoint.</div>
        </article>
      </section>

      <section className="card">
        <div className="cardBody pageStack">
          <div className="eyebrow">Connection & Environment</div>
          <h2 style={{ marginTop: 8 }}>Treat backend changes as environment changes</h2>
          <p className="cardDesc">
            Switching the API base changes what environment this browser uses for reads, session workflows, and action submission. Use this deliberately. For a remote genesis node, enter the full backend URL such as https://genesis.example.org.
          </p>

          <label className="pageStack" style={{ gap: 8 }}>
            <span>API base URL</span>
            <input
              value={apiBase}
              onChange={(e) => setApiBase(e.target.value)}
              placeholder={config.publicTestnet ? "https://api.your-node.example" : "http://127.0.0.1:8000"}
            />
          </label>

          <div className="progressList">
            <div className="progressRow">
              <span>Configured target differs from build default</span>
              <span className={`statusPill ${apiChanged ? "" : "ok"}`}>{apiChanged ? "Custom target" : "Using default"}</span>
            </div>
            <div className="progressRow">
              <span>Remote genesis API supported</span>
              <span className={`statusPill ${usingRemote ? "ok" : ""}`}>{usingRemote ? "Remote target" : "Same-origin or local"}</span>
            </div>
            <div className="progressRow">
              <span>Loopback backend target</span>
              <span className={`statusPill ${!usingLoopback || !config.isProduction ? "ok" : ""}`}>{usingLoopback ? (config.isProduction ? "Review before production use" : "Local development") : "Not loopback"}</span>
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
            <button className="btn btnPrimary" onClick={() => void saveNetwork()} disabled={networkBusy}>
              {networkBusy ? "Verifying node…" : "Save connection target"}
            </button>
            {!config.publicTestnet ? (
              <button className="btn" onClick={() => setApiBase(config.defaultApiBase)}>
                Use build default
              </button>
            ) : null}
            {!config.isProduction ? (
              <button className="btn" onClick={() => setApiBase("http://127.0.0.1:8000")}>
                Use local backend
              </button>
            ) : null}
          </div>
        </div>
      </section>

      <NodeConnectionPanel />
      </>
      ) : null}

      {(section === "themes" || section === "layout" || section === "accessibility") ? (
      <section className="card">
        <div className="cardBody pageStack">
          <div className="eyebrow">Appearance</div>
          <h2 style={{ marginTop: 8 }}>Personalize this browser client</h2>
          <p className="cardDesc">Appearance changes are local only. They do not change session state, account standing, or protocol behavior.</p>

          {section === "themes" ? (
            <div className="pageStack">
              <p className="cardDesc">Choose a bundled, non-executable visual theme. Preview the appearance on each tile before applying; changes stay local to this browser.</p>
              <div className="themePresetGrid" aria-label="Theme presets">
                {THEME_PRESETS.map((preset) => {
                  const selected = presetMatchesSettings(preset, settings);
                  return (
                    <button
                      type="button"
                      key={preset.id}
                      className={`themePresetTile ${selected ? "isActive" : ""}`}
                      aria-pressed={selected}
                      onClick={() => applyPreset(preset)}
                    >
                      <span className="themePresetPreview" style={{ background: preset.background, color: preset.foreground }}>
                        <span className="themePresetMockCard" style={{ background: preset.surface }}>
                          <span className="themePresetMockHeading">WeAll</span>
                          <span className="themePresetMockAccent" style={{ background: preset.accent }} />
                        </span>
                      </span>
                      <strong>{preset.name}</strong>
                      <span className="cardDesc">{preset.description}</span>
                      {selected ? <span className="miniTag">Current theme</span> : null}
                    </button>
                  );
                })}
              </div>
            </div>
          ) : null}

          {section === "themes" ? (
          <>
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
          </>
          ) : null}

          {section === "layout" ? (
          <>
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
          </>
          ) : null}

          {section === "accessibility" ? (
          <>
          <SettingSelect<MotionMode>
            label="Motion"
            value={settings.motionMode}
            options={[
              { value: "full", label: "Full motion" },
              { value: "reduced", label: "Reduced motion" },
            ]}
            onChange={(value) => update("motionMode", value)}
          />
          <div className="calloutInfo">
            Reduced motion affects decorative animation only. Required consent, signing, error and
            eligibility information remains visible regardless of color theme.
          </div>
          </>
          ) : null}

          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            <button className="btn" onClick={resetAppearance}>
              Reset appearance
            </button>
          </div>
        </div>
      </section>
      ) : null}

      {section === "advanced" ? (
      <section className="card">
        <div className="cardBody pageStack">
          <div className="eyebrow">Experience mode</div>
          <h2 style={{ marginTop: 8 }}>Keep technical workbench tools behind an explicit toggle</h2>
          <p className="cardDesc">
            Advanced mode reveals tester-oriented surfaces such as technical records, network status, and raw payload authoring controls. Leave it off for a cleaner end-user experience.
          </p>

          {config.enableDevTools ? (
            <SettingToggle
              label="Show advanced and tester surfaces"
              description="Use this only when you are intentionally auditing technical behavior, debugging a flow, or exercising expert-only authoring controls."
              checked={settings.showAdvancedMode}
              onChange={(value) => update("showAdvancedMode", value)}
            />
          ) : (
            <div className="calloutInfo">
              <strong>Advanced and tester surfaces are disabled in this production build.</strong> Normal users will not see demo tools, technical consoles, or developer routes.
            </div>
          )}
        </div>
      </section>
      ) : null}

      {section === "overview" ? (
      <section className="card">
        <div className="cardBody pageStack">
          <div className="eyebrow">Local state</div>
          <h2 style={{ marginTop: 8 }}>What this page does not change</h2>
          <p className="cardDesc">
            This page does not register accounts, change verification status, assign responsibilities, or modify shared network state. It only changes this browser’s client behavior and connection target.
          </p>
        </div>
      </section>
      ) : null}
    </div>
  );
}
