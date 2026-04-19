import React, { useEffect, useMemo, useState } from "react";

import AppShell from "./components/AppShell";
import ErrorBanner from "./components/ErrorBanner";
import SessionRecoveryBanner from "./components/SessionRecoveryBanner";
import { getKeypair, getSession } from "./auth/session";
import { applySettingsToDocument, loadSettings } from "./lib/settings";
import { useAppConfig } from "./lib/config";
import { maybeApplyDevBootstrap } from "./lib/devBootstrap";
import { currentHashPath, getRouteMeta, isPublicRoute, matchRoute, nav, type RouteMatch } from "./lib/router";
import { useSessionHealth } from "./hooks/useSessionHealth";

import HomeDashboard from "./pages/HomeDashboard";
import Feed from "./pages/Feed";
import Poh from "./pages/Poh";
import JurorDashboard from "./pages/JurorDashboard";
import Tools from "./pages/Tools";
import Groups from "./pages/Groups";
import Proposals from "./pages/Proposals";
import Proposal from "./pages/Proposal";
import Disputes from "./pages/Disputes";
import DisputeDetail from "./pages/DisputeDetail";
import Account from "./pages/Account";
import Content from "./pages/Content";
import Thread from "./pages/Thread";
import Post from "./pages/Post";
import SettingsPage from "./pages/SettingsPage";
import LoginPage from "./pages/LoginPage";
import SessionDevicesPage from "./pages/SessionDevicesPage";
import TransactionsPage from "./pages/TransactionsPage";

function renderPage(route: RouteMatch, readyForApp: boolean, showAdvancedMode: boolean): JSX.Element {
  switch (route.path) {
    case "/login":
      return <LoginPage />;
    case "/home":
      return readyForApp ? <HomeDashboard /> : <LoginPage />;
    case "/feed":
      return <Feed />;
    case "/post":
      return readyForApp ? <Post /> : <LoginPage />;
    case "/poh":
      return readyForApp ? <Poh /> : <LoginPage />;
    case "/juror":
      return readyForApp ? <JurorDashboard /> : <LoginPage />;
    case "/groups":
      return <Groups />;
    case "/groups/:id":
      return <Groups groupId={route.id} />;
    case "/proposals":
      return <Proposals />;
    case "/proposal/:id":
    case "/proposals/:id":
      return <Proposal id={route.id} />;
    case "/disputes":
      return <Disputes />;
    case "/disputes/:id":
      return <DisputeDetail id={route.id} />;
    case "/tools":
      return readyForApp && showAdvancedMode ? <Tools /> : readyForApp ? <HomeDashboard /> : <LoginPage />;
    case "/settings":
      return <SettingsPage />;
    case "/session":
      return <SessionDevicesPage />;
    case "/transactions":
      return readyForApp && showAdvancedMode ? <TransactionsPage /> : readyForApp ? <HomeDashboard /> : <LoginPage />;
    case "/account/:account":
      return <Account account={route.account} />;
    case "/content/:id":
      return <Content id={route.id} />;
    case "/thread/:id":
      return <Thread id={route.id} />;
    default:
      return readyForApp ? <HomeDashboard /> : <Feed />;
  }
}

function SessionRecoveryGate(): JSX.Element {
  return (
    <section className="card">
      <div className="cardBody formStack">
        <div className="eyebrow">Protected route locked</div>
        <h2 className="cardTitle">Recover session posture before continuing</h2>
        <p className="cardDesc">
          This route stays in the protected shell so the session failure is visible in context. Restore the browser session or the local
          signer before attempting new writes.
        </p>
        <div className="buttonRow">
          <button className="btn btnPrimary" onClick={() => nav("/session")}>Open session recovery</button>
          <button className="btn" onClick={() => nav("/login")}>Go to login</button>
        </div>
      </div>
    </section>
  );
}

export default function App(): JSX.Element {
  const config = useAppConfig();
  const [path, setPath] = useState<string>(() => currentHashPath());
  const [settingsVersion, setSettingsVersion] = useState<number>(0);
  const [authVersion, setAuthVersion] = useState<number>(0);
  const [authHydrated, setAuthHydrated] = useState<boolean>(false);

  const settings = useMemo(() => loadSettings(), [settingsVersion]);
  const session = useMemo(() => getSession(), [authVersion, path]);
  const account = session?.account || "";
  const keypair = useMemo(() => (account ? getKeypair(account) : null), [account, authVersion]);
  const readyForApp = !!session?.account && !!keypair?.secretKeyB64;
  const sessionHealth = useSessionHealth(authVersion);
  const showAdvancedMode = settings.showAdvancedMode;

  useEffect(() => {
    const hydrationTimer = window.setTimeout(() => setAuthHydrated(true), 120);
    const onHash = () => setPath(currentHashPath());
    const onStorage = (ev: StorageEvent) => {
      if (ev.key === "weall_client_settings_v3") {
        setSettingsVersion((v: number) => v + 1);
      }
      if (ev.key === "weall_session_v1" || ev.key === "weall.account" || String(ev.key || "").startsWith("weall_kp_v1::")) {
        setAuthVersion((v: number) => v + 1);
        setPath(currentHashPath());
      }
    };
    window.addEventListener("hashchange", onHash);
    window.addEventListener("storage", onStorage);
    return () => {
      window.clearTimeout(hydrationTimer);
      window.removeEventListener("hashchange", onHash);
      window.removeEventListener("storage", onStorage);
    };
  }, []);

  useEffect(() => {
    applySettingsToDocument(loadSettings());
  }, [settingsVersion]);

  useEffect(() => {
    let cancelled = false;

    const runBootstrapSync = async () => {
      const applied = await maybeApplyDevBootstrap(config);
      if (applied && !cancelled) {
        setAuthVersion((v: number) => v + 1);
        setPath(currentHashPath());
      }
      if (!cancelled) setAuthHydrated(true);
    };

    void runBootstrapSync();

    if (!config.enableDevBootstrap) {
      return () => {
        cancelled = true;
      };
    }

    const onFocus = () => {
      void runBootstrapSync();
    };
    const onVisibility = () => {
      if (!document.hidden) void runBootstrapSync();
    };

    window.addEventListener("focus", onFocus);
    document.addEventListener("visibilitychange", onVisibility);

    return () => {
      cancelled = true;
      window.removeEventListener("focus", onFocus);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [config]);

  useEffect(() => {
    if (!authHydrated) return;
    const current = currentHashPath();
    if (current === "/login" && readyForApp) {
      nav("/home");
      return;
    }
    if ((current === "/" || !current) && !readyForApp) {
      nav("/login");
      return;
    }
    if ((current === "/" || !current) && readyForApp) {
      nav("/home");
    }
  }, [authHydrated, readyForApp]);

  const route = matchRoute(path);
  const meta = getRouteMeta(route);
  const protectedButDegraded = meta.authRequired && authHydrated && !readyForApp && sessionHealth.recoverableAccount;
  const protectedAnonymous = meta.authRequired && authHydrated && !readyForApp && !sessionHealth.recoverableAccount;

  if (!authHydrated && meta.authRequired) {
    return (
      <AppShell route={route} meta={meta} sessionHealth={sessionHealth}>
        <section className="card">
          <div className="cardBody formStack">
            <div className="eyebrow">Restoring session</div>
            <h2 className="cardTitle">Checking device signer and session state</h2>
            <div className="cardDesc">
              Holding this route briefly prevents a false redirect to login while local signer and session state hydrate.
            </div>
          </div>
        </section>
      </AppShell>
    );
  }

  if (route.path === "/login") {
    return <LoginPage />;
  }

  if (protectedAnonymous && !isPublicRoute(path)) {
    return <LoginPage />;
  }

  if (protectedButDegraded && route.path !== "/session") {
    return (
      <AppShell route={route} meta={meta} sessionHealth={sessionHealth}>
        <SessionRecoveryBanner health={sessionHealth} />
        <SessionRecoveryGate />
      </AppShell>
    );
  }

  return (
    <AppShell route={route} meta={meta} sessionHealth={sessionHealth}>
      {meta.authRequired && sessionHealth.state !== "active" ? <SessionRecoveryBanner health={sessionHealth} compact /> : null}
      {renderPage(route, readyForApp, showAdvancedMode)}
      {meta.authRequired && sessionHealth.state === "expiring_soon" ? (
        <ErrorBanner
          category="auth_session_expired"
          title="Session nearing expiry"
          message="This route is still usable, but one-shot actions should be completed soon or the session should be renewed from the session utility page."
        />
      ) : null}
    </AppShell>
  );
}
