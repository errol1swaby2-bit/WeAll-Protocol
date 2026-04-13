import React, { useEffect, useMemo, useState } from "react";

import AppShell from "./components/AppShell";
import { getKeypair, getSession } from "./auth/session";
import { applySettingsToDocument, loadSettings } from "./lib/settings";
import { useAppConfig } from "./lib/config";
import { maybeApplyDevBootstrap } from "./lib/devBootstrap";
import { currentHashPath, getRouteMeta, isPublicRoute, matchRoute, nav, type RouteMatch } from "./lib/router";

import HomeDashboard from "./pages/HomeDashboard";
import Feed from "./pages/Feed";
import Poh from "./pages/Poh";
import JurorDashboard from "./pages/JurorDashboard";
import Tools from "./pages/Tools";
import Groups from "./pages/Groups";
import Proposals from "./pages/Proposals";
import Proposal from "./pages/Proposal";
import Account from "./pages/Account";
import Content from "./pages/Content";
import Thread from "./pages/Thread";
import Post from "./pages/Post";
import SettingsPage from "./pages/SettingsPage";
import LoginPage from "./pages/LoginPage";
import SessionDevicesPage from "./pages/SessionDevicesPage";
import TransactionsPage from "./pages/TransactionsPage";

function renderPage(route: RouteMatch, readyForApp: boolean): JSX.Element {
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
      return <Proposal id={route.id} />;
    case "/tools":
      return readyForApp ? <Tools /> : <LoginPage />;
    case "/settings":
      return <SettingsPage />;
    case "/session":
      return readyForApp ? <SessionDevicesPage /> : <LoginPage />;
    case "/transactions":
      return readyForApp ? <TransactionsPage /> : <LoginPage />;
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

export default function App(): JSX.Element {
  const config = useAppConfig();
  const [path, setPath] = useState<string>(() => currentHashPath());
  const [settingsVersion, setSettingsVersion] = useState<number>(0);
  const [authVersion, setAuthVersion] = useState<number>(0);

  const session = useMemo(() => getSession(), [authVersion, path]);
  const account = session?.account || "";
  const keypair = useMemo(() => (account ? getKeypair(account) : null), [account, authVersion]);
  const readyForApp = !!session?.account && !!keypair?.secretKeyB64;

  useEffect(() => {
    const onHash = () => setPath(currentHashPath());
    const onStorage = (ev: StorageEvent) => {
      if (ev.key === "weall_client_settings_v2") {
        setSettingsVersion((v: number) => v + 1);
      }
      if (ev.key === "weall_session_v1" || ev.key === "weall.account") {
        setAuthVersion((v: number) => v + 1);
        setPath(currentHashPath());
      }
    };
    window.addEventListener("hashchange", onHash);
    window.addEventListener("storage", onStorage);
    return () => {
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
    const current = currentHashPath();
    if (!readyForApp && !isPublicRoute(current)) {
      nav("/login");
      return;
    }
    if (readyForApp && (current === "/" || current === "/login")) {
      nav("/home");
    }
  }, [readyForApp]);

  const route = matchRoute(path);
  const meta = getRouteMeta(route);

  if (route.path === "/login") {
    return <LoginPage />;
  }

  return (
    <AppShell section={meta.section} label={meta.label} description={meta.description}>
      {renderPage(route, readyForApp)}
    </AppShell>
  );
}
