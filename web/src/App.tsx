import React, { useEffect, useMemo, useState } from "react";

import AppShell from "./components/AppShell";
import { getKeypair, getSession } from "./auth/session";
import { applySettingsToDocument, loadSettings } from "./lib/settings";
import { matchRoute, nav } from "./lib/router";

import Home from "./pages/Home";
import Feed from "./pages/Feed";
import PohPage from "./pages/PohPage";
import JurorDashboard from "./pages/JurorDashboard";
import Tools from "./pages/Tools";
import Groups from "./pages/Groups";
import Proposals from "./pages/Proposals";
import Proposal from "./pages/Proposal";
import Account from "./pages/Account";
import Content from "./pages/Content";
import Thread from "./pages/Thread";
import CreatePostPage from "./pages/CreatePostPage";
import Settings from "./pages/Settings";
import LoginPage from "./pages/LoginPage";

function getHashPath(): string {
  const raw = window.location.hash || "#/login";
  const p = raw.startsWith("#") ? raw.slice(1) : raw;
  return p.startsWith("/") ? p : `/${p}`;
}

function isPublicRoute(path: string): boolean {
  return (
    path === "/login" ||
    path === "/feed" ||
    path === "/groups" ||
    path === "/proposals" ||
    path === "/settings" ||
    path.startsWith("/groups/") ||
    path.startsWith("/proposal/") ||
    path.startsWith("/account/") ||
    path.startsWith("/content/") ||
    path.startsWith("/thread/")
  );
}

export default function App(): JSX.Element {
  const [path, setPath] = useState<string>(() => getHashPath());
  const [settingsVersion, setSettingsVersion] = useState<number>(0);

  const session = getSession();
  const account = session?.account || "";
  const keypair = useMemo(() => (account ? getKeypair(account) : null), [account]);
  const readyForApp = !!session?.account && !!keypair?.secretKeyB64;

  useEffect(() => {
    const onHash = () => setPath(getHashPath());
    const onStorage = (ev: StorageEvent) => {
      if (ev.key === "weall_client_settings_v2") {
        setSettingsVersion((v) => v + 1);
      }
      if (ev.key === "weall_session_v1") {
        setPath(getHashPath());
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
    const current = getHashPath();
    if (!readyForApp && !isPublicRoute(current)) {
      nav("/login");
      return;
    }
    if (readyForApp && (current === "/" || current === "/login")) {
      nav("/home");
    }
  }, [readyForApp]);

  const r = matchRoute(path);

  if (r.path === "/login") {
    return <LoginPage />;
  }

  let page: JSX.Element;
  switch (r.path) {
    case "/home":
      page = readyForApp ? <Home /> : <LoginPage />;
      break;
    case "/feed":
      page = <Feed />;
      break;
    case "/post":
      page = readyForApp ? <CreatePostPage /> : <LoginPage />;
      break;
    case "/poh":
      page = readyForApp ? <PohPage /> : <LoginPage />;
      break;
    case "/juror":
      page = readyForApp ? <JurorDashboard /> : <LoginPage />;
      break;
    case "/groups":
      page = <Groups />;
      break;
    case "/groups/:id":
      page = <Groups groupId={r.id} />;
      break;
    case "/proposals":
      page = <Proposals />;
      break;
    case "/proposal/:id":
      page = <Proposal id={r.id} />;
      break;
    case "/tools":
      page = readyForApp ? <Tools /> : <LoginPage />;
      break;
    case "/settings":
      page = <Settings />;
      break;
    case "/account/:account":
      page = <Account account={r.account} />;
      break;
    case "/content/:id":
      page = <Content id={r.id} />;
      break;
    case "/thread/:id":
      page = <Thread id={r.id} />;
      break;
    default:
      page = readyForApp ? <Home /> : <Feed />;
      break;
  }

  return <AppShell>{page}</AppShell>;
}
