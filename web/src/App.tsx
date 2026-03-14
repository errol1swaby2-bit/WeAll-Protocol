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
  return path === "/login";
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
      page = readyForApp ? <Feed /> : <LoginPage />;
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
      page = readyForApp ? <Groups /> : <LoginPage />;
      break;

    case "/groups/:id":
      page = readyForApp ? <Groups groupId={r.id} /> : <LoginPage />;
      break;

    case "/proposals":
      page = readyForApp ? <Proposals /> : <LoginPage />;
      break;

    case "/proposal/:id":
      page = readyForApp ? <Proposal id={r.id} /> : <LoginPage />;
      break;

    case "/tools":
      page = readyForApp ? <Tools /> : <LoginPage />;
      break;

    case "/settings":
      page = readyForApp ? <Settings /> : <LoginPage />;
      break;

    case "/account/:account":
      page = readyForApp ? <Account account={r.account} /> : <LoginPage />;
      break;

    case "/content/:id":
      page = readyForApp ? <Content id={r.id} /> : <LoginPage />;
      break;

    case "/thread/:id":
      page = readyForApp ? <Thread id={r.id} /> : <LoginPage />;
      break;

    default:
      page = readyForApp ? <Home /> : <LoginPage />;
      break;
  }

  return <AppShell>{page}</AppShell>;
}

