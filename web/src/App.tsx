import React, { Suspense, lazy, useEffect, useMemo, useState } from "react";

import AppShell from "./components/AppShell";
import ErrorBanner from "./components/ErrorBanner";
import SessionRecoveryBanner from "./components/SessionRecoveryBanner";
import MessagingKeyBootstrapper from "./components/MessagingKeyBootstrapper";
import { getKeypair, getSession } from "./auth/session";
import { CLIENT_SETTINGS_CHANGED_EVENT, applySettingsToDocument, loadSettings } from "./lib/settings";
import { useAppConfig } from "./lib/config";
import { maybeApplyDevBootstrap } from "./lib/devBootstrap";
import { requestGlobalRefresh } from "./lib/revalidation";
import { consumeReturnTo, currentHashPath, getRouteMeta, isPublicRoute, matchRoute, nav, navWithReturn, stashReturnTo, type RouteMatch } from "./lib/router";
import { prefetchRouteChunk } from "./lib/routePrefetch";
import { useSessionHealth } from "./hooks/useSessionHealth";

const Feed = lazy(() => import("./pages/Feed"));
const Home = lazy(() => import("./pages/Home"));
const Messaging = lazy(() => import("./pages/Messaging"));
const AccountVerificationPage = lazy(() => import("./pages/AccountVerificationPage"));
const LiveVerificationRoom = lazy(() => import("./pages/LiveVerificationRoom"));
const JurorDashboard = lazy(() => import("./pages/JurorDashboard"));
const Tools = lazy(() => import("./pages/Tools"));
const Groups = lazy(() => import("./pages/Groups"));
const Group = lazy(() => import("./pages/Group"));
const GroupCreate = lazy(() => import("./pages/GroupCreate"));
const Proposals = lazy(() => import("./pages/Proposals"));
const Proposal = lazy(() => import("./pages/Proposal"));
const ProposalCreate = lazy(() => import("./pages/ProposalCreate"));
const Disputes = lazy(() => import("./pages/Disputes"));
const DisputeDetail = lazy(() => import("./pages/DisputeDetail"));
const DisputeReview = lazy(() => import("./pages/DisputeReview"));
const Account = lazy(() => import("./pages/Account"));
const Content = lazy(() => import("./pages/Content"));
const Thread = lazy(() => import("./pages/Thread"));
const Post = lazy(() => import("./pages/Post"));
const SettingsPage = lazy(() => import("./pages/SettingsPage"));
const LoginPage = lazy(() => import("./pages/LoginPage"));
const SessionDevicesPage = lazy(() => import("./pages/SessionDevicesPage"));
const TransactionsPage = lazy(() => import("./pages/TransactionsPage"));

function renderPage(route: RouteMatch, readyForApp: boolean, showAdvancedMode: boolean): JSX.Element {
  switch (route.path) {
    case "/login":
      return <LoginPage />;
    case "/home":
      return readyForApp ? <Home /> : <LoginPage />;
    case "/feed":
      return readyForApp ? <Feed /> : <LoginPage />;
    case "/messages":
      return readyForApp ? <Messaging mode="hub" /> : <LoginPage />;
    case "/messages/compose":
      return readyForApp ? <Messaging mode="compose" /> : <LoginPage />;
    case "/messages/:id":
      return readyForApp ? <Messaging mode="thread" threadId={route.id} /> : <LoginPage />;
    case "/profile":
      return readyForApp ? <Account account={getSession()?.account || ""} /> : <LoginPage />;
    case "/create":
      return readyForApp ? <Post /> : <LoginPage />;
    case "/verification":
      return readyForApp ? <AccountVerificationPage /> : <LoginPage />;
    case "/verification/live/:caseId":
      return readyForApp ? <LiveVerificationRoom caseId={route.caseId} /> : <LoginPage />;
    case "/reviews":
      return readyForApp ? <JurorDashboard /> : <LoginPage />;
    case "/groups":
      return <Groups />;
    case "/groups/create":
      return readyForApp ? <GroupCreate /> : <LoginPage />;
    case "/groups/:id":
      return <Group groupId={route.id} />;
    case "/decisions":
      return <Proposals />;
    case "/decisions/create":
      return readyForApp ? <ProposalCreate /> : <LoginPage />;
    case "/decisions/:id":
      return <Proposal id={route.id} />;
    case "/reports":
      return <Disputes />;
    case "/reports/:id":
      return <DisputeDetail id={route.id} />;
    case "/reviews/:id":
      return <DisputeReview id={route.id} />;
    case "/advanced":
      return readyForApp && showAdvancedMode ? <Tools /> : readyForApp ? <AdvancedModeLocked /> : <LoginPage />;
    case "/settings":
      return <SettingsPage />;
    case "/session":
      return <SessionDevicesPage />;
    case "/transactions":
      return readyForApp && showAdvancedMode ? <TransactionsPage /> : readyForApp ? <AdvancedModeLocked /> : <LoginPage />;
    case "/account/:account":
      return <Account account={route.account} />;
    case "/post/:id":
      return <Content id={route.id} />;
    case "/content/:id":
      return <Content id={route.id} />;
    case "/thread/:id":
      return <Thread id={route.id} />;
    default:
      return readyForApp ? <Feed /> : <Feed />;
  }
}

function RouteTransitionFallback({ route }: { route: RouteMatch }): JSX.Element {
  const label =
    route.path === "/login"
      ? "Preparing sign-in"
      : route.path === "/create"
        ? "Opening post composer"
        : route.path === "/decisions/create"
          ? "Opening decision composer"
          : route.path === "/groups/create"
            ? "Opening group creation"
            : route.path === "/reviews/:id"
              ? "Opening review item"
              : "Loading page";

  return (
    <section className="card routeTransitionFallback" aria-live="polite" aria-busy="true">
      <div className="cardBody formStack">
        <div className="eyebrow">Route transition</div>
        <h2 className="cardTitle">{label}</h2>
        <p className="cardDesc">
          The page shell stays mounted so navigation, account state, and pending work remain visible while the next surface loads.
        </p>
        <div className="routeTransitionSkeleton" aria-hidden="true">
          <div className="routeTransitionSkeletonBar routeTransitionSkeletonBar-wide" />
          <div className="routeTransitionSkeletonBar" />
          <div className="routeTransitionSkeletonCard" />
          <div className="routeTransitionSkeletonCard" />
        </div>
      </div>
    </section>
  );
}

function SessionRecoveryGate({ returnTo }: { returnTo: string }): JSX.Element {
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
          <button className="btn btnPrimary" onClick={() => navWithReturn("/session", returnTo)}>Open session recovery</button>
          <button className="btn" onClick={() => navWithReturn("/login", returnTo)}>Go to login</button>
        </div>
      </div>
    </section>
  );
}

function AdvancedModeLocked(): JSX.Element {
  return (
    <section className="card">
      <div className="cardBody formStack">
        <div className="eyebrow">Advanced details are off</div>
        <h2 className="cardTitle">Keep normal social use simple</h2>
        <p className="cardDesc">
          Network and developer surfaces are hidden by default. Turn on advanced mode only when you intentionally need technical records or operator tools.
        </p>
        <div className="buttonRow">
          <button className="btn btnPrimary" onClick={() => nav("/settings")}>Open settings</button>
          <button className="btn" onClick={() => nav("/home")}>Back to home</button>
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
  const showAdvancedMode = config.enableDevTools && settings.showAdvancedMode;

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
    const onClientSettingsChanged = () => setSettingsVersion((v: number) => v + 1);
    window.addEventListener("hashchange", onHash);
    window.addEventListener("storage", onStorage);
    window.addEventListener(CLIENT_SETTINGS_CHANGED_EVENT, onClientSettingsChanged);
    return () => {
      window.clearTimeout(hydrationTimer);
      window.removeEventListener("hashchange", onHash);
      window.removeEventListener("storage", onStorage);
      window.removeEventListener(CLIENT_SETTINGS_CHANGED_EVENT, onClientSettingsChanged);
    };
  }, []);

  useEffect(() => {
    applySettingsToDocument(loadSettings());
  }, [settingsVersion]);

  useEffect(() => {
    let cancelled = false;

    const runBootstrapSync = async () => {
      if (!config.enableDevBootstrap) {
        if (!cancelled) setAuthHydrated(true);
        return;
      }
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
      nav(consumeReturnTo("/home"));
      return;
    }
    if ((current === "/" || !current) && !readyForApp) {
      nav("/login");
      return;
    }
    if ((current === "/" || !current) && readyForApp) {
      nav(consumeReturnTo("/home"));
    }
  }, [authHydrated, readyForApp]);

  const route = matchRoute(path);
  const meta = getRouteMeta(route);
  const intendedPath = path || currentHashPath();
  const protectedButDegraded = meta.authRequired && authHydrated && !readyForApp && sessionHealth.recoverableAccount;
  const protectedAnonymous = meta.authRequired && authHydrated && !readyForApp && !sessionHealth.recoverableAccount;

  useEffect(() => {
    prefetchRouteChunk(route.path);
  }, [route.path]);

  useEffect(() => {
    if (!authHydrated || !meta.authRequired) return;

    requestGlobalRefresh({
      reason: `route-enter:${route.path}`,
      scopes: ["account", "session", "pending_work", "route", "node"],
    });

    const runRefresh = () => {
      if (document.hidden) return;
      requestGlobalRefresh({
        reason: `route-freshness:${route.path}`,
        scopes: ["account", "session", "pending_work", "route", "node"],
      });
    };

    const interval = window.setInterval(runRefresh, 15000);
    window.addEventListener("focus", runRefresh);
    document.addEventListener("visibilitychange", runRefresh);

    return () => {
      window.clearInterval(interval);
      window.removeEventListener("focus", runRefresh);
      document.removeEventListener("visibilitychange", runRefresh);
    };
  }, [authHydrated, meta.authRequired, route.path]);

  if (!authHydrated && meta.authRequired) {
    return (
      <AppShell route={route} meta={meta} sessionHealth={sessionHealth} showAdvancedMode={showAdvancedMode}>
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
    return (
      <Suspense fallback={<RouteTransitionFallback route={route} />}>
        <LoginPage />
      </Suspense>
    );
  }

  if (protectedAnonymous && !isPublicRoute(path)) {
    stashReturnTo(intendedPath);
    return (
      <Suspense fallback={<RouteTransitionFallback route={{ path: "/login" }} />}>
        <LoginPage />
      </Suspense>
    );
  }

  if (protectedButDegraded && route.path !== "/session") {
    return (
      <AppShell route={route} meta={meta} sessionHealth={sessionHealth} showAdvancedMode={showAdvancedMode}>
        <SessionRecoveryBanner health={sessionHealth} />
        <SessionRecoveryGate returnTo={intendedPath} />
      </AppShell>
    );
  }

  return (
    <AppShell route={route} meta={meta} sessionHealth={sessionHealth} showAdvancedMode={showAdvancedMode}>
      {readyForApp ? <MessagingKeyBootstrapper /> : null}
      {meta.authRequired && sessionHealth.state !== "active" ? <SessionRecoveryBanner health={sessionHealth} compact /> : null}
      <Suspense fallback={<RouteTransitionFallback route={route} />}>
        {renderPage(route, readyForApp, showAdvancedMode)}
      </Suspense>
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
