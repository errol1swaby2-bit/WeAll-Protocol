export type PageMode = "hub" | "detail" | "action" | "utility" | "advanced";
export type FabAction = "post" | "group" | "decision" | "none";
export type RightRailContext =
  | "login"
  | "home"
  | "feed"
  | "groups"
  | "group_detail"
  | "group_create"
  | "decisions"
  | "decision_detail"
  | "decision_create"
  | "reports"
  | "report_detail"
  | "review_item"
  | "reviews"
  | "post_create"
  | "activity"
  | "verification"
  | "live_room"
  | "account"
  | "profile"
  | "session_devices"
  | "settings"
  | "advanced"
  | "transactions"
  | "economics"
  | "node"
  | "content_detail"
  | "thread";

export type RouteDataContract = {
  primaryObject: string;
  accountSnapshot: boolean;
  nodeSnapshot: boolean;
  pendingWorkSlice: boolean;
  contextPanelData: string;
  staleTolerance: {
    liveCriticalMs: number;
    taskRelevantMs: number;
    ambientMs: number;
  };
  blockingDependencies: string[];
};

export type RouteMeta = {
  section: string;
  label: string;
  description: string;
  title: string;
  public: boolean;
  authRequired: boolean;
  requiresReady?: boolean;
  minPohTier?: number;
  mode: PageMode;
  fab: FabAction;
  rightRail: RightRailContext;
  normalNav: boolean;
  advancedOnly?: boolean;
  operatorOnly?: boolean;
  devOnly?: boolean;
  breadcrumbs?: Array<{ label: string; href: string }>;
  dataContract: RouteDataContract;
};

export type RouteMatch =
  | { path: "/login" }
  | { path: "/home" }
  | { path: "/feed" }
  | { path: "/create" }
  | { path: "/post/:id"; id: string }
  | { path: "/verification" }
  | { path: "/verification/live/:caseId"; caseId: string }
  | { path: "/reviews" }
  | { path: "/reviews/:id"; id: string }
  | { path: "/groups" }
  | { path: "/groups/create" }
  | { path: "/groups/:id"; id: string }
  | { path: "/activity" }
  | { path: "/decisions" }
  | { path: "/decisions/create" }
  | { path: "/decisions/:id"; id: string }
  | { path: "/reports" }
  | { path: "/reports/:id"; id: string }
  | { path: "/settings" }
  | { path: "/session" }
  | { path: "/advanced" }
  | { path: "/transactions" }
  | { path: "/economics" }
  | { path: "/node" }
  | { path: "/profile" }
  | { path: "/account/:account"; account: string }
  | { path: "/content/:id"; id: string }
  | { path: "/thread/:id"; id: string };

export type NavItem = {
  href: string;
  label: string;
  description: string;
  icon: string;
  public: boolean;
  requiresReady?: boolean;
  minPohTier?: number;
  advancedOnly?: boolean;
};

export type NavSection = {
  key: string;
  label: string;
  description: string;
  items: NavItem[];
};

const DEFAULT_STALE_TOLERANCE = {
  liveCriticalMs: 12_000,
  taskRelevantMs: 20_000,
  ambientMs: 45_000,
};

function contract(overrides: Partial<RouteDataContract>): RouteDataContract {
  return {
    primaryObject: overrides.primaryObject || "page",
    accountSnapshot: overrides.accountSnapshot ?? true,
    nodeSnapshot: overrides.nodeSnapshot ?? true,
    pendingWorkSlice: overrides.pendingWorkSlice ?? true,
    contextPanelData: overrides.contextPanelData || "Helpful page context",
    staleTolerance: overrides.staleTolerance ?? DEFAULT_STALE_TOLERANCE,
    blockingDependencies: overrides.blockingDependencies ?? [],
  };
}

const ROUTE_REGISTRY: Record<RouteMatch["path"], RouteMeta> = {
  "/login": {
    section: "Start",
    label: "Sign in",
    title: "Sign in or create account",
    description: "Create a local account session or restore this device so you can use WeAll safely.",
    public: true,
    authRequired: false,
    mode: "utility",
    fab: "none",
    rightRail: "login",
    normalNav: false,
    dataContract: contract({
      primaryObject: "Account session",
      accountSnapshot: false,
      pendingWorkSlice: false,
      contextPanelData: "Connection and session readiness",
      blockingDependencies: ["Backend reachability"],
    }),
  },
  "/home": {
    section: "Home",
    label: "Home",
    title: "Home",
    description: "Your starting point for posts, groups, decisions, reviews, and account next steps.",
    public: false,
    authRequired: true,
    requiresReady: true,
    mode: "hub",
    fab: "none",
    rightRail: "home",
    normalNav: true,
    dataContract: contract({
      primaryObject: "Home",
      contextPanelData: "Helpful shortcuts, notifications, and pending actions",
      blockingDependencies: ["Account session", "Local signer"],
    }),
  },
  "/feed": {
    section: "Feed",
    label: "Feed",
    title: "Feed",
    description: "Read posts, join conversations, react, share, and report harmful content when eligible.",
    public: false,
    authRequired: true,
    requiresReady: true,
    mode: "hub",
    fab: "post",
    rightRail: "feed",
    normalNav: true,
    dataContract: contract({
      primaryObject: "Social feed",
      contextPanelData: "Feed activity, posting eligibility, and helpful next steps",
      blockingDependencies: ["Account session", "Feed state"],
    }),
  },
  "/create": {
    section: "Feed",
    label: "Create Post",
    title: "Create Post",
    description: "Write a post, attach media, choose where it appears, and save it with clear progress feedback.",
    public: false,
    authRequired: true,
    requiresReady: true,
    mode: "action",
    fab: "none",
    rightRail: "post_create",
    normalNav: false,
    breadcrumbs: [{ label: "Feed", href: "/feed" }],
    dataContract: contract({
      primaryObject: "Post composer",
      contextPanelData: "Posting eligibility and save progress",
      blockingDependencies: ["Account session", "Posting eligibility", "Media readiness"],
    }),
  },
  "/post/:id": {
    section: "Feed",
    label: "Post Detail",
    title: "Post Detail",
    description: "Read one post, its conversation, reactions, and report or review status.",
    public: true,
    authRequired: false,
    mode: "detail",
    fab: "none",
    rightRail: "content_detail",
    normalNav: false,
    breadcrumbs: [{ label: "Feed", href: "/feed" }],
    dataContract: contract({
      primaryObject: "Post",
      contextPanelData: "Post context, comments, and review status",
      blockingDependencies: [],
    }),
  },
  "/verification": {
    section: "Trust & Verification",
    label: "Account Verification",
    title: "Account Verification",
    description: "Understand your current account status, what it unlocks, and the next verification step.",
    public: false,
    authRequired: true,
    requiresReady: true,
    mode: "utility",
    fab: "none",
    rightRail: "verification",
    normalNav: true,
    dataContract: contract({
      primaryObject: "Account verification",
      contextPanelData: "Verification status, next steps, and trusted responsibilities",
      blockingDependencies: ["Account session", "Authoritative account state"],
    }),
  },
  "/verification/live/:caseId": {
    section: "Trust & Verification",
    label: "Live Verification Room",
    title: "Live Verification Room",
    description: "Join a live verification session, check in, record attendance, and complete reviewer votes with chain-backed authority.",
    public: false,
    authRequired: true,
    requiresReady: true,
    mode: "action",
    fab: "none",
    rightRail: "live_room",
    normalNav: false,
    breadcrumbs: [{ label: "Account Verification", href: "/verification" }],
    dataContract: contract({
      primaryObject: "Live verification room",
      contextPanelData: "Live room transport, participant presence, attendance, verdicts, and finalization status",
      staleTolerance: { liveCriticalMs: 6_000, taskRelevantMs: 12_000, ambientMs: 20_000 },
      blockingDependencies: ["Account session", "Live verification case", "Self-hosted room transport", "Signed attendance/verdict state"],
    }),
  },
  "/reviews": {
    section: "Review Center",
    label: "Review Center",
    title: "Review Center",
    description: "A lane-separated hub for content review, dispute juror review, PoH async review, and PoH live review duties.",
    public: false,
    authRequired: true,
    requiresReady: true,
    minPohTier: 2,
    mode: "hub",
    fab: "none",
    rightRail: "reviews",
    normalNav: true,
    dataContract: contract({
      primaryObject: "Review Center",
      contextPanelData: "Lane-separated review work, reviewer opt-in state, eligibility blockers, and assigned duties",
      blockingDependencies: ["Account session", "Trusted account status", "Exact reviewer lane responsibility", "Assigned review work"],
    }),
  },
  "/reviews/:id": {
    section: "Review Center",
    label: "Content review workspace",
    title: "Content review workspace",
    description: "Complete one assigned review with simple choices and clear outcome feedback.",
    public: false,
    authRequired: true,
    requiresReady: true,
    minPohTier: 2,
    mode: "action",
    fab: "none",
    rightRail: "review_item",
    normalNav: false,
    breadcrumbs: [{ label: "Review Center", href: "/reviews" }],
    dataContract: contract({
      primaryObject: "Assigned review",
      contextPanelData: "Review instructions, assignment state, and action feedback",
      blockingDependencies: ["Account session", "Exact reviewer lane responsibility", "Assignment state"],
    }),
  },
  "/groups": {
    section: "Groups",
    label: "Groups",
    title: "Groups",
    description: "Find communities, request membership, follow activity, and open group decisions or reports.",
    public: true,
    authRequired: false,
    mode: "hub",
    fab: "group",
    rightRail: "groups",
    normalNav: true,
    dataContract: contract({
      primaryObject: "Groups",
      contextPanelData: "Joined groups, suggested groups, and membership status",
      blockingDependencies: [],
    }),
  },
  "/groups/create": {
    section: "Groups",
    label: "Create Group",
    title: "Create Group",
    description: "Create a community when your account status allows it.",
    public: false,
    authRequired: true,
    requiresReady: true,
    minPohTier: 2,
    mode: "action",
    fab: "none",
    rightRail: "group_create",
    normalNav: false,
    breadcrumbs: [{ label: "Groups", href: "/groups" }],
    dataContract: contract({
      primaryObject: "Group creation",
      contextPanelData: "Group creation eligibility and save progress",
      blockingDependencies: ["Account session", "Group creation eligibility"],
    }),
  },
  "/groups/:id": {
    section: "Groups",
    label: "Group Detail",
    title: "Group Detail",
    description: "View group posts, membership state, rules, decisions, and reports where relevant.",
    public: true,
    authRequired: false,
    mode: "detail",
    fab: "post",
    rightRail: "group_detail",
    normalNav: false,
    breadcrumbs: [{ label: "Groups", href: "/groups" }],
    dataContract: contract({
      primaryObject: "Group",
      contextPanelData: "Group activity, membership state, and helpful actions",
      blockingDependencies: [],
    }),
  },
  "/activity": {
    section: "Activity",
    label: "Activity",
    title: "Activity",
    description: "Review public-event-derived mentions, replies, group invitations, moderation notices, dispute assignments, governance notices, and validator/operator alerts.",
    public: false,
    authRequired: true,
    requiresReady: true,
    mode: "hub",
    fab: "none",
    rightRail: "activity",
    normalNav: true,
    dataContract: contract({
      primaryObject: "Public activity notifications",
      contextPanelData: "Public protocol events relevant to this account",
      blockingDependencies: ["Account session", "Public protocol event index"],
    }),
  },
  "/decisions": {
    section: "Decisions",
    label: "Decisions",
    title: "Decisions",
    description: "Browse community decisions, understand what is being voted on, and vote when eligible.",
    public: true,
    authRequired: false,
    mode: "hub",
    fab: "decision",
    rightRail: "decisions",
    normalNav: true,
    dataContract: contract({
      primaryObject: "Decisions",
      contextPanelData: "Open decisions, voting status, and recent results",
      blockingDependencies: [],
    }),
  },
  "/decisions/create": {
    section: "Decisions",
    label: "Create Decision",
    title: "Create Decision",
    description: "Create a community decision when your account status allows it.",
    public: false,
    authRequired: true,
    requiresReady: true,
    minPohTier: 2,
    mode: "action",
    fab: "none",
    rightRail: "decision_create",
    normalNav: false,
    breadcrumbs: [{ label: "Decisions", href: "/decisions" }],
    dataContract: contract({
      primaryObject: "Decision creation",
      contextPanelData: "Decision authoring eligibility and save progress",
      blockingDependencies: ["Account session", "Decision creation eligibility"],
    }),
  },
  "/decisions/:id": {
    section: "Decisions",
    label: "Decision Detail",
    title: "Decision Detail",
    description: "Understand one decision, cast a vote when eligible, and view the result when complete.",
    public: true,
    authRequired: false,
    mode: "detail",
    fab: "none",
    rightRail: "decision_detail",
    normalNav: false,
    breadcrumbs: [{ label: "Decisions", href: "/decisions" }],
    dataContract: contract({
      primaryObject: "Decision",
      contextPanelData: "Decision summary, voting status, and result",
      blockingDependencies: [],
    }),
  },
  "/reports": {
    section: "Reports",
    label: "Reports",
    title: "Reports",
    description: "View reported content and community review status in plain language.",
    public: true,
    authRequired: false,
    mode: "hub",
    fab: "none",
    rightRail: "reports",
    normalNav: true,
    dataContract: contract({
      primaryObject: "Reports",
      contextPanelData: "Report status and community review context",
      blockingDependencies: [],
    }),
  },
  "/reports/:id": {
    section: "Reports",
    label: "Report Detail",
    title: "Report Detail",
    description: "Inspect one report, what was reported, and the community review status.",
    public: true,
    authRequired: false,
    mode: "detail",
    fab: "none",
    rightRail: "report_detail",
    normalNav: false,
    breadcrumbs: [{ label: "Reports", href: "/reports" }],
    dataContract: contract({
      primaryObject: "Report",
      contextPanelData: "Reported item, reason, status, and result",
      blockingDependencies: [],
    }),
  },
  "/settings": {
    section: "Settings",
    label: "Settings",
    title: "Settings",
    description: "Control profile, privacy, notifications, sessions, and advanced mode.",
    public: true,
    authRequired: false,
    mode: "utility",
    fab: "none",
    rightRail: "settings",
    normalNav: true,
    dataContract: contract({
      primaryObject: "Settings",
      contextPanelData: "Client preferences and account safety settings",
      pendingWorkSlice: false,
      blockingDependencies: [],
    }),
  },
  "/session": {
    section: "Settings",
    label: "Devices & Sessions",
    title: "Devices & Sessions",
    description: "Review this device, local signer state, browser session state, and account safety records.",
    public: false,
    authRequired: true,
    requiresReady: true,
    mode: "utility",
    fab: "none",
    rightRail: "session_devices",
    normalNav: false,
    dataContract: contract({
      primaryObject: "Device session",
      contextPanelData: "Current device, active session, and revocation posture",
      blockingDependencies: ["Account session"],
    }),
  },
  "/advanced": {
    section: "Advanced",
    label: "Advanced Details",
    title: "Advanced Details",
    description: "Inspect technical records and network status when advanced mode is enabled.",
    public: false,
    authRequired: true,
    requiresReady: true,
    mode: "advanced",
    fab: "none",
    rightRail: "advanced",
    normalNav: false,
    advancedOnly: true,
    dataContract: contract({
      primaryObject: "Advanced details",
      contextPanelData: "Technical records and operator context",
      blockingDependencies: ["Account session", "Advanced mode"],
    }),
  },
  "/transactions": {
    section: "Advanced",
    label: "Technical Action History",
    title: "Technical Action History",
    description: "Inspect saved technical action history and backend confirmation details in advanced mode.",
    public: false,
    authRequired: true,
    requiresReady: true,
    mode: "advanced",
    fab: "none",
    rightRail: "transactions",
    normalNav: false,
    advancedOnly: true,
    dataContract: contract({
      primaryObject: "Technical action history",
      contextPanelData: "Detailed submission history and technical records",
      blockingDependencies: ["Account session", "Advanced mode"],
    }),
  },

  "/economics": {
    section: "Economics",
    label: "Economics",
    title: "Economics & Treasury",
    description: "View the locked WeCoin, fee, reward, and treasury activation posture without enabling economics.",
    public: false,
    authRequired: true,
    requiresReady: true,
    mode: "utility",
    fab: "none",
    rightRail: "economics",
    normalNav: true,
    dataContract: contract({
      primaryObject: "Economics status",
      contextPanelData: "Locked tokenomics, wallet balance, fee-free civic protections, and treasury readiness",
      blockingDependencies: ["Account session", "Economics status"],
    }),
  },
  "/node": {
    section: "Node",
    label: "Personal Node",
    title: "Personal Node",
    description: "Operate the local node connection, status, validator/helper/storage readiness, and storage contribution preferences.",
    public: true,
    authRequired: false,
    requiresReady: false,
    mode: "utility",
    fab: "none",
    rightRail: "node",
    normalNav: true,
    operatorOnly: true,
    dataContract: contract({
      primaryObject: "Personal node dashboard",
      accountSnapshot: false,
      contextPanelData: "Node health, chain identity, runtime readiness, storage/IPFS contribution controls, and launch boundaries",
      blockingDependencies: ["Backend reachability", "Node status surfaces"],
    }),
  },

  "/profile": {
    section: "Profile",
    label: "Profile",
    title: "My Profile",
    description: "View your profile, account status, trusted responsibilities, groups, and posts.",
    public: false,
    authRequired: true,
    requiresReady: true,
    mode: "utility",
    fab: "none",
    rightRail: "profile",
    normalNav: true,
    dataContract: contract({
      primaryObject: "Profile",
      contextPanelData: "Profile, account status, and trusted responsibilities",
      blockingDependencies: ["Account session"],
    }),
  },
  "/account/:account": {
    section: "Profile",
    label: "Public Profile",
    title: "Public Profile",
    description: "View another person’s public profile, account label, trusted responsibilities, and public activity.",
    public: true,
    authRequired: false,
    mode: "detail",
    fab: "none",
    rightRail: "account",
    normalNav: false,
    dataContract: contract({
      primaryObject: "Public profile",
      contextPanelData: "Public profile and account status",
      blockingDependencies: [],
    }),
  },
  "/content/:id": {
    section: "Feed",
    label: "Post Detail",
    title: "Post Detail",
    description: "Inspect a post, its conversation, and related actions.",
    public: true,
    authRequired: false,
    mode: "detail",
    fab: "none",
    rightRail: "content_detail",
    normalNav: false,
    breadcrumbs: [{ label: "Feed", href: "/feed" }],
    dataContract: contract({
      primaryObject: "Post",
      contextPanelData: "Post context and review status",
      blockingDependencies: [],
    }),
  },
  "/thread/:id": {
    section: "Feed",
    label: "Thread",
    title: "Thread",
    description: "Inspect a post thread and its ordered discussion activity.",
    public: true,
    authRequired: false,
    mode: "detail",
    fab: "none",
    rightRail: "thread",
    normalNav: false,
    breadcrumbs: [{ label: "Feed", href: "/feed" }],
    dataContract: contract({
      primaryObject: "Thread",
      contextPanelData: "Thread activity and related actions",
      blockingDependencies: [],
    }),
  },
};

const LS_RETURN_TO = "weall_return_to_v1";

const NAV_SECTIONS: NavSection[] = [
  {
    key: "primary",
    label: "Main navigation",
    description: "Core social routes.",
    items: [
      { href: "/home", label: "Home", description: "Your starting point and pending actions.", icon: "⌂", public: false, requiresReady: true },
      { href: "/feed", label: "Feed", description: "Read and create posts.", icon: "≋", public: false, requiresReady: true },
      { href: "/groups", label: "Groups", description: "Communities and membership.", icon: "◌", public: true },
      { href: "/activity", label: "Activity", description: "Public notices and assignments.", icon: "✉", public: false, requiresReady: true },
      { href: "/decisions", label: "Decisions", description: "Community votes and results.", icon: "▣", public: true },
      { href: "/reports", label: "Reports", description: "Reported content and case status.", icon: "!", public: true },
      { href: "/reviews", label: "Review Center", description: "Lane-separated review duties.", icon: "✓", public: false, requiresReady: true, minPohTier: 2 },
      { href: "/verification", label: "Account Verification", description: "Account status and next steps.", icon: "◇", public: false, requiresReady: true },
      { href: "/profile", label: "Profile", description: "Profile and trusted responsibilities.", icon: "☺", public: false, requiresReady: true },
      { href: "/economics", label: "Economics", description: "Locked WeCoin and treasury status.", icon: "◎", public: false, requiresReady: true },
      { href: "/node", label: "Personal Node", description: "Local node health, readiness, and storage controls.", icon: "⬡", public: true },
      { href: "/settings", label: "Settings", description: "Preferences and account safety.", icon: "⚙", public: true },
      { href: "/advanced", label: "Advanced", description: "Technical records and network status.", icon: "⋯", public: false, requiresReady: true, advancedOnly: true },
    ],
  },
];

function decodeRoutePart(value: string): string {
  const raw = String(value || "").trim();
  if (!raw) return "";
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

export function matchRoute(path: string): RouteMatch {
  const r = path.split("?")[0];

  if (r === "/" || r === "/login") return { path: "/login" };
  if (r === "/home") return { path: "/home" };
  if (r === "/feed") return { path: "/feed" };
  if (r === "/create") return { path: "/create" };
  if (r === "/verification") return { path: "/verification" };
  if (r.startsWith("/verification/live/")) {
    const caseId = decodeRoutePart(r.slice("/verification/live/".length));
    if (caseId) return { path: "/verification/live/:caseId", caseId };
  }
  if (r === "/reviews") return { path: "/reviews" };
  if (r === "/groups") return { path: "/groups" };
  if (r === "/groups/create") return { path: "/groups/create" };
  if (r === "/activity") return { path: "/activity" };
  if (r === "/decisions") return { path: "/decisions" };
  if (r === "/decisions/create") return { path: "/decisions/create" };
  if (r === "/reports") return { path: "/reports" };
  if (r === "/settings") return { path: "/settings" };
  if (r === "/session") return { path: "/session" };
  if (r === "/node") return { path: "/node" };
  if (r === "/advanced") return { path: "/advanced" };
  if (r === "/transactions") return { path: "/transactions" };
  if (r === "/economics") return { path: "/economics" };
  if (r === "/profile") return { path: "/profile" };

  if (r.startsWith("/reviews/")) {
    const id = decodeRoutePart(r.slice("/reviews/".length));
    if (id) return { path: "/reviews/:id", id };
  }

  if (r.startsWith("/reports/")) {
    const id = decodeRoutePart(r.slice("/reports/".length));
    if (id) return { path: "/reports/:id", id };
  }

  if (r.startsWith("/groups/")) {
    const id = decodeRoutePart(r.slice("/groups/".length));
    if (id) return { path: "/groups/:id", id };
  }

  if (r.startsWith("/decisions/")) {
    const id = decodeRoutePart(r.slice("/decisions/".length));
    if (id) return { path: "/decisions/:id", id };
  }

  if (r.startsWith("/post/")) {
    const id = decodeRoutePart(r.slice("/post/".length));
    if (id) return { path: "/post/:id", id };
  }

  if (r.startsWith("/account/")) {
    const account = decodeRoutePart(r.slice("/account/".length));
    if (account) return { path: "/account/:account", account };
  }

  if (r.startsWith("/content/")) {
    const id = decodeRoutePart(r.slice("/content/".length));
    if (id) return { path: "/content/:id", id };
  }

  if (r.startsWith("/thread/")) {
    const id = decodeRoutePart(r.slice("/thread/".length));
    if (id) return { path: "/thread/:id", id };
  }

  return { path: "/login" };
}

export function getRouteMeta(route: RouteMatch): RouteMeta {
  return ROUTE_REGISTRY[route.path];
}

export function getNavSections(args: { ready: boolean; tier: number; showAdvanced: boolean }): NavSection[] {
  const { ready, tier, showAdvanced } = args;
  return NAV_SECTIONS.map((section) => ({
    ...section,
    items: section.items.filter((item) => {
      if (item.advancedOnly && !showAdvanced) return false;
      if (!ready && !item.public) return false;
      if (item.requiresReady && !ready) return false;
      if (typeof item.minPohTier === "number" && tier < item.minPohTier) return false;
      return true;
    }),
  })).filter((section) => section.items.length > 0);
}

export function currentHashPath(): string {
  if (typeof window === "undefined") return "/login";
  const hash = window.location.hash || "#/login";
  const raw = hash.startsWith("#") ? hash.slice(1) : hash;
  const normalized = raw || "/login";
  return normalized.startsWith("/") ? normalized : `/${normalized}`;
}

export function isPublicRoute(path: string): boolean {
  return getRouteMeta(matchRoute(path)).public;
}

export function isActiveNavPath(currentPath: string, href: string): boolean {
  const current = matchRoute(currentPath).path;
  const target = matchRoute(href).path;
  if (target === "/home") return current === "/home";
  if (target === "/feed") return current === "/feed" || current === "/content/:id" || current === "/thread/:id" || current === "/post/:id";
  if (target === "/activity") return current === "/activity";
  if (target === "/decisions") return current === "/decisions" || current === "/decisions/:id" || current === "/decisions/create";
  if (target === "/reports") return current === "/reports" || current === "/reports/:id";
  if (target === "/reviews") return current === "/reviews" || current === "/reviews/:id";
  if (target === "/verification") return current === "/verification" || current === "/verification/live/:caseId";
  return current === target || currentPath === href || currentPath.startsWith(`${href}/`);
}

export function nav(path: string): void {
  const p = path.startsWith("/") ? path : `/${path}`;
  window.location.hash = `#${p}`;
}

export function getDefaultReadyRoute(): RouteMatch {
  return { path: "/home" };
}

export function getFabHref(route: RouteMatch): string | null {
  const meta = getRouteMeta(route);
  switch (meta.fab) {
    case "post":
      return "/create";
    case "group":
      return "/groups/create";
    case "decision":
      return "/decisions/create";
    default:
      return null;
  }
}

export function canPreserveReturnPath(path: string): boolean {
  const normalized = String(path || "").trim();
  return !!normalized && normalized.startsWith("/") && normalized !== "/login";
}

export function stashReturnTo(path: string): void {
  if (typeof window === "undefined") return;
  const normalized = String(path || "").trim();
  if (!canPreserveReturnPath(normalized)) return;
  try {
    localStorage.setItem(LS_RETURN_TO, normalized);
  } catch {
    // ignore storage failures
  }
}

export function peekReturnTo(): string {
  if (typeof window === "undefined") return "";
  try {
    const value = String(localStorage.getItem(LS_RETURN_TO) || "").trim();
    return canPreserveReturnPath(value) ? value : "";
  } catch {
    return "";
  }
}

export function clearReturnTo(): void {
  if (typeof window === "undefined") return;
  try {
    localStorage.removeItem(LS_RETURN_TO);
  } catch {
    // ignore storage failures
  }
}

export function consumeReturnTo(fallback = "/home"): string {
  const target = peekReturnTo();
  clearReturnTo();
  return target || fallback;
}

export function navWithReturn(target: string, returnTo: string): void {
  stashReturnTo(returnTo);
  nav(target);
}
